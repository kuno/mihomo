package outboundgroup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/callback"
	"github.com/metacubex/mihomo/common/lru"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"

	"golang.org/x/net/publicsuffix"
)

type LoadBalanceOption struct {
	Strategy string `group:"strategy,omitempty"`
}

type LoadBalance struct {
	*GroupBase
	disableUDP     bool
	strategyFn     strategyFn
	testUrl        string
	expectedStatus string
}

type strategyFn = func(proxies []C.Proxy, metadata *C.Metadata, touch bool) C.Proxy

var errStrategy = errors.New("unsupported strategy")

func getKey(metadata *C.Metadata) string {
	if metadata == nil {
		return ""
	}

	if metadata.Host != "" {
		// ip host
		if ip := net.ParseIP(metadata.Host); ip != nil {
			return metadata.Host
		}

		if etld, err := publicsuffix.EffectiveTLDPlusOne(metadata.Host); err == nil {
			return etld
		}
	}

	if !metadata.DstIP.IsValid() {
		return ""
	}

	return metadata.DstIP.String()
}

func getKeyWithSrcAndDst(metadata *C.Metadata) string {
	dst := getKey(metadata)
	src := ""
	if metadata != nil {
		src = metadata.SrcIP.String()
	}

	return fmt.Sprintf("%s%s", src, dst)
}

func jumpHash(key uint64, buckets int32) int32 {
	var b, j int64

	for j < int64(buckets) {
		b = j
		key = key*2862933555777941757 + 1
		j = int64(float64(b+1) * (float64(int64(1)<<31) / float64((key>>33)+1)))
	}

	return int32(b)
}

// DialContext implements C.ProxyAdapter
func (lb *LoadBalance) DialContext(ctx context.Context, metadata *C.Metadata) (c C.Conn, err error) {
	proxy := lb.Unwrap(metadata, true)
	c, err = proxy.DialContext(ctx, metadata)

	if err == nil {
		c.AppendToChains(lb)
	} else {
		lb.onDialFailed(proxy.Type(), err, lb.healthCheck)
	}

	if N.NeedHandshake(c) {
		c = callback.NewFirstWriteCallBackConn(c, func(err error) {
			if err == nil {
				lb.onDialSuccess()
			} else {
				lb.onDialFailed(proxy.Type(), err, lb.healthCheck)
			}
		})
	}

	return
}

// ListenPacketContext implements C.ProxyAdapter
func (lb *LoadBalance) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (pc C.PacketConn, err error) {
	defer func() {
		if err == nil {
			pc.AppendToChains(lb)
		}
	}()

	proxy := lb.Unwrap(metadata, true)
	return proxy.ListenPacketContext(ctx, metadata)
}

// SupportUDP implements C.ProxyAdapter
func (lb *LoadBalance) SupportUDP() bool {
	return !lb.disableUDP
}

func (lb *LoadBalance) SupportUDPForDisplay() bool {
	return !lb.disableUDP
}

// IsL3Protocol implements C.ProxyAdapter
func (lb *LoadBalance) IsL3Protocol(metadata *C.Metadata) bool {
	return lb.Unwrap(metadata, false).IsL3Protocol(metadata)
}

func strategyRoundRobin(url string) strategyFn {
	// SWRR state
	type swrrState struct {
		currentWeight   int32
		effectiveWeight int32
	}
	stateMap := make(map[string]*swrrState)
	idxMutex := sync.Mutex{}

	// simple RR state
	idx := 0

	return func(proxies []C.Proxy, metadata *C.Metadata, touch bool) C.Proxy {
		idxMutex.Lock()
		defer idxMutex.Unlock()

		if len(proxies) == 0 {
			return nil
		}

		weighted := false
		for _, p := range proxies {
			if p.Weight() > 1 {
				weighted = true
				break
			}
		}

		if !weighted {
			i := 0
			length := len(proxies)
			if touch {
				defer func() {
					idx = (idx + i) % length
				}()
			}
			for ; i < length; i++ {
				id := (idx + i) % length
				proxy := proxies[id]
				if proxy.AliveForTestUrl(url) {
					i++
					return proxy
				}
			}
			return proxies[0]
		}

		var aliveProxies []C.Proxy
		for _, p := range proxies {
			if p.AliveForTestUrl(url) {
				aliveProxies = append(aliveProxies, p)
			}
		}
		if len(aliveProxies) == 0 {
			aliveProxies = proxies
		}

		totalWeight := int32(0)
		var bestProxy C.Proxy
		var bestState *swrrState

		for _, p := range aliveProxies {
			name := p.Name()
			s, ok := stateMap[name]
			if !ok {
				s = &swrrState{effectiveWeight: int32(p.Weight())}
				stateMap[name] = s
			} else {
				s.effectiveWeight = int32(p.Weight())
			}

			s.currentWeight += s.effectiveWeight
			totalWeight += s.effectiveWeight

			if bestProxy == nil || s.currentWeight > bestState.currentWeight {
				bestProxy = p
				bestState = s
			}
		}

		if bestProxy != nil {
			bestState.currentWeight -= totalWeight
			return bestProxy
		}

		return proxies[0]
	}
}

func getWeightedIndex(key uint64, proxies []C.Proxy) int {
	ranges := make([]uint32, len(proxies))
	total := uint32(0)
	for i, p := range proxies {
		total += uint32(p.Weight())
		ranges[i] = total
	}

	h := uint32(jumpHash(key, int32(total)))
	idx := sort.Search(len(ranges), func(i int) bool {
		return ranges[i] > h
	})
	if idx >= len(proxies) {
		idx = 0
	}
	return idx
}

func strategyWeightedRandom(url string) strategyFn {
	return func(proxies []C.Proxy, metadata *C.Metadata, touch bool) C.Proxy {
		if len(proxies) == 0 {
			return nil
		}

		var aliveProxies []C.Proxy
		for _, p := range proxies {
			if p.AliveForTestUrl(url) {
				aliveProxies = append(aliveProxies, p)
			}
		}

		if len(aliveProxies) == 0 {
			aliveProxies = proxies
		}

		totalWeight := 0
		for _, p := range aliveProxies {
			totalWeight += int(p.Weight())
		}

		if totalWeight > 0 {
			r := rand.Intn(totalWeight)
			for _, p := range aliveProxies {
				r -= int(p.Weight())
				if r < 0 {
					return p
				}
			}
		}

		return aliveProxies[rand.Intn(len(aliveProxies))]
	}
}

func strategyConsistentHashing(url string) strategyFn {
	maxRetry := 5
	return func(proxies []C.Proxy, metadata *C.Metadata, touch bool) C.Proxy {
		key := utils.MapHash(getKey(metadata))

		weighted := false
		for _, p := range proxies {
			if p.Weight() > 1 {
				weighted = true
				break
			}
		}

		if weighted {
			for i := 0; i < maxRetry; i, key = i+1, key+1 {
				idx := getWeightedIndex(key, proxies)
				proxy := proxies[idx]
				if proxy.AliveForTestUrl(url) {
					return proxy
				}
			}
			for _, proxy := range proxies {
				if proxy.AliveForTestUrl(url) {
					return proxy
				}
			}
			return proxies[0]
		}

		buckets := int32(len(proxies))
		for i := 0; i < maxRetry; i, key = i+1, key+1 {
			idx := jumpHash(key, buckets)
			proxy := proxies[idx]
			if proxy.AliveForTestUrl(url) {
				return proxy
			}
		}

		// when availability is poor, traverse the entire list to get the available nodes
		for _, proxy := range proxies {
			if proxy.AliveForTestUrl(url) {
				return proxy
			}
		}

		return proxies[0]
	}
}

func strategyStickySessions(url string) strategyFn {
	ttl := time.Minute * 10
	maxRetry := 5
	lruCache := lru.New(
		lru.WithAge[uint64, int](int64(ttl.Seconds())),
		lru.WithSize[uint64, int](1000))
	return func(proxies []C.Proxy, metadata *C.Metadata, touch bool) C.Proxy {
		key := utils.MapHash(getKeyWithSrcAndDst(metadata))

		weighted := false
		for _, p := range proxies {
			if p.Weight() > 1 {
				weighted = true
				break
			}
		}

		length := len(proxies)
		idx, has := lruCache.Get(key)
		if !has || idx >= length {
			if weighted {
				idx = getWeightedIndex(key+uint64(time.Now().UnixNano()), proxies)
			} else {
				idx = int(jumpHash(key+uint64(time.Now().UnixNano()), int32(length)))
			}
		}

		nowIdx := idx
		for i := 1; i < maxRetry; i++ {
			proxy := proxies[nowIdx]
			if proxy.AliveForTestUrl(url) {
				if !has || nowIdx != idx {
					lruCache.Set(key, nowIdx)
				}

				return proxy
			} else {
				if weighted {
					nowIdx = getWeightedIndex(key+uint64(time.Now().UnixNano()), proxies)
				} else {
					nowIdx = int(jumpHash(key+uint64(time.Now().UnixNano()), int32(length)))
				}
			}
		}

		lruCache.Set(key, 0)
		return proxies[0]
	}
}

// Unwrap implements C.ProxyAdapter
func (lb *LoadBalance) Unwrap(metadata *C.Metadata, touch bool) C.Proxy {
	proxies := lb.GetProxies(touch)
	return lb.strategyFn(proxies, metadata, touch)
}

// MarshalJSON implements C.ProxyAdapter
func (lb *LoadBalance) MarshalJSON() ([]byte, error) {
	var all []string
	for _, proxy := range lb.GetProxiesForDisplay() {
		all = append(all, proxy.Name())
	}
	return json.Marshal(map[string]any{
		"type":           lb.Type().String(),
		"all":            all,
		"testUrl":        lb.testUrl,
		"expectedStatus": lb.expectedStatus,
		"hidden":         lb.Hidden(),
		"icon":           lb.Icon(),
		"emptyFallback":  lb.EmptyFallback().Name(),
	})
}

func (lb *LoadBalance) Providers() []P.ProxyProvider {
	return lb.providers
}

func (lb *LoadBalance) Proxies() []C.Proxy {
	return lb.GetProxiesForDisplay()
}

func (lb *LoadBalance) Now() string {
	return ""
}

func NewLoadBalance(option GroupCommonOption, loadBalanceOption LoadBalanceOption, emptyFallback C.Proxy, providers []P.ProxyProvider) (lb *LoadBalance, err error) {
	var strategyFn strategyFn
	switch loadBalanceOption.Strategy {
	case "", "consistent-hashing":
		strategyFn = strategyConsistentHashing(option.URL)
	case "round-robin":
		strategyFn = strategyRoundRobin(option.URL)
	case "sticky-sessions":
		strategyFn = strategyStickySessions(option.URL)
	case "weighted-random":
		strategyFn = strategyWeightedRandom(option.URL)
	default:
		return nil, fmt.Errorf("%w: %s", errStrategy, loadBalanceOption.Strategy)
	}
	return &LoadBalance{
		GroupBase: NewGroupBase(GroupBaseOption{
			Name:                       option.Name,
			Type:                       C.LoadBalance,
			Hidden:                     option.Hidden,
			Icon:                       option.Icon,
			Filter:                     option.Filter,
			ExcludeFilter:              option.ExcludeFilter,
			IPPureCountryFilter:        option.IPPureCountryFilter,
			ExcludeIPPureCountryFilter: option.ExcludeIPPureCountryFilter,
			IPPureFraudScoreFilter:     option.IPPureFraudScoreFilter,
			ExcludeType:                option.ExcludeType,
			TestTimeout:                option.TestTimeout,
			MaxFailedTimes:             option.MaxFailedTimes,
			EmptyFallback:              emptyFallback,
			Providers:                  providers,
			Weight:                     uint16(option.Weight),
			WeightFilter:               option.WeightFilter,
		}),
		strategyFn:     strategyFn,
		disableUDP:     option.DisableUDP,
		testUrl:        option.URL,
		expectedStatus: option.ExpectedStatus,
	}, nil
}
