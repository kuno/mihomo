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

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/common/callback"
	"github.com/metacubex/mihomo/common/lru"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/dialer"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/constant/provider"

	"golang.org/x/net/publicsuffix"
)

type strategyFn = func(proxies []C.Proxy, metadata *C.Metadata, touch bool) C.Proxy

type LoadBalance struct {
	*GroupBase
	disableUDP     bool
	strategyFn     strategyFn
	testUrl        string
	expectedStatus string
	strategy       string
	Hidden         bool
	Icon           string
}

type DescendingWeight []C.Proxy

func (dw DescendingWeight) Len() int      { return len(dw) }
func (dw DescendingWeight) Swap(i, j int) { dw[i], dw[j] = dw[j], dw[i] }
func (dw DescendingWeight) Less(i, j int) bool {
	return dw[i].Weight() > dw[j].Weight()
}

type ProxyRandomStatistic struct {
	data   map[string]int
	header string
}

func (prs *ProxyRandomStatistic) Total() int {
	total := 0
	for _, count := range prs.data {
		total += count
	}

	return total
}

func (prs *ProxyRandomStatistic) Selected(name string) int {
	return prs.data[name]
}

func (prs *ProxyRandomStatistic) Record(name string) {
	if count, found := prs.data[name]; found {
		prs.data[name] = count + 1
		return
	}
	prs.data[name] = 1
}

var errStrategy = errors.New("unsupported strategy")

func parseStrategy(config map[string]any) string {
	if strategy, ok := config["strategy"].(string); ok {
		return strategy
	}
	return "consistent-hashing"
}

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

func (lb *LoadBalance) Weight() int {
	return 1
}

// DialContext implements C.ProxyAdapter
func (lb *LoadBalance) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (c C.Conn, err error) {
	proxy := lb.Unwrap(metadata, true)
	c, err = proxy.DialContext(ctx, metadata, lb.Base.DialOptions(opts...)...)

	if err == nil {
		c.AppendToChains(lb)
	} else {
		lb.onDialFailed(proxy.Type(), err)
	}

	if N.NeedHandshake(c) {
		c = callback.NewFirstWriteCallBackConn(c, func(err error) {
			if err == nil {
				lb.onDialSuccess()
			} else {
				lb.onDialFailed(proxy.Type(), err)
			}
		})
	}

	return
}

// ListenPacketContext implements C.ProxyAdapter
func (lb *LoadBalance) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (pc C.PacketConn, err error) {
	defer func() {
		if err == nil {
			pc.AppendToChains(lb)
		}
	}()

	proxy := lb.Unwrap(metadata, true)
	return proxy.ListenPacketContext(ctx, metadata, lb.Base.DialOptions(opts...)...)
}

// SupportUDP implements C.ProxyAdapter
func (lb *LoadBalance) SupportUDP() bool {
	return !lb.disableUDP
}

// IsL3Protocol implements C.ProxyAdapter
func (lb *LoadBalance) IsL3Protocol(metadata *C.Metadata) bool {
	return lb.Unwrap(metadata, false).IsL3Protocol(metadata)
}

func strategySimpleRandom(url string) strategyFn {
	return func(proxies []C.Proxy, metadata *C.Metadata, touch bool) C.Proxy {
		length := len(proxies)
		idx := rand.Intn(length)
		proxy := proxies[idx]
		if proxy.AliveForTestUrl(url) {
			return proxy
		}

		return proxies[0]
	}
}

func totalWeight(proxies []C.Proxy, base int) int {
	total := base

	for _, p := range proxies {
		total += p.Weight()
	}

	return total
}

func strategyWeightedRandom(url string) strategyFn {
	return func(proxies []C.Proxy, metadata *C.Metadata, touch bool) C.Proxy {
		sum := 0
		total := totalWeight(proxies, -1)
		threshold := rand.Intn(total)
		for _, pxy := range proxies {
			sum += pxy.Weight()
			if pxy.AliveForTestUrl(url) && sum >= threshold {
				return pxy
			}
		}

		return proxies[0]
	}
}

func strategyWeightedSpeedy(url string) strategyFn {
	return func(proxies []C.Proxy, metadata *C.Metadata, touch bool) C.Proxy {
		sort.Slice(proxies, func(i, j int) bool {
			// Using the ratio of Weight / Delay to determine the priority
			return (proxies[i].Weight() / int(proxies[i].LastDelayForTestUrl(url))) > (proxies[j].Weight() / int(proxies[j].LastDelayForTestUrl(url)))
		})

		// Tries to return a alive proxy
		for _, pxy := range proxies {
			if pxy.AliveForTestUrl(url) {
				return pxy
			}
		}

		return proxies[0]
	}
}

func strategyRoundRobin(url string) strategyFn {
	idx := 0
	idxMutex := sync.Mutex{}
	return func(proxies []C.Proxy, metadata *C.Metadata, touch bool) C.Proxy {
		idxMutex.Lock()
		defer idxMutex.Unlock()

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
}

func strategyWeightedRoundRobin(url string) strategyFn {
	threshold := 0
	return func(proxies []C.Proxy, metadata *C.Metadata, touch bool) C.Proxy {
		sum := 0
		total := totalWeight(proxies, -1)
		threshold = (threshold + 1) % total
		for _, pxy := range proxies {
			sum += pxy.Weight()
			if threshold <= sum && pxy.AliveForTestUrl(url) {
				return pxy
			}
		}

		return proxies[0]
	}
}

func strategyConsistentHashing(url string) strategyFn {
	maxRetry := 5
	return func(proxies []C.Proxy, metadata *C.Metadata, touch bool) C.Proxy {
		key := utils.MapHash(getKey(metadata))
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
	lruCache := lru.New[uint64, int](
		lru.WithAge[uint64, int](int64(ttl.Seconds())),
		lru.WithSize[uint64, int](1000))
	return func(proxies []C.Proxy, metadata *C.Metadata, touch bool) C.Proxy {
		key := utils.MapHash(getKeyWithSrcAndDst(metadata))
		length := len(proxies)
		idx, has := lruCache.Get(key)
		if !has {
			idx = int(jumpHash(key+uint64(time.Now().UnixNano()), int32(length)))
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
				nowIdx = int(jumpHash(key+uint64(time.Now().UnixNano()), int32(length)))
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
	for _, proxy := range lb.GetProxies(false) {
		all = append(all, proxy.Name())
	}
	m := map[string]any{
		"type":           lb.Type().String(),
		"all":            all,
		"strategy":       lb.strategy,
		"testUrl":        lb.testUrl,
		"expectedStatus": lb.expectedStatus,
		"hidden":         lb.Hidden,
		"icon":           lb.Icon,
	}

	m["now"] = lb.Unwrap(nil, false).Name()

	return json.Marshal(m)
}

func NewLoadBalance(option *GroupCommonOption, providers []provider.ProxyProvider, strategy string) (lb *LoadBalance, err error) {
	var strategyFn strategyFn
	switch strategy {
	case "consistent-hashing":
		strategyFn = strategyConsistentHashing(option.URL)
	case "round-robin":
		if option.RespectWeight {
			strategyFn = strategyWeightedRoundRobin(option.URL)
		} else {
			strategyFn = strategyRoundRobin(option.URL)
		}
	case "random":
		if option.RespectWeight {
			strategyFn = strategyWeightedRandom(option.URL)
		} else {
			strategyFn = strategySimpleRandom(option.URL)
		}
	case "sticky-sessions":
		strategyFn = strategyStickySessions(option.URL)
	case "weighted-speedy":
		strategyFn = strategyWeightedSpeedy(option.URL)
	default:
		return nil, fmt.Errorf("%w: %s", errStrategy, strategy)
	}
	return &LoadBalance{
		GroupBase: NewGroupBase(GroupBaseOption{
			outbound.BaseOption{
				Name:        option.Name,
				Type:        C.LoadBalance,
				Interface:   option.Interface,
				RoutingMark: option.RoutingMark,
			},
			option.Filter,
			option.WeightFilter,
			option.ExcludeFilter,
			option.ExcludeType,
			option.TestTimeout,
			option.MaxFailedTimes,
			providers,
		}),
		strategyFn:     strategyFn,
		disableUDP:     option.DisableUDP,
		strategy:       strategy,
		testUrl:        option.URL,
		expectedStatus: option.ExpectedStatus,
		Hidden:         option.Hidden,
		Icon:           option.Icon,
	}, nil
}
