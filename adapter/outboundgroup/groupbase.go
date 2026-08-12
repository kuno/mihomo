package outboundgroup

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/log"

	"github.com/dlclark/regexp2"
	"golang.org/x/exp/slices"
)

type GroupBase struct {
	*outbound.Base
	hidden                          bool
	icon                            string
	filterRegs                      []*regexp2.Regexp
	excludeFilterRegs               []*regexp2.Regexp
	ipPureCountryFilterCodes        []string
	excludeIPPureCountryFilterCodes []string
	ipPureFraudScoreConditions      []func(int) bool
	excludeTypeArray                []string
	weightFilterConditions          []func(int) bool
	providers                       []P.ProxyProvider
	failedTestMux                   sync.Mutex
	failedTimes                     int
	failedTime                      time.Time
	failedTesting                   atomic.Bool
	testTimeout                     int
	maxFailedTimes                  int
	emptyFallback                   C.Proxy

	// for GetProxies
	getProxiesMutex     sync.Mutex
	providerVersions    []uint32
	providerProxies     []C.Proxy
	ipPureFilterExpires time.Time
}

type GroupBaseOption struct {
	Name                       string
	Type                       C.AdapterType
	Hidden                     bool
	Icon                       string
	Filter                     string
	ExcludeFilter              string
	IPPureCountryFilter        string
	ExcludeIPPureCountryFilter string
	IPPureFraudScoreFilter     string
	ExcludeType                string
	TestTimeout                int
	MaxFailedTimes             int
	EmptyFallback              C.Proxy
	Providers                  []P.ProxyProvider
	Weight                     uint16
	WeightFilter               string
}

func NewGroupBase(opt GroupBaseOption) *GroupBase {
	var excludeTypeArray []string
	if opt.ExcludeType != "" {
		excludeTypeArray = strings.Split(opt.ExcludeType, "|")
	}

	var excludeFilterRegs []*regexp2.Regexp
	if opt.ExcludeFilter != "" {
		for _, excludeFilter := range strings.Split(opt.ExcludeFilter, "`") {
			excludeFilterReg := regexp2.MustCompile(excludeFilter, regexp2.None)
			excludeFilterRegs = append(excludeFilterRegs, excludeFilterReg)
		}
	}

	var filterRegs []*regexp2.Regexp
	if opt.Filter != "" {
		for _, filter := range strings.Split(opt.Filter, "`") {
			filterReg := regexp2.MustCompile(filter, regexp2.None)
			filterRegs = append(filterRegs, filterReg)
		}
	}

	gb := &GroupBase{
		Base:                            outbound.NewBase(outbound.BaseOption{Name: opt.Name, Type: opt.Type, Weight: opt.Weight}),
		hidden:                          opt.Hidden,
		icon:                            opt.Icon,
		filterRegs:                      filterRegs,
		excludeFilterRegs:               excludeFilterRegs,
		ipPureCountryFilterCodes:        splitCountryFilter(opt.IPPureCountryFilter),
		excludeIPPureCountryFilterCodes: splitCountryFilter(opt.ExcludeIPPureCountryFilter),
		excludeTypeArray:                excludeTypeArray,
		providers:                       opt.Providers,
		failedTesting:                   atomic.NewBool(false),
		testTimeout:                     opt.TestTimeout,
		maxFailedTimes:                  opt.MaxFailedTimes,
		emptyFallback:                   opt.EmptyFallback,
	}

	if opt.WeightFilter != "" {
		conds, err := ParseWeightFilter(opt.WeightFilter)
		if err != nil {
			log.Errorln("Group %s parse weight filter error: %s", opt.Name, err)
		} else {
			gb.weightFilterConditions = conds
		}
	}

	if opt.IPPureFraudScoreFilter != "" {
		conds, err := ParseIPPureFraudScoreFilter(opt.IPPureFraudScoreFilter)
		if err != nil {
			log.Errorln("Group %s parse ippure fraud score filter error: %s", opt.Name, err)
		} else {
			gb.ipPureFraudScoreConditions = conds
		}
	}

	if gb.testTimeout == 0 {
		gb.testTimeout = 5000
	}
	if gb.maxFailedTimes == 0 {
		gb.maxFailedTimes = 5
	}

	return gb
}

func (gb *GroupBase) Hidden() bool {
	return gb.hidden
}

func (gb *GroupBase) hasIPPureFilter() bool {
	return len(gb.ipPureCountryFilterCodes) > 0 ||
		len(gb.excludeIPPureCountryFilterCodes) > 0 ||
		len(gb.ipPureFraudScoreConditions) > 0
}

func (gb *GroupBase) Icon() string {
	return gb.icon
}

func (gb *GroupBase) EmptyFallback() C.Proxy {
	return gb.emptyFallback
}

func (gb *GroupBase) Touch() {
	for _, pd := range gb.providers {
		pd.Touch()
	}
}

func (gb *GroupBase) GetProxies(touch bool) []C.Proxy {
	return gb.getProxies(touch, true)
}

func (gb *GroupBase) GetProxiesForDisplay() []C.Proxy {
	if gb.getProxiesMutex.TryLock() {
		if len(gb.providerProxies) > 0 {
			proxies := gb.providerProxies
			gb.getProxiesMutex.Unlock()
			return proxies
		}
		gb.getProxiesMutex.Unlock()
	}

	var proxies []C.Proxy
	for _, pd := range gb.providers {
		proxies = append(proxies, pd.Proxies()...)
	}
	if len(proxies) == 0 {
		return []C.Proxy{gb.EmptyFallback()}
	}
	return proxies
}

func (gb *GroupBase) SupportUDPForDisplay() bool {
	return gb.supportUDPForDisplay(map[string]struct{}{})
}

func (gb *GroupBase) supportUDPForDisplay(seen map[string]struct{}) bool {
	if _, ok := seen[gb.Name()]; ok {
		return false
	}
	seen[gb.Name()] = struct{}{}

	for _, proxy := range gb.GetProxiesForDisplay() {
		if group, ok := proxy.Adapter().(interface {
			supportUDPForDisplay(map[string]struct{}) bool
		}); ok {
			if group.supportUDPForDisplay(seen) {
				return true
			}
			continue
		}
		if proxy.SupportUDP() {
			return true
		}
	}
	return false
}

func (gb *GroupBase) getProxies(touch bool, refreshIPPure bool) []C.Proxy {
	providerVersions := make([]uint32, len(gb.providers))
	for i, pd := range gb.providers {
		if touch { // touch first
			pd.Touch()
		}
		providerVersions[i] = pd.Version()
	}

	// thread safe
	gb.getProxiesMutex.Lock()
	defer gb.getProxiesMutex.Unlock()

	// return the cached proxies if version not changed
	sameProviderVersions := slices.Equal(providerVersions, gb.providerVersions)
	if sameProviderVersions && len(gb.providerProxies) > 0 &&
		(!gb.hasIPPureFilter() || time.Now().Before(gb.ipPureFilterExpires)) {
		return gb.providerProxies
	}

	var proxies []C.Proxy
	if len(gb.filterRegs) == 0 {
		for _, pd := range gb.providers {
			if len(gb.weightFilterConditions) > 0 {
				for _, p := range pd.Proxies() {
					w := int(p.Weight())
					keep := true
					for _, cond := range gb.weightFilterConditions {
						if !cond(w) {
							keep = false
							break
						}
					}
					if keep {
						proxies = append(proxies, p)
					}
				}
			} else {
				proxies = append(proxies, pd.Proxies()...)
			}
		}
	} else {
		for _, pd := range gb.providers {
			if pd.VehicleType() == P.Compatible { // compatible provider unneeded filter
				if len(gb.weightFilterConditions) > 0 {
					var newProxies []C.Proxy
					for _, p := range pd.Proxies() {
						w := int(p.Weight())
						keep := true
						for _, cond := range gb.weightFilterConditions {
							if !cond(w) {
								keep = false
								break
							}
						}
						if keep {
							newProxies = append(newProxies, p)
						}
					}
					proxies = append(proxies, newProxies...)
				} else {
					proxies = append(proxies, pd.Proxies()...)
				}
				continue
			}

			var newProxies []C.Proxy
			proxiesSet := map[string]struct{}{}
			for _, filterReg := range gb.filterRegs {
				for _, p := range pd.Proxies() {
					name := p.Name()
					if mat, _ := filterReg.MatchString(name); mat {
						if _, ok := proxiesSet[name]; !ok {
							proxiesSet[name] = struct{}{}
							// Check weight filter
							if len(gb.weightFilterConditions) > 0 {
								w := int(p.Weight())
								keep := true
								for _, cond := range gb.weightFilterConditions {
									if !cond(w) {
										keep = false
										break
									}
								}
								if !keep {
									continue
								}
							}
							newProxies = append(newProxies, p)
						}
					}
				}
			}
			proxies = append(proxies, newProxies...)
		}
	}

	// Multiple filers means that proxies are sorted in the order in which the filers appear.
	// Although the filter has been performed once in the previous process,
	// when there are multiple providers, the array needs to be reordered as a whole.
	if len(gb.providers) > 1 && len(gb.filterRegs) > 1 {
		var newProxies []C.Proxy
		proxiesSet := map[string]struct{}{}
		for _, filterReg := range gb.filterRegs {
			for _, p := range proxies {
				name := p.Name()
				if mat, _ := filterReg.MatchString(name); mat {
					if _, ok := proxiesSet[name]; !ok {
						proxiesSet[name] = struct{}{}
						newProxies = append(newProxies, p)
					}
				}
			}
		}
		for _, p := range proxies { // add not matched proxies at the end
			name := p.Name()
			if _, ok := proxiesSet[name]; !ok {
				proxiesSet[name] = struct{}{}
				newProxies = append(newProxies, p)
			}
		}
		proxies = newProxies
	}

	if len(gb.excludeFilterRegs) > 0 {
		var newProxies []C.Proxy
	LOOP1:
		for _, p := range proxies {
			name := p.Name()
			for _, excludeFilterReg := range gb.excludeFilterRegs {
				if mat, _ := excludeFilterReg.MatchString(name); mat {
					continue LOOP1
				}
			}
			newProxies = append(newProxies, p)
		}
		proxies = newProxies
	}

	if gb.excludeTypeArray != nil {
		var newProxies []C.Proxy
	LOOP2:
		for _, p := range proxies {
			mType := p.Type().String()
			for _, excludeType := range gb.excludeTypeArray {
				if strings.EqualFold(mType, excludeType) {
					continue LOOP2
				}
			}
			newProxies = append(newProxies, p)
		}
		proxies = newProxies
	}

	if gb.hasIPPureFilter() && !refreshIPPure {
		if sameProviderVersions && len(gb.providerProxies) > 0 {
			return gb.providerProxies
		}
		if len(proxies) == 0 {
			return []C.Proxy{gb.EmptyFallback()}
		}
		return proxies
	}

	var usedStaleIPPure bool
	proxies, usedStaleIPPure = gb.filterIPPureProxies(proxies)

	if len(proxies) == 0 {
		if gb.hasIPPureFilter() && sameProviderVersions && len(gb.providerProxies) > 0 {
			gb.ipPureFilterExpires = time.Now().Add(ipPureStaleFilterTTL)
			return gb.providerProxies
		}
		return []C.Proxy{gb.EmptyFallback()}
	}

	// only cache when proxies not empty
	gb.providerVersions = providerVersions
	gb.providerProxies = proxies
	if gb.hasIPPureFilter() {
		if usedStaleIPPure {
			gb.ipPureFilterExpires = time.Now().Add(ipPureStaleFilterTTL)
		} else {
			gb.ipPureFilterExpires = time.Now().Add(defaultIPPureCacheTTL)
		}
	} else {
		gb.ipPureFilterExpires = time.Time{}
	}

	return proxies
}

func (gb *GroupBase) URLTest(ctx context.Context, url string, expectedStatus utils.IntRanges[uint16]) (map[string]uint16, error) {
	var wg sync.WaitGroup
	var lock sync.Mutex
	mp := map[string]uint16{}
	proxies := gb.GetProxies(false)
	for _, proxy := range proxies {
		proxy := proxy
		wg.Add(1)
		go func() {
			delay, err := proxy.URLTest(ctx, url, expectedStatus)
			if err == nil {
				lock.Lock()
				mp[proxy.Name()] = delay
				lock.Unlock()
			}

			wg.Done()
		}()
	}
	wg.Wait()

	if len(mp) == 0 {
		return mp, fmt.Errorf("get delay: all proxies timeout")
	} else {
		return mp, nil
	}
}

func (gb *GroupBase) onDialFailed(adapterType C.AdapterType, err error, fn func()) {
	if adapterType == C.Direct || adapterType == C.Compatible || adapterType == C.Reject || adapterType == C.Pass || adapterType == C.RejectDrop {
		return
	}

	if errors.Is(err, C.ErrNotSupport) {
		return
	}

	go func() {
		if strings.Contains(err.Error(), "connection refused") {
			fn()
			return
		}

		gb.failedTestMux.Lock()
		defer gb.failedTestMux.Unlock()

		gb.failedTimes++
		if gb.failedTimes == 1 {
			log.Debugln("ProxyGroup: %s first failed", gb.Name())
			gb.failedTime = time.Now()
		} else {
			if time.Since(gb.failedTime) > time.Duration(gb.testTimeout)*time.Millisecond {
				gb.failedTimes = 0
				return
			}

			log.Debugln("ProxyGroup: %s failed count: %d", gb.Name(), gb.failedTimes)
			if gb.failedTimes >= gb.maxFailedTimes {
				log.Warnln("because %s failed multiple times, activate health check", gb.Name())
				fn()
			}
		}
	}()
}

func (gb *GroupBase) healthCheck() {
	if gb.failedTesting.Load() {
		return
	}

	gb.failedTesting.Store(true)
	wg := sync.WaitGroup{}
	for _, proxyProvider := range gb.providers {
		wg.Add(1)
		proxyProvider := proxyProvider
		go func() {
			defer wg.Done()
			proxyProvider.HealthCheck()
		}()
	}

	wg.Wait()
	gb.failedTesting.Store(false)
	gb.failedTimes = 0
}

func (gb *GroupBase) onDialSuccess() {
	if !gb.failedTesting.Load() {
		gb.failedTimes = 0
	}
}

func ParseWeightFilter(filter string) ([]func(int) bool, error) {
	return parseIntFilter(filter, []string{"w", "weight"})
}

func ParseIPPureFraudScoreFilter(filter string) ([]func(int) bool, error) {
	return parseIntFilter(filter, []string{"f", "fs", "fraud", "fraud-score", "fraudscore"})
}

func parseIntFilter(filter string, valueNames []string) ([]func(int) bool, error) {
	filter = strings.ToLower(strings.TrimSpace(filter))
	if filter == "" {
		return nil, nil
	}

	parts := strings.Split(filter, "&&")
	var conditions []func(int) bool

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Handle range syntax like 10<w<=100
		operators := []string{">=", "<=", ">", "<", "="}
		var opsFound []string
		var opIndices []int

		tempPart := part
		offset := 0
		for {
			idx := -1
			foundOp := ""
			for _, op := range operators {
				i := strings.Index(tempPart, op)
				if i != -1 {
					if idx == -1 || i < idx {
						idx = i
						foundOp = op
					}
				}
			}

			if idx != -1 {
				opsFound = append(opsFound, foundOp)
				opIndices = append(opIndices, offset+idx)
				tempPart = tempPart[idx+len(foundOp):]
				offset += idx + len(foundOp)
			} else {
				break
			}
		}

		if len(opsFound) == 2 {
			firstOpIdx := opIndices[0]
			firstOpLen := len(opsFound[0])
			secondOpIdx := opIndices[1]

			left := strings.TrimSpace(part[:firstOpIdx])
			middle := strings.TrimSpace(part[firstOpIdx+firstOpLen : secondOpIdx])
			right := strings.TrimSpace(part[secondOpIdx+len(opsFound[1]):])

			if !isFilterValueName(middle, valueNames) {
				return nil, fmt.Errorf("invalid range format (middle must be %s): %s", strings.Join(valueNames, "/"), part)
			}

			op1 := opsFound[0]
			val1, err := strconv.Atoi(left)
			if err != nil {
				return nil, fmt.Errorf("invalid value in range: %s", left)
			}

			cond1, err := createCondition(op1, val1, true)
			if err != nil {
				return nil, err
			}
			conditions = append(conditions, cond1)

			op2 := opsFound[1]
			val2, err := strconv.Atoi(right)
			if err != nil {
				return nil, fmt.Errorf("invalid value in range: %s", right)
			}
			cond2, err := createCondition(op2, val2, false)
			if err != nil {
				return nil, err
			}
			conditions = append(conditions, cond2)

		} else if len(opsFound) == 1 {
			op := opsFound[0]
			idx := opIndices[0]
			left := strings.TrimSpace(part[:idx])
			right := strings.TrimSpace(part[idx+len(op):])

			var val int
			var err error
			reverse := false

			if isFilterValueName(left, valueNames) {
				val, err = strconv.Atoi(right)
			} else if isFilterValueName(right, valueNames) {
				val, err = strconv.Atoi(left)
				reverse = true
			} else if left == "" && right != "" {
				val, err = strconv.Atoi(right)
			} else {
				return nil, fmt.Errorf("invalid simple filter format: %s", part)
			}

			if err != nil {
				return nil, fmt.Errorf("invalid value in filter: %s", part)
			}

			cond, err := createCondition(op, val, reverse)
			if err != nil {
				return nil, err
			}
			conditions = append(conditions, cond)

		} else {
			val, err := strconv.Atoi(part)
			if err == nil {
				conditions = append(conditions, func(w int) bool { return w == val })
			} else {
				return nil, fmt.Errorf("invalid filter format: %s", part)
			}
		}
	}

	return conditions, nil
}

func isFilterValueName(value string, names []string) bool {
	for _, name := range names {
		if value == name {
			return true
		}
	}
	return false
}

func createCondition(op string, target int, reverse bool) (func(int) bool, error) {
	if reverse {
		switch op {
		case ">=":
			op = "<="
		case "<=":
			op = ">="
		case ">":
			op = "<"
		case "<":
			op = ">"
		case "=":
			op = "="
		default:
			return nil, fmt.Errorf("unknown operator: %s", op)
		}
	}

	switch op {
	case ">=":
		return func(w int) bool { return w >= target }, nil
	case "<=":
		return func(w int) bool { return w <= target }, nil
	case ">":
		return func(w int) bool { return w > target }, nil
	case "<":
		return func(w int) bool { return w < target }, nil
	case "=":
		return func(w int) bool { return w == target }, nil
	default:
		return nil, fmt.Errorf("unknown operator: %s", op)
	}
}
