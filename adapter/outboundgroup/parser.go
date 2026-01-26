package outboundgroup

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/dlclark/regexp2"

	"github.com/metacubex/mihomo/adapter/provider"
	"github.com/metacubex/mihomo/common/structure"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/log"
)

var (
	errFormat            = errors.New("format error")
	errType              = errors.New("unsupported type")
	errMissProxy         = errors.New("`use` or `proxies` missing")
	errDuplicateProvider = errors.New("duplicate provider name")
)

type GroupCommonOption struct {
	Name                string   `group:"name"`
	Type                string   `group:"type"`
	Proxies             []string `group:"proxies,omitempty"`
	Use                 []string `group:"use,omitempty"`
	URL                 string   `group:"url,omitempty"`
	Interval            int      `group:"interval,omitempty"`
	TestTimeout         int      `group:"timeout,omitempty"`
	MaxFailedTimes      int      `group:"max-failed-times,omitempty"`
	Lazy                bool     `group:"lazy,omitempty"`
	DisableUDP          bool     `group:"disable-udp,omitempty"`
	Filter              string   `group:"filter,omitempty"`
	ExcludeFilter       string   `group:"exclude-filter,omitempty"`
	ExcludeType         string   `group:"exclude-type,omitempty"`
	ExpectedStatus      string   `group:"expected-status,omitempty"`
	IncludeAll          bool     `group:"include-all,omitempty"`
	IncludeAllProxies   bool     `group:"include-all-proxies,omitempty"`
	IncludeAllProviders bool     `group:"include-all-providers,omitempty"`
	Hidden              bool     `group:"hidden,omitempty"`
	Icon                string   `group:"icon,omitempty"`
	Weight              int      `group:"weight,omitempty"`
	WeightFilter        string   `group:"weight-filter,omitempty"`

	// removed configs, only for error logging
	Interface   string `group:"interface-name,omitempty"`
	RoutingMark int    `group:"routing-mark,omitempty"`
}

func ParseProxyGroup(config map[string]any, proxyMap map[string]C.Proxy, providersMap map[string]P.ProxyProvider, AllProxies []string, AllProviders []string) (C.ProxyAdapter, error) {
	decoder := structure.NewDecoder(structure.Option{TagName: "group", WeaklyTypedInput: true})

	groupOption := &GroupCommonOption{
		Lazy: true,
	}
	if err := decoder.Decode(config, groupOption); err != nil {
		return nil, errFormat
	}

	if groupOption.Type == "" || groupOption.Name == "" {
		return nil, errFormat
	}

	if groupOption.RoutingMark != 0 {
		log.Errorln("The group [%s] with routing-mark configuration was removed, please set it directly on the proxy instead", groupOption.Name)
	}
	if groupOption.Interface != "" {
		log.Errorln("The group [%s] with interface-name configuration was removed, please set it directly on the proxy instead", groupOption.Name)
	}

	groupName := groupOption.Name

	providers := []P.ProxyProvider{}

	if groupOption.IncludeAll {
		groupOption.IncludeAllProviders = true
		groupOption.IncludeAllProxies = true
	}

	if groupOption.IncludeAllProviders {
		groupOption.Use = AllProviders
	}
	if groupOption.IncludeAllProxies {
		if groupOption.Filter != "" {
			var filterRegs []*regexp2.Regexp
			for _, filter := range strings.Split(groupOption.Filter, "`") {
				filterReg := regexp2.MustCompile(filter, regexp2.None)
				filterRegs = append(filterRegs, filterReg)
			}
			for _, p := range AllProxies {
				for _, filterReg := range filterRegs {
					if mat, _ := filterReg.MatchString(p); mat {
						groupOption.Proxies = append(groupOption.Proxies, p)
					}
				}
			}
		} else {
			groupOption.Proxies = append(groupOption.Proxies, AllProxies...)
		}
		if len(groupOption.Proxies) == 0 && len(groupOption.Use) == 0 {
			groupOption.Proxies = []string{"COMPATIBLE"}
		}
	}

	if len(groupOption.Proxies) == 0 && len(groupOption.Use) == 0 {
		return nil, fmt.Errorf("%s: %w", groupName, errMissProxy)
	}

	expectedStatus, err := utils.NewUnsignedRanges[uint16](groupOption.ExpectedStatus)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", groupName, err)
	}

	status := strings.TrimSpace(groupOption.ExpectedStatus)
	if status == "" {
		status = "*"
	}
	groupOption.ExpectedStatus = status

	if len(groupOption.Use) != 0 {
		PDs, err := getProviders(providersMap, groupOption.Use)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", groupName, err)
		}

		// if test URL is empty, use the first health check URL of providers
		if groupOption.URL == "" {
			for _, pd := range PDs {
				if pd.HealthCheckURL() != "" {
					groupOption.URL = pd.HealthCheckURL()
					break
				}
			}
			if groupOption.URL == "" {
				groupOption.URL = C.DefaultTestURL
			}
		} else {
			addTestUrlToProviders(PDs, groupOption.URL, expectedStatus, groupOption.Filter, uint(groupOption.Interval))
		}
		providers = append(providers, PDs...)
	}

	if len(groupOption.Proxies) != 0 {
		ps, err := getProxies(proxyMap, groupOption.Proxies)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", groupName, err)
		}

		if groupOption.WeightFilter != "" {
			ps, err = filterByWeight(ps, groupOption.WeightFilter)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", groupName, err)
			}
		}

		if len(groupOption.Use) == 0 && len(ps) == 0 {
			return nil, fmt.Errorf("%s: %w", groupName, errMissProxy)
		}

		if len(ps) != 0 {
			if _, ok := providersMap[groupName]; ok {
				return nil, fmt.Errorf("%s: %w", groupName, errDuplicateProvider)
			}

			if groupOption.URL == "" {
				groupOption.URL = C.DefaultTestURL
			}

			// select don't need auto health check
			if groupOption.Type != "select" && groupOption.Type != "relay" {
				if groupOption.Interval == 0 {
					groupOption.Interval = 300
				}
			}

			hc := provider.NewHealthCheck(ps, groupOption.URL, uint(groupOption.TestTimeout), uint(groupOption.Interval), groupOption.Lazy, expectedStatus)

			pd, err := provider.NewCompatibleProvider(groupName, ps, hc)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", groupName, err)
			}

			providers = append([]P.ProxyProvider{pd}, providers...)
			providersMap[groupName] = pd
		}
	}

	var group C.ProxyAdapter
	switch groupOption.Type {
	case "url-test":
		opts := parseURLTestOption(config)
		group = NewURLTest(groupOption, providers, opts...)
	case "select":
		group = NewSelector(groupOption, providers)
	case "fallback":
		group = NewFallback(groupOption, providers)
	case "load-balance":
		strategy := parseStrategy(config)
		return NewLoadBalance(groupOption, providers, strategy)
	case "relay":
		return nil, fmt.Errorf("%w: The group [%s] with relay type was removed, please using dialer-proxy instead", errType, groupName)
	default:
		return nil, fmt.Errorf("%w: %s", errType, groupOption.Type)
	}

	return group, nil
}

func getProxies(mapping map[string]C.Proxy, list []string) ([]C.Proxy, error) {
	var ps []C.Proxy
	for _, name := range list {
		p, ok := mapping[name]
		if !ok {
			return nil, fmt.Errorf("'%s' not found", name)
		}
		ps = append(ps, p)
	}
	return ps, nil
}

func getProviders(mapping map[string]P.ProxyProvider, list []string) ([]P.ProxyProvider, error) {
	var ps []P.ProxyProvider
	for _, name := range list {
		p, ok := mapping[name]
		if !ok {
			return nil, fmt.Errorf("'%s' not found", name)
		}

		if p.VehicleType() == P.Compatible {
			return nil, fmt.Errorf("proxy group %s can't contains in `use`", name)
		}
		ps = append(ps, p)
	}
	return ps, nil
}

func addTestUrlToProviders(providers []P.ProxyProvider, url string, expectedStatus utils.IntRanges[uint16], filter string, interval uint) {
	if len(providers) == 0 || len(url) == 0 {
		return
	}

	for _, pd := range providers {
		pd.RegisterHealthCheckTask(url, expectedStatus, filter, interval)
	}
}

func filterByWeight(proxies []C.Proxy, filter string) ([]C.Proxy, error) {
	filter = strings.ToLower(strings.TrimSpace(filter))
	if filter == "" {
		return proxies, nil
	}

	parts := strings.Split(filter, "&&")
	var conditions []func(int) bool

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Handle range syntax like 10<w<=100
		// We look for index of operators
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
			// Range syntax: val1 op1 w op2 val2
			// split into val1 op1 w AND w op2 val2
			// identifying "w" position is tricky if implicit.
			// Assumption: w is in the middle.
			// val1 op1 w op2 val2
			// But easier approach: split by "w" if present?
			// Let's rely on splitting by the operators found.

			// We have 2 operators at opIndices[0] and opIndices[1].
			// First operator is at opIndices[0] with length len(opsFound[0])
			// Second operator is at opIndices[1] with length len(opsFound[1])

			firstOpIdx := opIndices[0]
			firstOpLen := len(opsFound[0])
			secondOpIdx := opIndices[1]
			// secondOpLen := len(opsFound[1])

			left := strings.TrimSpace(part[:firstOpIdx])
			middle := strings.TrimSpace(part[firstOpIdx+firstOpLen : secondOpIdx])
			right := strings.TrimSpace(part[secondOpIdx+len(opsFound[1]):])

			// Validate middle is "w" (or empty if implicit?) - actually standard math notation usually has variable in middle.
			// Allow "w" to be missing if it's just implicit? No, 10<100 is valid bool but 10<=100 isn't a proxy filter.
			// We expect 10<w<=100. Middle should contain 'w'.
			if middle != "w" {
				return nil, fmt.Errorf("invalid range format (middle must be 'w'): %s", part)
			}

			// Condition 1: left op1 w -> which is equivalent to w reverse_op1 left
			// e.g. 10 < w  => w > 10
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

			// Condition 2: w op2 right
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
			// Simple check: w op val OR op val OR val op w
			op := opsFound[0]
			idx := opIndices[0]
			left := strings.TrimSpace(part[:idx])
			right := strings.TrimSpace(part[idx+len(op):])

			var val int
			var err error
			reverse := false

			if left == "w" {
				// w op val
				val, err = strconv.Atoi(right)
			} else if right == "w" {
				// val op w -> equivalent to w reverse_op val
				val, err = strconv.Atoi(left)
				reverse = true
			} else if left == "" && right != "" {
				// op val (implicit w at start) -> w op val
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
			// No operator found? maybe just "10" (implicit = 10) or "=10" (handled above if = detected)
			// if just a number
			val, err := strconv.Atoi(part)
			if err == nil {
				conditions = append(conditions, func(w int) bool { return w == val })
			} else {
				return nil, fmt.Errorf("invalid filter format: %s", part)
			}
		}
	}

	var filtered []C.Proxy
	for _, p := range proxies {
		w := int(p.Weight())
		keep := true
		for _, cond := range conditions {
			if !cond(w) {
				keep = false
				break
			}
		}
		if keep {
			filtered = append(filtered, p)
		}
	}

	return filtered, nil
}

func createCondition(op string, target int, reverse bool) (func(int) bool, error) {
	if reverse {
		switch op {
		case ">=":
			op = "<=" // val >= w  <=> w <= val
		case "<=":
			op = ">=" // val <= w  <=> w >= val
		case ">":
			op = "<" // val > w   <=> w < val
		case "<":
			op = ">" // val < w   <=> w > val
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
