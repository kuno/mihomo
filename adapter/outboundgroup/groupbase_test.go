package outboundgroup

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

type testProxyProvider struct {
	name    string
	proxies []C.Proxy
}

func (p testProxyProvider) Name() string { return p.name }

func (p testProxyProvider) VehicleType() P.VehicleType { return P.HTTP }

func (p testProxyProvider) Type() P.ProviderType { return P.Proxy }

func (p testProxyProvider) Initial() error { return nil }

func (p testProxyProvider) Update() error { return nil }

func (p testProxyProvider) Proxies() []C.Proxy { return p.proxies }

func (p testProxyProvider) Count() int { return len(p.proxies) }

func (p testProxyProvider) Touch() {}

func (p testProxyProvider) HealthCheck() {}

func (p testProxyProvider) Version() uint32 { return 1 }

func (p testProxyProvider) RegisterHealthCheckTask(string, utils.IntRanges[uint16], string, uint) {}

func (p testProxyProvider) HealthCheckURL() string { return "" }

func testProvider(name string, proxies ...C.Proxy) P.ProxyProvider {
	return testProxyProvider{name: name, proxies: proxies}
}

func TestGetProxiesForDisplayUsesFilteredFallback(t *testing.T) {
	proxy := adapter.NewProxy(outbound.NewDirect())
	fallback := adapter.NewProxy(outbound.NewReject())
	gb := NewGroupBase(GroupBaseOption{
		Name:          "test",
		Type:          C.URLTest,
		Filter:        "does-not-match",
		EmptyFallback: fallback,
		Providers:     []P.ProxyProvider{testProvider("provider", proxy)},
	})

	proxies := gb.GetProxiesForDisplay()
	if len(proxies) != 1 || proxies[0].Name() != "REJECT" {
		t.Fatalf("display proxies = %v, want [REJECT]", proxyNames(proxies))
	}
}

func TestGetProxiesForDisplayUsesIPPureFilteredFallback(t *testing.T) {
	gb := newCachedIPPureCountryMismatchGroup(t)

	proxies := gb.GetProxiesForDisplay()
	if len(proxies) != 1 || proxies[0].Name() != "REJECT" {
		t.Fatalf("display proxies = %v, want [REJECT]", proxyNames(proxies))
	}
}

func TestURLTestMarshalJSONUsesFilteredFallbackForAll(t *testing.T) {
	group := &URLTest{GroupBase: newCachedIPPureCountryMismatchGroup(t)}

	data, err := group.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}

	var body struct {
		All           []string `json:"all"`
		EmptyFallback string   `json:"emptyFallback"`
		Now           string   `json:"now"`
	}
	if err := json.Unmarshal(data, &body); err != nil {
		t.Fatal(err)
	}

	if body.EmptyFallback != "REJECT" {
		t.Fatalf("emptyFallback = %q, want REJECT", body.EmptyFallback)
	}
	if len(body.All) != 1 || body.All[0] != "REJECT" {
		t.Fatalf("all = %v, want [REJECT]", body.All)
	}
	if body.Now != "REJECT" {
		t.Fatalf("now = %q, want REJECT", body.Now)
	}
}

func newCachedIPPureCountryMismatchGroup(t *testing.T) *GroupBase {
	t.Helper()

	proxy := adapter.NewProxy(outbound.NewDirect())
	fallback := adapter.NewProxy(outbound.NewReject())
	gb := NewGroupBase(GroupBaseOption{
		Name:                "test",
		Type:                C.URLTest,
		IPPureCountryFilter: "sg",
		EmptyFallback:       fallback,
		Providers:           []P.ProxyProvider{testProvider("provider", proxy)},
	})

	ipPureCacheMutex.Lock()
	ipPureCache = map[string]ipPureCacheEntry{
		gb.ipPureCacheKey(proxy): {
			info:      &ipPureInfo{CountryCode: "us"},
			expiresAt: time.Now().Add(time.Hour),
		},
	}
	ipPureCacheMutex.Unlock()
	t.Cleanup(func() {
		ipPureCacheMutex.Lock()
		ipPureCache = map[string]ipPureCacheEntry{}
		ipPureCacheMutex.Unlock()
	})

	return gb
}

func proxyNames(proxies []C.Proxy) []string {
	names := make([]string, 0, len(proxies))
	for _, proxy := range proxies {
		names = append(names, proxy.Name())
	}
	return names
}
