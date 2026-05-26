package outboundgroup

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/http"
	"golang.org/x/exp/slices"
)

const (
	defaultIPPureURL      = "https://my.ippure.com/v1/info"
	defaultIPPureUA       = "Mozilla/5.0 (compatible; mihomo ippure-filter)"
	defaultIPPureTimeout  = 8 * time.Second
	defaultIPPureCacheTTL = 30 * time.Minute
	maxIPPureConcurrency  = 8
	maxIPPureErrorBody    = 256
)

type ipPureInfo struct {
	IP             string `json:"ip"`
	ASN            int    `json:"asn"`
	ASOrganization string `json:"asOrganization"`
	Country        string `json:"country"`
	CountryCode    string `json:"countryCode"`
	Region         string `json:"region"`
	RegionCode     string `json:"regionCode"`
	City           string `json:"city"`
	Timezone       string `json:"timezone"`
	Longitude      string `json:"longitude"`
	Latitude       string `json:"latitude"`
	PostalCode     string `json:"postalCode"`
	FraudScore     int    `json:"fraudScore"`
	IsResidential  bool   `json:"isResidential"`
	IsBroadcast    bool   `json:"isBroadcast"`
	UserAgent      string `json:"userAgent"`
}

type ipPureCacheEntry struct {
	info      *ipPureInfo
	expiresAt time.Time
}

func (gb *GroupBase) filterIPPureProxies(proxies []C.Proxy) []C.Proxy {
	if !gb.hasIPPureFilter() {
		return proxies
	}

	infos := make([]*ipPureInfo, len(proxies))
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxIPPureConcurrency)

	for idx, proxy := range proxies {
		idx, proxy := idx, proxy
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			infos[idx] = gb.lookupIPPure(proxy)
		}()
	}
	wg.Wait()

	filtered := make([]C.Proxy, 0, len(proxies))
	for idx, proxy := range proxies {
		info := infos[idx]
		if info == nil {
			continue
		}
		countryCode := strings.ToLower(strings.TrimSpace(info.CountryCode))
		if len(gb.ipPureCountryFilterCodes) > 0 && !slices.Contains(gb.ipPureCountryFilterCodes, countryCode) {
			continue
		}
		if len(gb.excludeIPPureCountryFilterCodes) > 0 && slices.Contains(gb.excludeIPPureCountryFilterCodes, countryCode) {
			continue
		}
		if !gb.matchIPPureFraudScore(info.FraudScore) {
			continue
		}
		filtered = append(filtered, proxy)
	}
	return filtered
}

func (gb *GroupBase) matchIPPureFraudScore(score int) bool {
	for _, condition := range gb.ipPureFraudScoreConditions {
		if !condition(score) {
			return false
		}
	}
	return true
}

func (gb *GroupBase) lookupIPPure(proxy C.Proxy) *ipPureInfo {
	key := proxy.Name() + "\x00" + proxy.Addr()
	now := time.Now()

	gb.ipPureCacheMutex.Lock()
	if entry, ok := gb.ipPureCache[key]; ok && now.Before(entry.expiresAt) {
		gb.ipPureCacheMutex.Unlock()
		return entry.info
	}
	gb.ipPureCacheMutex.Unlock()

	info, err := fetchIPPureInfo(proxy)
	if err != nil {
		log.Debugln("ProxyGroup %s skip ippure lookup for %s(%s): %s", gb.Name(), proxy.Name(), proxy.Addr(), err)
	}

	gb.ipPureCacheMutex.Lock()
	gb.ipPureCache[key] = ipPureCacheEntry{
		info:      info,
		expiresAt: now.Add(defaultIPPureCacheTTL),
	}
	gb.ipPureCacheMutex.Unlock()

	return info
}

func fetchIPPureInfo(proxy C.Proxy) (*ipPureInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultIPPureTimeout)
	defer cancel()

	metadata, err := ipPureURLToMetadata(defaultIPPureURL)
	if err != nil {
		return nil, err
	}

	instance, err := proxy.DialContext(ctx, &metadata)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = instance.Close()
	}()

	req, err := http.NewRequest(http.MethodGet, defaultIPPureURL, nil)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", defaultIPPureUA)

	tlsConfig, err := ca.GetTLSConfig(ca.Option{})
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return instance, nil
		},
		MaxIdleConns:          1,
		IdleConnTimeout:       10 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       tlsConfig,
	}

	client := http.Client{
		Timeout:   defaultIPPureTimeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	defer client.CloseIdleConnections()

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxIPPureErrorBody))
		if len(body) == 0 {
			return nil, fmt.Errorf("ippure returned status %d", resp.StatusCode)
		}
		return nil, fmt.Errorf("ippure returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var info ipPureInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, err
	}
	info.CountryCode = strings.ToLower(strings.TrimSpace(info.CountryCode))
	if info.CountryCode == "" {
		return nil, fmt.Errorf("ippure returned empty countryCode")
	}
	return &info, nil
}

func ipPureURLToMetadata(rawURL string) (metadata C.Metadata, err error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return metadata, err
	}

	port := u.Port()
	if port == "" {
		switch u.Scheme {
		case "https":
			port = "443"
		case "http":
			port = "80"
		default:
			return metadata, fmt.Errorf("%s scheme not support", rawURL)
		}
	}

	err = metadata.SetRemoteAddress(net.JoinHostPort(u.Hostname(), port))
	return metadata, err
}
