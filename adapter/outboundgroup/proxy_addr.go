package outboundgroup

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/metacubex/mihomo/component/resolver"
)

func splitCountryFilter(filter string) []string {
	parts := strings.FieldsFunc(filter, func(r rune) bool {
		switch r {
		case ',', '|', '`', ' ', '\t', '\n', '\r':
			return true
		default:
			return false
		}
	})

	codes := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, part := range parts {
		code := strings.ToLower(strings.TrimSpace(part))
		if code == "" {
			continue
		}
		if _, ok := seen[code]; ok {
			continue
		}
		seen[code] = struct{}{}
		codes = append(codes, code)
	}
	return codes
}

func proxyAddrHost(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return strings.Trim(host, "[]")
	}
	if ip, err := netip.ParseAddr(strings.Trim(addr, "[]")); err == nil {
		return ip.String()
	}
	if strings.Count(addr, ":") == 1 {
		if host, _, found := strings.Cut(addr, ":"); found {
			return strings.Trim(host, "[]")
		}
	}
	return strings.Trim(addr, "[]")
}

func resolveProxyHostIP(host string) (netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Unmap(), nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if resolver.SystemResolver != nil {
		return resolver.ResolveIPWithResolver(ctx, host, resolver.ProxyServerHostResolver)
	}

	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return netip.Addr{}, err
	}
	if len(ips) == 0 {
		return netip.Addr{}, resolver.ErrIPNotFound
	}
	ipv4s, ipv6s := resolver.SortationAddr(ips)
	if len(ipv4s) > 0 {
		return ipv4s[0].Unmap(), nil
	}
	return ipv6s[0].Unmap(), nil
}
