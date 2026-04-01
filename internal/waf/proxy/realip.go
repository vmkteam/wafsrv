package proxy

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// ExtractIP extracts the real client IP from the request using configured headers and trusted proxies.
// It checks headers in order, and for X-Forwarded-For takes the rightmost non-trusted IP.
// Falls back to RemoteAddr.
func ExtractIP(r *http.Request, headers []string, trusted []netip.Prefix) netip.Addr {
	for _, h := range headers {
		val := r.Header.Get(h)
		if val == "" {
			continue
		}

		if strings.EqualFold(h, "X-Forwarded-For") {
			if ip := extractFromXFF(val, trusted); ip.IsValid() {
				return ip
			}

			continue
		}

		if ip := parseIP(strings.TrimSpace(val)); ip.IsValid() {
			return ip
		}
	}

	return addrFromRemoteAddr(r.RemoteAddr)
}

// ParseTrustedProxies parses CIDR strings into netip.Prefix slice.
func ParseTrustedProxies(cidrs []string) ([]netip.Prefix, error) {
	result := make([]netip.Prefix, 0, len(cidrs))
	for _, cidr := range cidrs {
		p, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, err
		}

		result = append(result, p)
	}

	return result, nil
}

// extractFromXFF returns the rightmost non-trusted IP from X-Forwarded-For header.
func extractFromXFF(xff string, trusted []netip.Prefix) netip.Addr {
	parts := strings.Split(xff, ",")

	for i := len(parts) - 1; i >= 0; i-- {
		ip := parseIP(strings.TrimSpace(parts[i]))
		if !ip.IsValid() {
			continue
		}

		if !isTrusted(ip, trusted) {
			return ip
		}
	}

	return netip.Addr{}
}

func isTrusted(ip netip.Addr, trusted []netip.Prefix) bool {
	for _, p := range trusted {
		if p.Contains(ip) {
			return true
		}
	}

	return false
}

func parseIP(s string) netip.Addr {
	ip, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}
	}

	return ip
}

func addrFromRemoteAddr(remoteAddr string) netip.Addr {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return parseIP(remoteAddr)
	}

	return parseIP(host)
}
