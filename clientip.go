package threatdb

import (
	"net"
	"net/http"
	"strings"
)

// cgnatNet is the shared address space used by carrier-grade NAT
// (RFC 6598). net.IP.IsPrivate does not cover it.
var cgnatNet = mustParseCIDR("100.64.0.0/10")

func mustParseCIDR(value string) *net.IPNet {
	_, network, err := net.ParseCIDR(value)
	if err != nil {
		panic(err)
	}
	return network
}

// clientIP returns the address to match against the lists.
//
// With depth <= 0 the TCP peer address is used. Otherwise the configured
// forwarded header is read and the address depth hops from the right is
// returned, which is the client address as seen by the outermost trusted
// proxy. Malformed or too-short headers fall back to the peer address.
func clientIP(req *http.Request, header string, depth int) net.IP {
	if req == nil {
		return nil
	}

	remote := parseIP(req.RemoteAddr)
	if depth <= 0 || header == "" {
		return remote
	}

	raw := req.Header.Get(header)
	if raw == "" {
		return remote
	}

	values := make([]string, 0, 4)
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			values = append(values, part)
		}
	}

	if len(values) < depth {
		return remote
	}

	ip := parseIP(values[len(values)-depth])
	if ip == nil {
		return remote
	}

	return ip
}

// parseIP parses an address, optionally with a port or IPv6 brackets.
func parseIP(value string) net.IP {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}

	if ip := net.ParseIP(value); ip != nil {
		return ip
	}

	if host, _, err := net.SplitHostPort(value); err == nil {
		if ip := net.ParseIP(host); ip != nil {
			return ip
		}
	}

	if len(value) > 2 && value[0] == '[' && value[len(value)-1] == ']' {
		if ip := net.ParseIP(value[1 : len(value)-1]); ip != nil {
			return ip
		}
	}

	return nil
}

// isInternalIP reports whether the address is not a normal publicly routable
// client address.
func isInternalIP(ip net.IP) bool {
	return ip.IsPrivate() ||
		ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified() ||
		cgnatNet.Contains(ip)
}
