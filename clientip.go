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

	// Walk the header from the right instead of splitting the whole value:
	// headers can be large and only the selected hop matters on the request
	// path.
	remaining := depth
	end := len(raw)
	for end > 0 {
		start := strings.LastIndexByte(raw[:end], ',') + 1
		value := strings.TrimSpace(raw[start:end])
		if value != "" {
			remaining--
			if remaining == 0 {
				ip := parseIP(value)
				if ip == nil {
					return remote
				}
				return ip
			}
		}

		if start == 0 {
			break
		}
		end = start - 1
	}

	return remote
}

// parseIP parses an address, optionally with a port, IPv6 brackets or an
// IPv6 zone identifier.
func parseIP(value string) net.IP {
	value = stripIPv6Zone(strings.TrimSpace(value))
	if value == "" {
		return nil
	}

	if ip := net.ParseIP(value); ip != nil {
		return ip
	}

	if host, _, err := net.SplitHostPort(value); err == nil {
		host = stripIPv6Zone(host)
		if ip := net.ParseIP(host); ip != nil {
			return ip
		}
	}

	if len(value) > 2 && value[0] == '[' && value[len(value)-1] == ']' {
		if ip := net.ParseIP(stripIPv6Zone(value[1 : len(value)-1])); ip != nil {
			return ip
		}
	}

	return nil
}

// stripIPv6Zone removes a %zone suffix (for example %eth0) from an address.
// Zones are only meaningful on a local link and net.ParseIP rejects them;
// ignoring them lets zoned link-local peers match like any other address.
func stripIPv6Zone(value string) string {
	index := strings.IndexByte(value, '%')
	if index < 0 {
		return value
	}

	end := index
	for end < len(value) && value[end] != ']' {
		end++
	}

	return value[:index] + value[end:]
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
