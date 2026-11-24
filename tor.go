package threatdb

import (
	"strings"
	"time"
)

const (
	defaultTorExitAddressesURL = "https://check.torproject.org/exit-addresses"
	torRefreshInterval         = 60 * time.Minute
	torProviderKey             = "tor"
	torProviderName            = "Tor exit nodes"
)

// torExitAddressesURL is a variable so tests can point at a local server.
var torExitAddressesURL = defaultTorExitAddressesURL

// buildTorProvider returns the shared cache for the Tor exit-node list.
func buildTorProvider(opts *options, prefix string) *providerCache {
	settings := providerShareSettings{
		kind:         "tor",
		url:          torExitAddressesURL,
		interval:     torRefreshInterval,
		timeout:      opts.requestTimeout,
		maxListBytes: opts.maxListBytes,
		userAgent:    opts.userAgent,
	}

	candidate := newProviderCache(torProviderKey, torProviderName, settings, prefix)
	candidate.parse = parseTorExitAddresses
	return acquireSharedProvider(settings.key(), candidate)
}

// parseTorExitAddresses extracts the address from each "ExitAddress" line of
// https://check.torproject.org/exit-addresses. Other lines (ExitNode,
// Published, LastStatus) are ignored.
func parseTorExitAddresses(body []byte) (*ipSet, int, int, error) {
	scanner := newLineScanner(body)
	set := newIPSet()

	valid := 0
	invalid := 0
	first := true

	for scanner.Scan() {
		line := scanner.Text()
		if first {
			line = strings.TrimPrefix(line, "\ufeff")
			first = false
		}

		if index := strings.IndexByte(line, '#'); index >= 0 {
			line = line[:index]
		}
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "ExitAddress" {
			continue
		}
		if len(fields) < 2 {
			invalid++
			continue
		}

		ip := parseIP(fields[1])
		if ip == nil {
			invalid++
			continue
		}

		set.addIP(ip)
		valid++
	}

	if err := scanner.Err(); err != nil {
		return nil, 0, 0, err
	}

	return set, valid, invalid, nil
}
