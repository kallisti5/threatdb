package threatdb

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// statusResponse is the JSON document served on Config.StatusPath.
type statusResponse struct {
	Middleware      string           `json:"middleware,omitempty"`
	Version         string           `json:"version"`
	FailClosed      bool             `json:"failClosed"`
	BlockStatusCode int              `json:"blockStatusCode"`
	MaxStaleSeconds int64            `json:"maxStaleSeconds"`
	Stats           statsSnapshot    `json:"stats"`
	Tor             *providerStatus  `json:"tor,omitempty"`
	Providers       []providerStatus `json:"providers"`
}

// serveStatus serves an operational snapshot of the loaded lists. It is only
// reachable when Config.StatusPath is set, and it bypasses the block logic.
//
// The default representation is JSON. Prometheus (and compatible scrapers)
// receive the text exposition format instead, selected through the Accept
// header or an explicit ?format=prometheus query parameter.
func (m *Middleware) serveStatus(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		rw.Header().Set("Allow", "GET, HEAD")
		http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	now := time.Now()
	if wantsPrometheus(req) {
		m.serveMetrics(rw, now)
		return
	}

	status := statusResponse{
		Middleware:      m.name,
		Version:         Version,
		FailClosed:      m.opts.failClosed,
		BlockStatusCode: m.opts.statusCode,
		MaxStaleSeconds: int64(m.opts.maxStale.Seconds()),
		Stats:           m.stats.snapshot(),
		Providers:       make([]providerStatus, 0, len(m.providers)),
	}

	for _, provider := range m.providers {
		status.Providers = append(status.Providers, provider.status(now, m.opts.maxStale))
	}
	if m.tor != nil {
		torStatus := m.tor.status(now, m.opts.maxStale)
		status.Tor = &torStatus
	}

	body, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	rw.Header().Set("Cache-Control", "no-store")
	rw.WriteHeader(http.StatusOK)
	_, _ = rw.Write(body)
	_, _ = rw.Write([]byte("\n"))
}

// wantsPrometheus reports whether the request should be answered with the
// Prometheus text exposition format. An explicit "format" query parameter
// wins; otherwise a text/plain or OpenMetrics Accept header selects metrics.
// Everything else, including browsers and curl's default */*, gets JSON.
func wantsPrometheus(req *http.Request) bool {
	switch strings.ToLower(strings.TrimSpace(req.URL.Query().Get("format"))) {
	case "prometheus", "openmetrics", "text":
		return true
	case "json":
		return false
	}

	accept := strings.ToLower(req.Header.Get("Accept"))
	if accept == "" || strings.Contains(accept, "application/json") {
		return false
	}

	return strings.Contains(accept, "application/openmetrics-text") ||
		strings.Contains(accept, "text/plain")
}

// serveMetrics writes the Prometheus text exposition format (version 0.0.4).
func (m *Middleware) serveMetrics(rw http.ResponseWriter, now time.Time) {
	var b strings.Builder

	s := m.stats.snapshot()

	writeMetricHeader(&b, "threatdb_requests_total", "counter",
		"Total number of requests evaluated by the middleware.")
	fmt.Fprintf(&b, "threatdb_requests_total %d\n\n", s.Requests)

	writeMetricHeader(&b, "threatdb_allowed_total", "counter",
		"Total number of requests allowed through to the next handler.")
	fmt.Fprintf(&b, "threatdb_allowed_total %d\n\n", s.Allowed)

	writeMetricHeader(&b, "threatdb_allowed_tor_total", "counter",
		"Total number of requests allowed because the client is a Tor exit node.")
	fmt.Fprintf(&b, "threatdb_allowed_tor_total %d\n\n", s.AllowedTor)

	writeMetricHeader(&b, "threatdb_rejected_total", "counter",
		"Total number of requests rejected by the middleware, by reason.")
	fmt.Fprintf(&b, "threatdb_rejected_total{reason=\"match\"} %d\n", s.RejectedMatches)
	fmt.Fprintf(&b, "threatdb_rejected_total{reason=\"unavailable\"} %d\n\n", s.RejectedUnavailable)

	writeMetricHeader(&b, "threatdb_no_client_ip_total", "counter",
		"Total number of requests forwarded without a usable client IP address.")
	fmt.Fprintf(&b, "threatdb_no_client_ip_total %d\n\n", s.NoClientIP)

	writeMetricHeader(&b, "threatdb_info", "gauge",
		"Information about this middleware instance.")
	fmt.Fprintf(&b, "threatdb_info{middleware=\"%s\",version=\"%s\"} 1\n\n",
		escapeLabel(m.name), escapeLabel(Version))

	statuses := make([]providerStatus, 0, len(m.providers))
	for _, provider := range m.providers {
		statuses = append(statuses, provider.status(now, m.opts.maxStale))
	}

	writeProviderFamily(&b, statuses, "threatdb_provider_loaded", "gauge",
		"Whether the provider has a list loaded (1) or not (0).",
		func(status providerStatus) float64 { return boolValue(status.Loaded) })

	writeProviderFamily(&b, statuses, "threatdb_provider_stale", "gauge",
		"Whether the provider's list is stale (1) or not (0).",
		func(status providerStatus) float64 { return boolValue(status.Stale) })

	writeProviderFamily(&b, statuses, "threatdb_provider_fetching", "gauge",
		"Whether a refresh is currently in progress (1) or not (0).",
		func(status providerStatus) float64 { return boolValue(status.Fetching) })

	writeProviderFamily(&b, statuses, "threatdb_provider_entries", "gauge",
		"Number of addresses and networks loaded for the provider.",
		func(status providerStatus) float64 { return float64(status.Entries) })

	writeProviderFamily(&b, statuses, "threatdb_provider_matches_total", "counter",
		"Total number of requests rejected because the client matched this provider.",
		func(status providerStatus) float64 { return float64(status.Matches) })

	writeProviderFamily(&b, statuses, "threatdb_provider_last_success_timestamp_seconds", "gauge",
		"Unix timestamp of the last successful refresh, or 0 if never loaded.",
		func(status providerStatus) float64 { return float64(status.lastSuccessUnix) })

	writeProviderFamily(&b, statuses, "threatdb_provider_last_attempt_timestamp_seconds", "gauge",
		"Unix timestamp of the last refresh attempt, or 0 if never attempted.",
		func(status providerStatus) float64 { return float64(status.lastAttemptUnix) })

	writeProviderFamily(&b, statuses, "threatdb_provider_last_refresh_duration_seconds", "gauge",
		"Duration of the most recent refresh attempt in seconds.",
		func(status providerStatus) float64 { return status.LastRefreshSeconds })

	writeMetricHeader(&b, "threatdb_provider_refresh_total", "counter",
		"Total number of provider refresh attempts, by result.")
	for _, status := range statuses {
		fmt.Fprintf(&b, "threatdb_provider_refresh_total{provider=\"%s\",result=\"success\"} %d\n",
			escapeLabel(status.Key), status.RefreshSuccesses)
	}
	for _, status := range statuses {
		fmt.Fprintf(&b, "threatdb_provider_refresh_total{provider=\"%s\",result=\"failure\"} %d\n",
			escapeLabel(status.Key), status.RefreshFailures)
	}
	b.WriteString("\n")

	if m.tor != nil {
		tor := m.tor.status(now, m.opts.maxStale)

		writeMetricHeader(&b, "threatdb_tor_loaded", "gauge",
			"Whether the Tor exit-node list has been loaded (1) or not (0).")
		fmt.Fprintf(&b, "threatdb_tor_loaded %g\n\n", boolValue(tor.Loaded))

		writeMetricHeader(&b, "threatdb_tor_stale", "gauge",
			"Whether the Tor exit-node list is stale (1) or not (0).")
		fmt.Fprintf(&b, "threatdb_tor_stale %g\n\n", boolValue(tor.Stale))

		writeMetricHeader(&b, "threatdb_tor_entries", "gauge",
			"Number of Tor exit addresses currently loaded.")
		fmt.Fprintf(&b, "threatdb_tor_entries %d\n\n", tor.Entries)

		writeMetricHeader(&b, "threatdb_tor_last_success_timestamp_seconds", "gauge",
			"Unix timestamp of the last successful Tor list refresh, or 0 if never loaded.")
		fmt.Fprintf(&b, "threatdb_tor_last_success_timestamp_seconds %d\n\n", tor.lastSuccessUnix)

		writeMetricHeader(&b, "threatdb_tor_refresh_total", "counter",
			"Total number of Tor exit-node list refresh attempts, by result.")
		fmt.Fprintf(&b, "threatdb_tor_refresh_total{result=\"success\"} %d\n", tor.RefreshSuccesses)
		fmt.Fprintf(&b, "threatdb_tor_refresh_total{result=\"failure\"} %d\n\n", tor.RefreshFailures)
	}

	rw.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	rw.Header().Set("Cache-Control", "no-store")
	rw.WriteHeader(http.StatusOK)
	_, _ = rw.Write([]byte(b.String()))
}

func writeMetricHeader(b *strings.Builder, name, kind, help string) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, kind)
}

func writeProviderFamily(b *strings.Builder, statuses []providerStatus, name, kind, help string, value func(providerStatus) float64) {
	writeMetricHeader(b, name, kind, help)
	for _, status := range statuses {
		fmt.Fprintf(b, "%s{provider=\"%s\"} %s\n",
			name, escapeLabel(status.Key), strconv.FormatFloat(value(status), 'f', -1, 64))
	}
	b.WriteString("\n")
}

func boolValue(value bool) float64 {
	if value {
		return 1
	}
	return 0
}

// escapeLabel applies the escaping required inside a Prometheus label value.
func escapeLabel(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, "\"", `\"`)
	value = strings.ReplaceAll(value, "\n", `\n`)
	return value
}
