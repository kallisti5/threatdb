// Package threatdb implements a Traefik middleware plugin that blocks
// requests from client IP addresses that appear on one or more remote
// threat lists.
//
// Lists are downloaded and parsed at startup, kept in memory, and refreshed
// periodically. Requests are only ever matched against the in-memory copy,
// so upstream providers are never contacted on the request path.
//
// The plugin only depends on the Go standard library, which keeps it easy to
// run under Yaegi (the interpreter used by Traefik plugins) and avoids the
// need to vendor third-party packages.
package threatdb

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Version is the plugin version, also reported by the optional status endpoint.
const Version = "0.1.0"

const (
	defaultRefreshInterval    = 15 * time.Minute
	defaultRequestTimeout     = 15 * time.Second
	defaultMaxStale           = 24 * time.Hour
	defaultMaxListBytes       = 16 << 20 // 16 MiB
	defaultMessage            = "Your IP is present on the {provider} threat list. Please try again later"
	defaultUnavailableMessage = "The {provider} threat list is temporarily unavailable. Please try again later"
	defaultContentType        = "text/plain; charset=utf-8"
	defaultForwardedHeader    = "X-Forwarded-For"
	defaultUserAgent          = "traefik-threatdb/" + Version
)

// Config is the plugin configuration.
//
// Every field is optional; the zero value behaves like CreateConfig.
// Durations are Go duration strings such as "30s", "15m" or "24h".
type Config struct {
	// Providers declares the threat lists to download. The map key is a
	// stable identifier used in logs; Provider.Name is the human readable
	// name used in the block message.
	Providers map[string]Provider `json:"providers,omitempty"`

	// RefreshInterval controls how often every list is refreshed.
	// Defaults to 15m. Individual providers may override it.
	RefreshInterval string `json:"refreshInterval,omitempty"`

	// RequestTimeout bounds a single HTTP download (connect + body).
	// Defaults to 15s. Note that the first download happens during plugin
	// construction, so this also bounds how long Traefik can be delayed at
	// startup by an unresponsive provider.
	RequestTimeout string `json:"requestTimeout,omitempty"`

	// MaxStale is the age after which a list is reported as stale by the
	// optional status endpoint. Stale lists keep being used for matching.
	// Set to "0" to disable staleness reporting. Defaults to 24h.
	MaxStale string `json:"maxStale,omitempty"`

	// MaxListBytes rejects list downloads larger than this many bytes.
	// Defaults to 16 MiB.
	MaxListBytes int `json:"maxListBytes,omitempty"`

	// StatusCode is the HTTP status returned to blocked clients.
	// Defaults to 403.
	StatusCode int `json:"statusCode,omitempty"`

	// Message is the body returned to blocked clients. The placeholders
	// {provider} and {ip} are replaced with the matching list name(s) and
	// the client address.
	Message string `json:"message,omitempty"`

	// UnavailableMessage is the body returned when FailClosed is enabled and
	// no list has been loaded yet. Supports the same placeholders as Message.
	UnavailableMessage string `json:"unavailableMessage,omitempty"`

	// ContentType is the Content-Type sent with block responses.
	// Defaults to "text/plain; charset=utf-8".
	ContentType string `json:"contentType,omitempty"`

	// AllowList contains IP addresses or CIDR ranges that are never blocked.
	AllowList []string `json:"allowList,omitempty"`

	// ExcludePrivateIPs lets loopback, private, link-local, multicast and
	// CGNAT addresses bypass the lists. Useful when Traefik sits behind a
	// load balancer on a private network. Defaults to false.
	ExcludePrivateIPs bool `json:"excludePrivateIPs,omitempty"`

	// TrustedProxyDepth enables client IP extraction from a forwarded header.
	// 0 (the default) always uses the TCP peer address (RemoteAddr).
	//
	// When set to N, the plugin trusts the last N entries of the header
	// (i.e. N proxies in front of Traefik, including the direct peer) and
	// takes the address N hops from the right. Only enable this when a proxy
	// you control appends/overwrites the header; otherwise clients can spoof
	// their address and evade the lists.
	TrustedProxyDepth int `json:"trustedProxyDepth,omitempty"`

	// ForwardedForHeader is the header used when TrustedProxyDepth > 0.
	// Defaults to X-Forwarded-For. Set it to e.g. X-Real-IP when your proxy
	// only sets that header.
	ForwardedForHeader string `json:"forwardedForHeader,omitempty"`

	// FailClosed makes the middleware reject requests with 503 while a list
	// has never been loaded successfully. The default (false) fails open and
	// lets requests through, which favours availability.
	FailClosed bool `json:"failClosed,omitempty"`

	// StatusPath, when set (e.g. "/threatdb/status"), serves a JSON snapshot
	// of the loaded lists at that exact path, bypassing the block logic.
	// Leave empty to disable. Make sure the path is not used by your
	// application, and consider restricting it at the router level.
	StatusPath string `json:"statusPath,omitempty"`

	// LogBlockedRequests logs every blocked request to the plugin log.
	// Disabled by default to avoid log flooding under attack.
	LogBlockedRequests bool `json:"logBlockedRequests,omitempty"`

	// UserAgent is sent with list download requests.
	UserAgent string `json:"userAgent,omitempty"`
}

// Provider describes a single remote threat list.
type Provider struct {
	// URL is the list location. It must be an absolute http or https URL.
	URL string `json:"url,omitempty"`

	// Name is the display name used in block messages, e.g. "Threat.Live".
	// Defaults to the provider's map key.
	Name string `json:"name,omitempty"`

	// RefreshInterval overrides Config.RefreshInterval for this provider.
	// Set to "0" to download the list once at startup and never refresh it.
	RefreshInterval string `json:"refreshInterval,omitempty"`

	// Headers adds HTTP headers to the download request, e.g. an API token.
	Headers map[string]string `json:"headers,omitempty"`

	// MinEntries rejects a download with fewer parsed entries than this.
	// It protects against truncated downloads and error pages replacing a
	// good list. Defaults to 0 (only an empty list is rejected).
	MinEntries int `json:"minEntries,omitempty"`

	// MaxListBytes overrides Config.MaxListBytes for this provider.
	MaxListBytes int `json:"maxListBytes,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		Providers:          make(map[string]Provider),
		RefreshInterval:    "15m",
		RequestTimeout:     "15s",
		MaxStale:           "24h",
		MaxListBytes:       defaultMaxListBytes,
		StatusCode:         http.StatusForbidden,
		Message:            defaultMessage,
		UnavailableMessage: defaultUnavailableMessage,
		ContentType:        defaultContentType,
		ForwardedForHeader: defaultForwardedHeader,
		UserAgent:          defaultUserAgent,
	}
}

// options holds the parsed, validated configuration.
type options struct {
	refreshInterval    time.Duration
	requestTimeout     time.Duration
	maxStale           time.Duration
	maxListBytes       int
	statusCode         int
	message            string
	unavailableMessage string
	contentType        string
	excludePrivate     bool
	proxyDepth         int
	forwardedHeader    string
	failClosed         bool
	statusPath         string
	logBlocked         bool
	userAgent          string
}

// Middleware is the threat list blocking middleware.
type Middleware struct {
	next      http.Handler
	name      string
	opts      options
	allow     *ipSet
	providers []*providerCache
	prefix    string
}

// New creates the plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if next == nil {
		return nil, fmt.Errorf("next handler is required")
	}
	if config == nil {
		config = CreateConfig()
	}
	if ctx == nil {
		ctx = context.Background()
	}

	opts, allow, err := parseOptions(config)
	if err != nil {
		return nil, err
	}

	prefix := "threatdb"
	if name != "" {
		prefix = "threatdb[" + name + "]"
	}

	providers, err := buildProviders(config, opts, prefix)
	if err != nil {
		return nil, err
	}

	m := &Middleware{
		next:      next,
		name:      name,
		opts:      *opts,
		allow:     allow,
		providers: providers,
		prefix:    prefix,
	}

	// Load every list once before returning so that the middleware is ready
	// to make decisions as soon as Traefik starts serving traffic.
	m.initialLoad(ctx)

	for _, p := range providers {
		if p.interval <= 0 {
			continue
		}
		go p.loop(ctx)
	}

	return m, nil
}

// ServeHTTP blocks matching client IPs and forwards everything else.
func (m *Middleware) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if m.opts.statusPath != "" && req.URL.Path == m.opts.statusPath {
		m.serveStatus(rw, req)
		return
	}

	ip := clientIP(req, m.opts.forwardedHeader, m.opts.proxyDepth)
	if ip == nil {
		// Without an address we cannot make a decision; fail open.
		m.next.ServeHTTP(rw, req)
		return
	}

	if m.allow.contains(ip) || (m.opts.excludePrivate && isInternalIP(ip)) {
		m.next.ServeHTTP(rw, req)
		return
	}

	var matches []string
	var missing []string

	for _, p := range m.providers {
		set, loaded := p.snapshot()
		if !loaded {
			if m.opts.failClosed {
				missing = append(missing, p.name)
			}
			continue
		}
		if set.contains(ip) {
			matches = append(matches, p.name)
		}
	}

	if len(matches) > 0 {
		provider := strings.Join(matches, ", ")
		if m.opts.logBlocked {
			logf(m.prefix, "blocked %s (matched %s) on %s %s", ip, provider, req.Method, req.URL.Path)
		}
		m.deny(rw, m.opts.statusCode, provider, ip, m.opts.message)
		return
	}

	if len(missing) > 0 {
		provider := strings.Join(missing, ", ")
		if m.opts.logBlocked {
			logf(m.prefix, "blocked %s (no list loaded: %s) on %s %s", ip, provider, req.Method, req.URL.Path)
		}
		m.deny(rw, http.StatusServiceUnavailable, provider, ip, m.opts.unavailableMessage)
		return
	}

	m.next.ServeHTTP(rw, req)
}

// deny writes a block response.
func (m *Middleware) deny(rw http.ResponseWriter, status int, provider string, ip net.IP, message string) {
	body := strings.ReplaceAll(message, "{provider}", provider)
	body = strings.ReplaceAll(body, "{ip}", ip.String())

	rw.Header().Set("Content-Type", m.opts.contentType)
	rw.Header().Set("Cache-Control", "no-store")
	if provider != "" {
		rw.Header().Set("X-Threat-List", provider)
	}
	rw.WriteHeader(status)
	_, _ = rw.Write([]byte(body + "\n"))
}

// parseOptions validates the public configuration and applies defaults.
func parseOptions(config *Config) (*options, *ipSet, error) {
	refresh, err := parsePositiveDuration("refreshInterval", config.RefreshInterval, defaultRefreshInterval)
	if err != nil {
		return nil, nil, err
	}

	requestTimeout, err := parsePositiveDuration("requestTimeout", config.RequestTimeout, defaultRequestTimeout)
	if err != nil {
		return nil, nil, err
	}

	maxStale, err := parseNonNegativeDuration("maxStale", config.MaxStale, defaultMaxStale)
	if err != nil {
		return nil, nil, err
	}

	maxListBytes := config.MaxListBytes
	if maxListBytes <= 0 {
		maxListBytes = defaultMaxListBytes
	}

	statusCode := config.StatusCode
	if statusCode == 0 {
		statusCode = http.StatusForbidden
	}
	if statusCode < 200 || statusCode > 599 {
		return nil, nil, fmt.Errorf("invalid statusCode %d: must be between 200 and 599", statusCode)
	}

	if config.TrustedProxyDepth < 0 {
		return nil, nil, fmt.Errorf("invalid trustedProxyDepth %d: must not be negative", config.TrustedProxyDepth)
	}

	statusPath := strings.TrimSpace(config.StatusPath)
	if statusPath != "" {
		if !strings.HasPrefix(statusPath, "/") {
			return nil, nil, fmt.Errorf("invalid statusPath %q: must start with /", statusPath)
		}
		if strings.ContainsAny(statusPath, "?#") {
			return nil, nil, fmt.Errorf("invalid statusPath %q: must not contain a query or fragment", statusPath)
		}
	}

	allow := newIPSet()
	for _, entry := range config.AllowList {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if !addEntry(allow, entry) {
			return nil, nil, fmt.Errorf("invalid allowList entry %q", entry)
		}
	}

	opts := &options{
		refreshInterval:    refresh,
		requestTimeout:     requestTimeout,
		maxStale:           maxStale,
		maxListBytes:       maxListBytes,
		statusCode:         statusCode,
		message:            stringOrDefault(config.Message, defaultMessage),
		unavailableMessage: stringOrDefault(config.UnavailableMessage, defaultUnavailableMessage),
		contentType:        stringOrDefault(config.ContentType, defaultContentType),
		excludePrivate:     config.ExcludePrivateIPs,
		proxyDepth:         config.TrustedProxyDepth,
		forwardedHeader:    stringOrDefault(config.ForwardedForHeader, defaultForwardedHeader),
		failClosed:         config.FailClosed,
		statusPath:         statusPath,
		logBlocked:         config.LogBlockedRequests,
		userAgent:          stringOrDefault(config.UserAgent, defaultUserAgent),
	}

	return opts, allow, nil
}

// buildProviders validates provider entries and creates their caches.
func buildProviders(config *Config, opts *options, prefix string) ([]*providerCache, error) {
	if len(config.Providers) == 0 {
		return nil, fmt.Errorf("at least one entry in providers is required")
	}

	keys := make([]string, 0, len(config.Providers))
	for key := range config.Providers {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	providers := make([]*providerCache, 0, len(keys))
	names := make(map[string]string, len(keys))

	for _, key := range keys {
		provider := config.Providers[key]

		rawURL := strings.TrimSpace(provider.URL)
		if rawURL == "" {
			return nil, fmt.Errorf("provider %q: url is required", key)
		}
		parsed, err := url.Parse(rawURL)
		if err != nil {
			return nil, fmt.Errorf("provider %q: invalid url %q: %w", key, provider.URL, err)
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return nil, fmt.Errorf("provider %q: invalid url %q: scheme must be http or https", key, provider.URL)
		}
		if parsed.Host == "" {
			return nil, fmt.Errorf("provider %q: invalid url %q: missing host", key, provider.URL)
		}

		name := strings.TrimSpace(provider.Name)
		if name == "" {
			name = key
		}
		if other, exists := names[name]; exists {
			return nil, fmt.Errorf("providers %q and %q share the display name %q", other, key, name)
		}
		names[name] = key

		interval := opts.refreshInterval
		if strings.TrimSpace(provider.RefreshInterval) != "" {
			interval, err = parseNonNegativeDuration("provider "+key+" refreshInterval", provider.RefreshInterval, opts.refreshInterval)
			if err != nil {
				return nil, err
			}
		}

		if provider.MinEntries < 0 {
			return nil, fmt.Errorf("provider %q: minEntries must not be negative", key)
		}

		maxListBytes := opts.maxListBytes
		if provider.MaxListBytes > 0 {
			maxListBytes = provider.MaxListBytes
		}

		providers = append(providers, &providerCache{
			key:          key,
			name:         name,
			url:          rawURL,
			headers:      copyHeaders(provider.Headers),
			interval:     interval,
			timeout:      opts.requestTimeout,
			minEntries:   provider.MinEntries,
			maxListBytes: maxListBytes,
			userAgent:    opts.userAgent,
			logPrefix:    prefix,
			client:       &http.Client{},
		})
	}

	return providers, nil
}

func copyHeaders(headers map[string]string) map[string]string {
	if len(headers) == 0 {
		return nil
	}
	copied := make(map[string]string, len(headers))
	for key, value := range headers {
		copied[key] = value
	}
	return copied
}

func stringOrDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func parsePositiveDuration(field, value string, fallback time.Duration) (time.Duration, error) {
	parsed, err := parseDurationValue(field, value, fallback)
	if err != nil {
		return 0, err
	}
	if parsed <= 0 {
		return 0, fmt.Errorf("invalid %s %q: must be greater than zero", field, value)
	}
	return parsed, nil
}

func parseNonNegativeDuration(field, value string, fallback time.Duration) (time.Duration, error) {
	parsed, err := parseDurationValue(field, value, fallback)
	if err != nil {
		return 0, err
	}
	if parsed < 0 {
		return 0, fmt.Errorf("invalid %s %q: must not be negative", field, value)
	}
	return parsed, nil
}

func parseDurationValue(field, value string, fallback time.Duration) (time.Duration, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("invalid %s %q: %w", field, value, err)
	}
	return parsed, nil
}
