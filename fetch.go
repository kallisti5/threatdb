package threatdb

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

const (
	retryMinDelay = 10 * time.Second
	retryMaxDelay = 5 * time.Minute
)

// providerCache owns the downloaded copy of a single threat list and keeps it
// up to date in the background.
//
// The counter fields are accessed with sync/atomic and must stay at the top of
// the struct so they remain 64-bit aligned on 32-bit platforms.
type providerCache struct {
	refreshSuccesses int64
	refreshFailures  int64

	id     string
	ctx    context.Context
	cancel context.CancelFunc
	ready  chan struct{}
	refs   int // guarded by sharedProvidersMu

	key          string
	name         string
	url          string
	headers      map[string]string
	interval     time.Duration
	timeout      time.Duration
	minEntries   int
	maxListBytes int
	userAgent    string
	logPrefix    string
	client       *http.Client

	mu           sync.RWMutex
	set          *ipSet
	entries      int
	lastAttempt  time.Time
	lastSuccess  time.Time
	lastErr      string
	etag         string
	lastModified string
	fetching     bool
	lastDuration time.Duration
}

// snapshot returns the current list and whether one has ever been loaded.
func (p *providerCache) snapshot() (*ipSet, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return p.set, p.set != nil
}

// run performs the first download, publishes readiness to every middleware
// instance waiting on this cache, and then starts the refresh loop.
func (p *providerCache) run() {
	p.refresh(p.ctx)
	close(p.ready)
	p.loop(p.ctx)
}

// providerView is one middleware instance's handle to a shared provider cache.
// The cache owns the parsed list and refresh state; the view adds the local
// display name and per-instance match counter.
type providerView struct {
	matches int64

	cache *providerCache
	key   string
	name  string
}

func (v *providerView) snapshot() (*ipSet, bool) {
	return v.cache.snapshot()
}

func (v *providerView) refresh(ctx context.Context) bool {
	return v.cache.refresh(ctx)
}

func (v *providerView) status(now time.Time, maxStale time.Duration) providerStatus {
	status := v.cache.status(now, maxStale)
	status.Key = v.key
	status.Name = v.name
	status.Matches = atomic.LoadInt64(&v.matches)
	return status
}

// loop refreshes a list periodically, with exponential backoff while the
// provider is unavailable.
func (p *providerCache) loop(ctx context.Context) {
	failures := 0
	wait := p.interval

	if _, loaded := p.snapshot(); !loaded {
		failures = 1
		wait = p.retryDelay(failures)
	}

	for {
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			logf(p.logPrefix, "provider %q: refresh loop stopped (context canceled)", p.name)
			return
		case <-timer.C:
		}

		if p.refresh(ctx) {
			failures = 0
			wait = p.interval
			continue
		}

		if ctx.Err() != nil {
			return
		}

		failures++
		wait = p.retryDelay(failures)
	}
}

// retryDelay returns the delay before the next attempt after n consecutive
// failures, bounded by the regular refresh interval when that is shorter.
func (p *providerCache) retryDelay(failures int) time.Duration {
	minDelay := retryMinDelay
	maxDelay := retryMaxDelay

	if p.interval > 0 && p.interval < minDelay {
		minDelay = p.interval
	}
	if p.interval > 0 && p.interval < maxDelay {
		maxDelay = p.interval
	}
	if maxDelay < minDelay {
		maxDelay = minDelay
	}

	delay := minDelay
	for i := 1; i < failures; i++ {
		if delay >= maxDelay {
			return maxDelay
		}
		delay *= 2
	}
	if delay > maxDelay {
		delay = maxDelay
	}

	return delay
}

// refresh performs one conditional download. It reports whether the list is
// available after the attempt.
func (p *providerCache) refresh(ctx context.Context) bool {
	p.mu.Lock()
	if p.fetching {
		p.mu.Unlock()
		return false
	}
	p.fetching = true
	etag := p.etag
	lastModified := p.lastModified
	p.lastAttempt = time.Now()
	p.mu.Unlock()

	started := time.Now()
	entries, notModified, err := p.fetch(ctx, etag, lastModified)
	elapsed := time.Since(started).Round(time.Millisecond)

	p.mu.Lock()
	p.fetching = false
	p.lastDuration = elapsed
	if err != nil {
		p.lastErr = err.Error()
	} else {
		p.lastErr = ""
	}
	p.mu.Unlock()

	if err != nil {
		atomic.AddInt64(&p.refreshFailures, 1)
		if ctx.Err() == nil {
			logerrf(p.logPrefix, "provider %q: refresh failed: %v", p.name, err)
		}
		return false
	}

	atomic.AddInt64(&p.refreshSuccesses, 1)

	if notModified {
		logf(p.logPrefix, "provider %q: list unchanged (HTTP 304, %s)", p.name, elapsed)
	} else {
		logf(p.logPrefix, "provider %q: loaded %d entries in %s", p.name, entries, elapsed)
	}

	return true
}

// fetch downloads and parses the list. On success it replaces the cached copy
// atomically under the lock.
func (p *providerCache) fetch(ctx context.Context, etag, lastModified string) (int, bool, error) {
	reqCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, p.url, nil)
	if err != nil {
		return 0, false, fmt.Errorf("build request: %w", err)
	}

	req.Header.Set("User-Agent", p.userAgent)
	req.Header.Set("Accept", "text/plain, */*")
	for key, value := range p.headers {
		req.Header.Set(key, value)
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	if lastModified != "" {
		req.Header.Set("If-Modified-Since", lastModified)
	}

	response, err := p.client.Do(req)
	if err != nil {
		return 0, false, err
	}
	defer func() {
		_ = response.Body.Close()
	}()

	if response.StatusCode == http.StatusNotModified {
		p.mu.Lock()
		loaded := p.set != nil
		entries := p.entries
		if loaded {
			p.lastSuccess = time.Now()
		}
		p.mu.Unlock()

		if !loaded {
			return 0, false, fmt.Errorf("received HTTP 304 before any list was loaded")
		}
		return entries, true, nil
	}

	if response.StatusCode != http.StatusOK {
		return 0, false, fmt.Errorf("unexpected HTTP status %q", response.Status)
	}

	limit := int64(p.maxListBytes)
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return 0, false, fmt.Errorf("read response: %w", err)
	}
	if int64(len(body)) > limit {
		return 0, false, fmt.Errorf("response is larger than maxListBytes (%d)", p.maxListBytes)
	}

	set, valid, invalid, err := parseList(body)
	if err != nil {
		return 0, false, fmt.Errorf("parse response: %w", err)
	}
	if valid == 0 {
		return 0, false, fmt.Errorf("no IP addresses found in response (%d unparseable lines)", invalid)
	}
	if valid < p.minEntries {
		return 0, false, fmt.Errorf("only %d entries parsed, minimum is %d", valid, p.minEntries)
	}

	p.mu.Lock()
	p.set = set
	p.entries = set.size
	p.lastSuccess = time.Now()
	p.etag = response.Header.Get("ETag")
	p.lastModified = response.Header.Get("Last-Modified")
	p.lastErr = ""
	p.mu.Unlock()

	if invalid > 0 {
		logf(p.logPrefix, "provider %q: skipped %d unparseable lines", p.name, invalid)
	}

	return set.size, false, nil
}

// providerStatus is the status endpoint representation of a provider.
type providerStatus struct {
	Key                string  `json:"key"`
	Name               string  `json:"name"`
	URL                string  `json:"url"`
	Entries            int     `json:"entries"`
	Loaded             bool    `json:"loaded"`
	Stale              bool    `json:"stale"`
	Fetching           bool    `json:"fetching"`
	Matches            int64   `json:"matches"`
	RefreshSuccesses   int64   `json:"refreshSuccesses"`
	RefreshFailures    int64   `json:"refreshFailures"`
	LastRefreshSeconds float64 `json:"lastRefreshSeconds,omitempty"`
	LastAttempt        string  `json:"lastAttempt,omitempty"`
	LastSuccess        string  `json:"lastSuccess,omitempty"`
	AgeSeconds         int64   `json:"ageSeconds"`
	LastError          string  `json:"lastError,omitempty"`

	lastAttemptUnix int64
	lastSuccessUnix int64
}

func (p *providerCache) status(now time.Time, maxStale time.Duration) providerStatus {
	p.mu.RLock()
	defer p.mu.RUnlock()

	status := providerStatus{
		Key:              p.key,
		Name:             p.name,
		URL:              redactedURL(p.url),
		Entries:          p.entries,
		Loaded:           p.set != nil,
		Fetching:         p.fetching,
		RefreshSuccesses: atomic.LoadInt64(&p.refreshSuccesses),
		RefreshFailures:  atomic.LoadInt64(&p.refreshFailures),
		LastError:        p.lastErr,
	}

	if p.lastDuration > 0 {
		status.LastRefreshSeconds = p.lastDuration.Seconds()
	}
	if !p.lastAttempt.IsZero() {
		status.LastAttempt = p.lastAttempt.Format(time.RFC3339)
		status.lastAttemptUnix = p.lastAttempt.Unix()
	}
	if !p.lastSuccess.IsZero() {
		status.LastSuccess = p.lastSuccess.Format(time.RFC3339)
		status.lastSuccessUnix = p.lastSuccess.Unix()
		status.AgeSeconds = int64(now.Sub(p.lastSuccess).Seconds())
	}

	status.Stale = !status.Loaded || (maxStale > 0 && now.Sub(p.lastSuccess) > maxStale)

	return status
}

func newProviderCache(key, name string, settings providerShareSettings, logPrefix string) *providerCache {
	return &providerCache{
		key:          key,
		name:         name,
		url:          settings.url,
		headers:      settings.headers,
		interval:     settings.interval,
		timeout:      settings.timeout,
		minEntries:   settings.minEntries,
		maxListBytes: settings.maxListBytes,
		userAgent:    settings.userAgent,
		logPrefix:    logPrefix,
		client:       newHTTPClient(),
	}
}

// logf writes an informational message. Traefik maps plugin stdout to its
// debug log level.
func logf(prefix, format string, args ...interface{}) {
	writeLog(os.Stdout, prefix, format, args...)
}

// logerrf writes an error message. Traefik maps plugin stderr to its error
// log level.
func logerrf(prefix, format string, args ...interface{}) {
	writeLog(os.Stderr, prefix, format, args...)
}

func writeLog(output *os.File, prefix, format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	_, _ = output.WriteString(time.Now().Format(time.RFC3339) + " " + prefix + ": " + message + "\n")
}
