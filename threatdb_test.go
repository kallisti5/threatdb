package threatdb

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// listHandler is a mutable, concurrency safe threat list server for tests.
type listHandler struct {
	mu              sync.Mutex
	body            string
	status          int
	etag            string
	requests        int
	conditionalSeen bool
	requireHeader   string
	requireValue    string
}

func (l *listHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	l.mu.Lock()
	l.requests++

	if l.requireHeader != "" && req.Header.Get(l.requireHeader) != l.requireValue {
		l.mu.Unlock()
		http.Error(rw, "unauthorized", http.StatusUnauthorized)
		return
	}

	if l.etag != "" && req.Header.Get("If-None-Match") == l.etag {
		l.conditionalSeen = true
		l.mu.Unlock()
		rw.WriteHeader(http.StatusNotModified)
		return
	}

	body := l.body
	status := l.status
	etag := l.etag
	l.mu.Unlock()

	if etag != "" {
		rw.Header().Set("ETag", etag)
	}
	if status != 0 {
		rw.WriteHeader(status)
	}
	_, _ = rw.Write([]byte(body))
}

func (l *listHandler) setBody(body string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.body = body
}

func (l *listHandler) setStatus(status int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.status = status
}

func (l *listHandler) requestCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.requests
}

func newListServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server
}

func testConfig(url string) *Config {
	config := CreateConfig()
	config.Providers["test"] = Provider{URL: url, Name: "TestList"}
	config.RequestTimeout = "5s"
	return config
}

func nextHandler() http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte("allowed"))
	})
}

func newTestMiddleware(t *testing.T, config *Config, next http.Handler) *Middleware {
	t.Helper()

	if next == nil {
		next = nextHandler()
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	handler, err := New(ctx, next, config, "test-middleware")
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	middleware, ok := handler.(*Middleware)
	if !ok {
		t.Fatalf("New returned %T, want *Middleware", handler)
	}

	return middleware
}

func performRequest(handler http.Handler, remote string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/hello", nil)
	req.RemoteAddr = remote
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	return recorder
}

func waitFor(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition was not met before the timeout")
}

func TestBlocksMatchingIP(t *testing.T) {
	list := &listHandler{body: "203.0.113.5\n198.51.100.0/24\n"}
	server := newListServer(t, list)
	middleware := newTestMiddleware(t, testConfig(server.URL), nil)

	recorder := performRequest(middleware, "203.0.113.5:443", nil)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusForbidden)
	}

	want := "Your IP is present on the TestList threat list. Please try again later"
	if body := strings.TrimSpace(recorder.Body.String()); body != want {
		t.Errorf("body = %q, want %q", body, want)
	}
	if got := recorder.Header().Get("X-Threat-List"); got != "TestList" {
		t.Errorf("X-Threat-List = %q, want TestList", got)
	}
	if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	if got := recorder.Header().Get("Content-Type"); got != defaultContentType {
		t.Errorf("Content-Type = %q, want %q", got, defaultContentType)
	}

	recorder = performRequest(middleware, "198.51.100.99:443", nil)
	if recorder.Code != http.StatusForbidden {
		t.Errorf("CIDR match status = %d, want %d", recorder.Code, http.StatusForbidden)
	}

	recorder = performRequest(middleware, "192.0.2.10:443", nil)
	if recorder.Code != http.StatusOK || recorder.Body.String() != "allowed" {
		t.Errorf("unlisted IP got status %d body %q, want 200/allowed", recorder.Code, recorder.Body.String())
	}
}

func TestBlocksIPv6(t *testing.T) {
	list := &listHandler{body: "2001:db8::1\n2001:db8:beef::/48\n"}
	server := newListServer(t, list)
	middleware := newTestMiddleware(t, testConfig(server.URL), nil)

	if recorder := performRequest(middleware, "[2001:db8::1]:443", nil); recorder.Code != http.StatusForbidden {
		t.Errorf("exact IPv6 status = %d, want 403", recorder.Code)
	}
	if recorder := performRequest(middleware, "[2001:db8:beef::42]:443", nil); recorder.Code != http.StatusForbidden {
		t.Errorf("IPv6 CIDR status = %d, want 403", recorder.Code)
	}
	if recorder := performRequest(middleware, "[2001:db8:cafe::1]:443", nil); recorder.Code != http.StatusOK {
		t.Errorf("unlisted IPv6 status = %d, want 200", recorder.Code)
	}
}

func TestAllowList(t *testing.T) {
	list := &listHandler{body: "203.0.113.5\n"}
	server := newListServer(t, list)

	config := testConfig(server.URL)
	config.AllowList = []string{"203.0.113.0/24"}
	middleware := newTestMiddleware(t, config, nil)

	recorder := performRequest(middleware, "203.0.113.5:443", nil)
	if recorder.Code != http.StatusOK {
		t.Errorf("allow listed IP status = %d, want 200", recorder.Code)
	}
}

func TestExcludePrivateIPs(t *testing.T) {
	list := &listHandler{body: "10.1.2.3\n100.64.0.9\n203.0.113.5\n"}
	server := newListServer(t, list)

	excluded := testConfig(server.URL)
	excluded.ExcludePrivateIPs = true
	middleware := newTestMiddleware(t, excluded, nil)

	for _, remote := range []string{"10.1.2.3:443", "100.64.0.9:443"} {
		if recorder := performRequest(middleware, remote, nil); recorder.Code != http.StatusOK {
			t.Errorf("%s: status = %d, want 200 with excludePrivateIPs", remote, recorder.Code)
		}
	}

	if recorder := performRequest(middleware, "203.0.113.5:443", nil); recorder.Code != http.StatusForbidden {
		t.Errorf("public IP status = %d, want 403 with excludePrivateIPs", recorder.Code)
	}

	included := testConfig(server.URL)
	includeMiddleware := newTestMiddleware(t, included, nil)
	if recorder := performRequest(includeMiddleware, "10.1.2.3:443", nil); recorder.Code != http.StatusForbidden {
		t.Errorf("private IP status = %d, want 403 without excludePrivateIPs", recorder.Code)
	}
}

func TestTrustedProxyDepth(t *testing.T) {
	list := &listHandler{body: "203.0.113.5\n198.51.100.7\n"}
	server := newListServer(t, list)

	config := testConfig(server.URL)
	config.TrustedProxyDepth = 1
	middleware := newTestMiddleware(t, config, nil)

	recorder := performRequest(middleware, "10.0.0.9:5000", map[string]string{
		"X-Forwarded-For": "203.0.113.5",
	})
	if recorder.Code != http.StatusForbidden {
		t.Errorf("forwarded IP status = %d, want 403", recorder.Code)
	}

	recorder = performRequest(middleware, "10.0.0.9:5000", map[string]string{
		"X-Forwarded-For": "192.0.2.50",
	})
	if recorder.Code != http.StatusOK {
		t.Errorf("unlisted forwarded IP status = %d, want 200", recorder.Code)
	}

	untrustedConfig := testConfig(server.URL)
	untrusted := newTestMiddleware(t, untrustedConfig, nil)
	if recorder := performRequest(untrusted, "10.0.0.9:5000", map[string]string{
		"X-Forwarded-For": "203.0.113.5",
	}); recorder.Code != http.StatusOK {
		t.Errorf("header should be ignored without trustedProxyDepth, got %d", recorder.Code)
	}

	deepConfig := testConfig(server.URL)
	deepConfig.TrustedProxyDepth = 2
	deep := newTestMiddleware(t, deepConfig, nil)
	if recorder := performRequest(deep, "10.0.0.9:5000", map[string]string{
		"X-Forwarded-For": "198.51.100.7, 203.0.113.5",
	}); recorder.Code != http.StatusForbidden {
		t.Errorf("depth 2 status = %d, want 403", recorder.Code)
	}
}

func TestMultipleProvidersReportAllMatches(t *testing.T) {
	first := &listHandler{body: "203.0.113.5\n"}
	second := &listHandler{body: "203.0.113.5\n"}
	firstServer := newListServer(t, first)
	secondServer := newListServer(t, second)

	config := CreateConfig()
	config.Providers["a"] = Provider{URL: firstServer.URL, Name: "Alpha"}
	config.Providers["b"] = Provider{URL: secondServer.URL, Name: "Beta"}
	middleware := newTestMiddleware(t, config, nil)

	recorder := performRequest(middleware, "203.0.113.5:443", nil)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", recorder.Code)
	}
	if got := recorder.Header().Get("X-Threat-List"); got != "Alpha, Beta" {
		t.Errorf("X-Threat-List = %q, want %q", got, "Alpha, Beta")
	}
	if body := recorder.Body.String(); !strings.Contains(body, "Alpha, Beta") {
		t.Errorf("body = %q, want both providers", body)
	}
}

func TestCustomMessageAndStatus(t *testing.T) {
	list := &listHandler{body: "203.0.113.5\n"}
	server := newListServer(t, list)

	config := testConfig(server.URL)
	config.StatusCode = http.StatusTooManyRequests
	config.Message = "Blocked {ip} via {provider}"
	config.ContentType = "text/plain; charset=us-ascii"
	middleware := newTestMiddleware(t, config, nil)

	recorder := performRequest(middleware, "203.0.113.5:443", nil)
	if recorder.Code != http.StatusTooManyRequests {
		t.Errorf("status = %d, want 429", recorder.Code)
	}
	if body := strings.TrimSpace(recorder.Body.String()); body != "Blocked 203.0.113.5 via TestList" {
		t.Errorf("body = %q", body)
	}
	if got := recorder.Header().Get("Content-Type"); got != "text/plain; charset=us-ascii" {
		t.Errorf("Content-Type = %q", got)
	}
}

func TestFailClosedWhenListMissing(t *testing.T) {
	list := &listHandler{status: http.StatusInternalServerError, body: "nope"}
	server := newListServer(t, list)

	closed := testConfig(server.URL)
	closed.FailClosed = true
	middleware := newTestMiddleware(t, closed, nil)

	recorder := performRequest(middleware, "203.0.113.5:443", nil)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", recorder.Code)
	}
	if body := recorder.Body.String(); !strings.Contains(body, "temporarily unavailable") {
		t.Errorf("body = %q, want unavailable message", body)
	}

	open := testConfig(server.URL)
	openMiddleware := newTestMiddleware(t, open, nil)
	if recorder := performRequest(openMiddleware, "203.0.113.5:443", nil); recorder.Code != http.StatusOK {
		t.Errorf("fail-open status = %d, want 200", recorder.Code)
	}
}

func TestKeepsCachedListOnFailure(t *testing.T) {
	list := &listHandler{body: "203.0.113.5\n"}
	server := newListServer(t, list)
	middleware := newTestMiddleware(t, testConfig(server.URL), nil)

	provider := middleware.providers[0]
	if _, loaded := provider.snapshot(); !loaded {
		t.Fatal("list should be loaded after startup")
	}

	list.setStatus(http.StatusInternalServerError)
	if ok := provider.refresh(context.Background()); ok {
		t.Fatal("refresh should fail when the provider errors")
	}

	set, loaded := provider.snapshot()
	if !loaded || !set.contains(parseIP("203.0.113.5")) {
		t.Fatal("cached list should be retained after a failed refresh")
	}

	status := provider.status(time.Now(), time.Hour)
	if status.LastError == "" {
		t.Error("status should report the last error")
	}
	if !status.Loaded || status.Entries != 1 {
		t.Errorf("status = %+v, want one loaded entry", status)
	}

	if recorder := performRequest(middleware, "203.0.113.5:443", nil); recorder.Code != http.StatusForbidden {
		t.Errorf("cached list should still block, got %d", recorder.Code)
	}
}

func TestConditionalRequest(t *testing.T) {
	list := &listHandler{body: "203.0.113.5\n", etag: `"v1"`}
	server := newListServer(t, list)
	middleware := newTestMiddleware(t, testConfig(server.URL), nil)

	provider := middleware.providers[0]
	if ok := provider.refresh(context.Background()); !ok {
		t.Fatal("conditional refresh should succeed")
	}

	list.mu.Lock()
	seen := list.conditionalSeen
	requests := list.requests
	list.mu.Unlock()
	if !seen {
		t.Error("provider should send If-None-Match")
	}
	if requests != 2 {
		t.Errorf("requests = %d, want 2", requests)
	}

	status := provider.status(time.Now(), time.Hour)
	if !status.Loaded || status.Entries != 1 {
		t.Errorf("status = %+v, want one loaded entry", status)
	}
	if status.LastError != "" {
		t.Errorf("lastError = %q, want empty", status.LastError)
	}
}

func TestRefreshPicksUpChanges(t *testing.T) {
	list := &listHandler{body: "203.0.113.5\n"}
	server := newListServer(t, list)

	config := testConfig(server.URL)
	config.RefreshInterval = "25ms"
	middleware := newTestMiddleware(t, config, nil)

	provider := middleware.providers[0]
	if recorder := performRequest(middleware, "203.0.113.5:443", nil); recorder.Code != http.StatusForbidden {
		t.Fatalf("initial list should block, got %d", recorder.Code)
	}

	list.setBody("203.0.113.6\n")
	waitFor(t, 3*time.Second, func() bool {
		set, loaded := provider.snapshot()
		return loaded && set.contains(parseIP("203.0.113.6"))
	})

	if recorder := performRequest(middleware, "203.0.113.5:443", nil); recorder.Code != http.StatusOK {
		t.Errorf("removed IP should be allowed, got %d", recorder.Code)
	}
	if recorder := performRequest(middleware, "203.0.113.6:443", nil); recorder.Code != http.StatusForbidden {
		t.Errorf("new IP should be blocked, got %d", recorder.Code)
	}
}

func TestMinEntriesRejectsSmallList(t *testing.T) {
	list := &listHandler{body: "203.0.113.5\n198.51.100.7\n"}
	server := newListServer(t, list)

	config := testConfig(server.URL)
	config.Providers["test"] = Provider{URL: server.URL, Name: "TestList", MinEntries: 5}
	middleware := newTestMiddleware(t, config, nil)

	provider := middleware.providers[0]
	if _, loaded := provider.snapshot(); loaded {
		t.Fatal("small list should have been rejected")
	}

	status := provider.status(time.Now(), time.Hour)
	if !strings.Contains(status.LastError, "minimum is 5") {
		t.Errorf("lastError = %q, want minimum complaint", status.LastError)
	}
}

func TestMaxListBytes(t *testing.T) {
	list := &listHandler{body: "203.0.113.5\n198.51.100.7\n192.0.2.1\n"}
	server := newListServer(t, list)

	config := testConfig(server.URL)
	config.MaxListBytes = 10
	middleware := newTestMiddleware(t, config, nil)

	status := middleware.providers[0].status(time.Now(), time.Hour)
	if !strings.Contains(status.LastError, "larger than maxListBytes") {
		t.Errorf("lastError = %q, want maxListBytes complaint", status.LastError)
	}
}

func TestEmptyListIsRejected(t *testing.T) {
	list := &listHandler{body: "<html>maintenance</html>\n"}
	server := newListServer(t, list)
	middleware := newTestMiddleware(t, testConfig(server.URL), nil)

	status := middleware.providers[0].status(time.Now(), time.Hour)
	if !strings.Contains(status.LastError, "no IP addresses") {
		t.Errorf("lastError = %q, want no addresses complaint", status.LastError)
	}
}

func TestProviderHeaders(t *testing.T) {
	list := &listHandler{
		body:          "203.0.113.5\n",
		requireHeader: "Authorization",
		requireValue:  "Bearer secret",
	}
	server := newListServer(t, list)

	config := testConfig(server.URL)
	config.Providers["test"] = Provider{
		URL:     server.URL,
		Name:    "TestList",
		Headers: map[string]string{"Authorization": "Bearer secret"},
	}
	middleware := newTestMiddleware(t, config, nil)

	if recorder := performRequest(middleware, "203.0.113.5:443", nil); recorder.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", recorder.Code)
	}
}

func TestStatusEndpoint(t *testing.T) {
	list := &listHandler{body: "203.0.113.5\n198.51.100.0/24\n"}
	server := newListServer(t, list)

	config := testConfig(server.URL)
	config.StatusPath = "/_threatdb/status"
	middleware := newTestMiddleware(t, config, nil)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/_threatdb/status", nil)
	recorder := httptest.NewRecorder()
	middleware.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	if got := recorder.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Errorf("Content-Type = %q, want JSON", got)
	}

	var status statusResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &status); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if status.Version != Version {
		t.Errorf("version = %q, want %q", status.Version, Version)
	}
	if len(status.Providers) != 1 {
		t.Fatalf("providers = %d, want 1", len(status.Providers))
	}
	if status.Providers[0].Name != "TestList" || !status.Providers[0].Loaded || status.Providers[0].Entries != 2 {
		t.Errorf("provider status = %+v", status.Providers[0])
	}
	if status.Providers[0].Key != "test" {
		t.Errorf("provider key = %q, want test", status.Providers[0].Key)
	}
	if status.MaxStaleSeconds != int64((24 * time.Hour).Seconds()) {
		t.Errorf("maxStaleSeconds = %d", status.MaxStaleSeconds)
	}

	post := httptest.NewRequest(http.MethodPost, "http://example.com/_threatdb/status", nil)
	postRecorder := httptest.NewRecorder()
	middleware.ServeHTTP(postRecorder, post)
	if postRecorder.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST status = %d, want 405", postRecorder.Code)
	}
}

func TestInvalidConfig(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{
			name: "no providers",
			mutate: func(config *Config) {
				config.Providers = map[string]Provider{}
			},
		},
		{
			name: "missing url",
			mutate: func(config *Config) {
				config.Providers["test"] = Provider{Name: "Test"}
			},
		},
		{
			name: "unsupported scheme",
			mutate: func(config *Config) {
				config.Providers["test"] = Provider{URL: "ftp://example.com/list"}
			},
		},
		{
			name: "duplicate display names",
			mutate: func(config *Config) {
				config.Providers["test"] = Provider{URL: "https://example.com/a", Name: "Same"}
				config.Providers["other"] = Provider{URL: "https://example.com/b", Name: "Same"}
			},
		},
		{
			name: "bad refresh interval",
			mutate: func(config *Config) {
				config.RefreshInterval = "soon"
			},
		},
		{
			name: "bad provider refresh interval",
			mutate: func(config *Config) {
				config.Providers["test"] = Provider{URL: "https://example.com/a", RefreshInterval: "later"}
			},
		},
		{
			name: "bad status code",
			mutate: func(config *Config) {
				config.StatusCode = 99
			},
		},
		{
			name: "negative proxy depth",
			mutate: func(config *Config) {
				config.TrustedProxyDepth = -1
			},
		},
		{
			name: "relative status path",
			mutate: func(config *Config) {
				config.StatusPath = "status"
			},
		},
		{
			name: "invalid allow list",
			mutate: func(config *Config) {
				config.AllowList = []string{"not-an-ip"}
			},
		},
		{
			name: "negative min entries",
			mutate: func(config *Config) {
				config.Providers["test"] = Provider{URL: "https://example.com/a", MinEntries: -1}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := testConfig("https://example.com/list")
			test.mutate(config)

			if _, err := New(context.Background(), nextHandler(), config, "invalid"); err == nil {
				t.Error("New should have returned an error")
			}
		})
	}
}

func TestConcurrentRequestsAndRefresh(t *testing.T) {
	list := &listHandler{body: "203.0.113.5\n"}
	server := newListServer(t, list)
	middleware := newTestMiddleware(t, testConfig(server.URL), nil)

	provider := middleware.providers[0]

	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				recorder := performRequest(middleware, "203.0.113.5:443", nil)
				if recorder.Code != http.StatusForbidden {
					t.Errorf("status = %d, want 403", recorder.Code)
					return
				}
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			provider.refresh(context.Background())
		}
	}()

	wg.Wait()
}

// TestRefreshLoopsCoverAllProviders is a regression test for a Yaegi-specific
// bug: starting goroutines with `go provider.loop(ctx)` inside a range loop
// makes every goroutine use the last provider. Under Yaegi only the final
// provider would ever refresh, so running the suite with `yaegi test` catches
// a regression even though compiled Go handles the original code correctly.
func TestRefreshLoopsCoverAllProviders(t *testing.T) {
	first := &listHandler{body: "203.0.113.5\n"}
	second := &listHandler{body: "198.51.100.7\n"}
	firstServer := newListServer(t, first)
	secondServer := newListServer(t, second)

	config := CreateConfig()
	config.Providers["a"] = Provider{URL: firstServer.URL, Name: "First"}
	config.Providers["z"] = Provider{URL: secondServer.URL, Name: "Second"}
	config.RefreshInterval = "25ms"
	middleware := newTestMiddleware(t, config, nil)

	if len(middleware.providers) != 2 {
		t.Fatalf("providers = %d, want 2", len(middleware.providers))
	}

	first.setBody("203.0.113.6\n")
	second.setBody("198.51.100.8\n")

	waitFor(t, 3*time.Second, func() bool {
		one, _ := middleware.providers[0].snapshot()
		two, _ := middleware.providers[1].snapshot()
		return one != nil && one.contains(parseIP("203.0.113.6")) &&
			two != nil && two.contains(parseIP("198.51.100.8"))
	})
}

func TestProviderHeadersNotForwardedAcrossHostRedirect(t *testing.T) {
	var received http.Header

	target := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		received = req.Header.Clone()
		_, _ = rw.Write([]byte("203.0.113.5\n"))
	}))
	t.Cleanup(target.Close)

	targetURL, err := url.Parse(target.URL)
	if err != nil {
		t.Fatal(err)
	}

	redirector := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		// 127.0.0.1 -> localhost is a cross-host redirect for the client.
		http.Redirect(rw, req, "http://localhost:"+targetURL.Port()+"/list.txt", http.StatusFound)
	}))
	t.Cleanup(redirector.Close)

	config := testConfig(redirector.URL)
	config.Providers["test"] = Provider{
		URL:     redirector.URL,
		Name:    "TestList",
		Headers: map[string]string{"X-Api-Key": "topsecret"},
	}
	newTestMiddleware(t, config, nil)

	if received == nil {
		t.Fatal("redirect target was not called")
	}
	if got := received.Get("X-Api-Key"); got != "" {
		t.Errorf("X-Api-Key leaked to redirect target: %q", got)
	}
}

func TestStatusRedactsProviderCredentials(t *testing.T) {
	list := &listHandler{body: "203.0.113.5\n"}
	server := newListServer(t, list)

	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	config := testConfig("http://alice:supersecret@" + parsed.Host + "/list.txt")
	config.StatusPath = "/_threatdb/status"
	middleware := newTestMiddleware(t, config, nil)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/_threatdb/status", nil)
	recorder := httptest.NewRecorder()
	middleware.ServeHTTP(recorder, req)

	if strings.Contains(recorder.Body.String(), "supersecret") {
		t.Errorf("status endpoint leaked the provider password: %s", recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), parsed.Host) {
		t.Errorf("status endpoint should still show the provider host: %s", recorder.Body.String())
	}
}
