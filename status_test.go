package threatdb

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStatusMetricsEndpoint(t *testing.T) {
	list := &listHandler{body: "203.0.113.5\n"}
	server := newListServer(t, list)

	config := testConfig(server.URL)
	config.StatusPath = "/_threatdb/status"
	middleware := newTestMiddleware(t, config, nil)

	// One blocked request, one allowed request, and one without a usable IP.
	if recorder := performRequest(middleware, "203.0.113.5:443", nil); recorder.Code != http.StatusForbidden {
		t.Fatalf("blocked request status = %d, want 403", recorder.Code)
	}
	if recorder := performRequest(middleware, "198.51.100.7:443", nil); recorder.Code != http.StatusOK {
		t.Fatalf("allowed request status = %d, want 200", recorder.Code)
	}
	if recorder := performRequest(middleware, "", nil); recorder.Code != http.StatusOK {
		t.Fatalf("missing IP request status = %d, want 200", recorder.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/_threatdb/status", nil)
	req.Header.Set("Accept", "text/plain; version=0.0.4; charset=utf-8")
	recorder := httptest.NewRecorder()
	middleware.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("metrics status = %d, want 200", recorder.Code)
	}
	if got := recorder.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain", got)
	}

	body := recorder.Body.String()
	for _, want := range []string{
		"# TYPE threatdb_requests_total counter",
		"threatdb_requests_total 3",
		"threatdb_allowed_total 1",
		"threatdb_rejected_total{reason=\"match\"} 1",
		"threatdb_rejected_total{reason=\"unavailable\"} 0",
		"threatdb_no_client_ip_total 1",
		"threatdb_provider_loaded{provider=\"test\"} 1",
		"threatdb_provider_entries{provider=\"test\"} 1",
		"threatdb_provider_matches_total{provider=\"test\"} 1",
		"threatdb_provider_refresh_total{provider=\"test\",result=\"success\"} 1",
		"threatdb_provider_refresh_total{provider=\"test\",result=\"failure\"} 0",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics body missing %q:\n%s", want, body)
		}
	}

	// The status endpoint itself must not be counted as a handled request.
	if strings.Contains(body, "threatdb_requests_total 4") {
		t.Errorf("status request was counted in threatdb_requests_total:\n%s", body)
	}

	// The JSON representation exposes the same counters.
	jsonReq := httptest.NewRequest(http.MethodGet, "http://example.com/_threatdb/status?format=json", nil)
	jsonReq.Header.Set("Accept", "text/plain")
	jsonRecorder := httptest.NewRecorder()
	middleware.ServeHTTP(jsonRecorder, jsonReq)

	var status statusResponse
	if err := json.Unmarshal(jsonRecorder.Body.Bytes(), &status); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if status.Stats.Requests != 3 || status.Stats.Allowed != 1 ||
		status.Stats.RejectedMatches != 1 || status.Stats.NoClientIP != 1 {
		t.Errorf("stats = %+v", status.Stats)
	}
	if len(status.Providers) != 1 || status.Providers[0].Matches != 1 {
		t.Errorf("provider status = %+v", status.Providers)
	}
}

func TestWantsPrometheus(t *testing.T) {
	tests := []struct {
		name   string
		accept string
		query  string
		want   bool
	}{
		{name: "default", want: false},
		{name: "browser", accept: "text/html,application/xhtml+xml,*/*;q=0.8", want: false},
		{name: "prometheus text", accept: "text/plain; version=0.0.4; charset=utf-8", want: true},
		{name: "openmetrics", accept: "application/openmetrics-text; version=1.0.0", want: true},
		{name: "json wins", accept: "application/json, text/plain", want: false},
		{name: "query prometheus", query: "?format=prometheus", want: true},
		{name: "query json", accept: "text/plain", query: "?format=json", want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://example.com/_threatdb/status"+test.query, nil)
			if test.accept != "" {
				req.Header.Set("Accept", test.accept)
			}
			if got := wantsPrometheus(req); got != test.want {
				t.Errorf("wantsPrometheus() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestStatusMetricsQueryFormat(t *testing.T) {
	list := &listHandler{body: "203.0.113.5\n"}
	server := newListServer(t, list)

	config := testConfig(server.URL)
	config.StatusPath = "/_threatdb/status"
	middleware := newTestMiddleware(t, config, nil)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/_threatdb/status?format=prometheus", nil)
	recorder := httptest.NewRecorder()
	middleware.ServeHTTP(recorder, req)

	if got := recorder.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain with ?format=prometheus", got)
	}
	if !strings.Contains(recorder.Body.String(), "# TYPE threatdb_requests_total counter") {
		t.Errorf("body does not look like Prometheus metrics:\n%s", recorder.Body.String())
	}
}

func TestFailClosedMetrics(t *testing.T) {
	list := &listHandler{body: "unavailable", status: http.StatusInternalServerError}
	server := newListServer(t, list)

	config := testConfig(server.URL)
	config.StatusPath = "/_threatdb/status"
	config.FailClosed = true
	middleware := newTestMiddleware(t, config, nil)

	if recorder := performRequest(middleware, "203.0.113.5:443", nil); recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", recorder.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/_threatdb/status?format=prometheus", nil)
	recorder := httptest.NewRecorder()
	middleware.ServeHTTP(recorder, req)

	body := recorder.Body.String()
	if !strings.Contains(body, "threatdb_rejected_total{reason=\"unavailable\"} 1") {
		t.Errorf("metrics body missing unavailable rejection:\n%s", body)
	}
	if !strings.Contains(body, "threatdb_provider_loaded{provider=\"test\"} 0") {
		t.Errorf("metrics body should report the provider as unloaded:\n%s", body)
	}
	if !strings.Contains(body, "threatdb_provider_refresh_total{provider=\"test\",result=\"failure\"} 1") {
		t.Errorf("metrics body missing failed refresh:\n%s", body)
	}
}
