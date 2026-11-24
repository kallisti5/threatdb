package threatdb

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestParseTorExitAddresses(t *testing.T) {
	body := []byte("\ufeffExitNode 1A2B3C\r\n" +
		"Published 2026-01-01 00:00:00\r\n" +
		"LastStatus 2026-01-02 00:00:00\r\n" +
		"ExitAddress 203.0.113.10 2026-01-02 00:00:00\r\n" +
		"ExitAddress 2001:db8::5 2026-01-02 00:00:00\r\n" +
		"ExitAddress not-an-ip 2026-01-02 00:00:00\r\n" +
		"# ExitAddress 198.51.100.1 2026-01-02 00:00:00\r\n" +
		"ExitAddress 203.0.113.10 2026-01-03 00:00:00\r\n")

	set, valid, invalid, err := parseTorExitAddresses(body)
	if err != nil {
		t.Fatalf("parseTorExitAddresses returned error: %v", err)
	}
	if valid != 3 {
		t.Errorf("valid = %d, want 3", valid)
	}
	if invalid != 1 {
		t.Errorf("invalid = %d, want 1", invalid)
	}
	if set.size != 2 {
		t.Errorf("set size = %d, want 2 unique addresses", set.size)
	}
	for _, value := range []string{"203.0.113.10", "2001:db8::5"} {
		if !set.contains(parseIP(value)) {
			t.Errorf("%s should be allowed", value)
		}
	}
	if set.contains(parseIP("198.51.100.1")) {
		t.Error("commented ExitAddress should be ignored")
	}
}

func TestAllowTor(t *testing.T) {
	torList := &listHandler{body: "ExitNode ABC\n" +
		"ExitAddress 203.0.113.5 2026-01-02 00:00:00\n" +
		"ExitAddress 198.51.100.9 2026-01-02 00:00:00\n"}
	torServer := newListServer(t, torList)

	oldURL := torExitAddressesURL
	torExitAddressesURL = torServer.URL
	t.Cleanup(func() {
		torExitAddressesURL = oldURL
	})

	blockList := &listHandler{body: "203.0.113.5\n198.51.100.9\n192.0.2.50\n"}
	blockServer := newListServer(t, blockList)

	config := testConfig(blockServer.URL)
	config.AllowTor = true
	config.StatusPath = "/_threatdb/status"
	middleware := newTestMiddleware(t, config, nil)

	if middleware.tor == nil {
		t.Fatal("tor cache should be enabled")
	}
	if middleware.tor.interval != 60*time.Minute {
		t.Errorf("tor interval = %s, want 60m", middleware.tor.interval)
	}
	if got := torList.requestCount(); got != 1 {
		t.Fatalf("tor downloads = %d, want 1", got)
	}

	// Tor exit nodes are allowed even when present on a block list.
	if recorder := performRequest(middleware, "203.0.113.5:443", nil); recorder.Code != http.StatusOK {
		t.Errorf("Tor exit node status = %d, want 200", recorder.Code)
	}
	if recorder := performRequest(middleware, "198.51.100.9:443", nil); recorder.Code != http.StatusOK {
		t.Errorf("second Tor exit node status = %d, want 200", recorder.Code)
	}
	if recorder := performRequest(middleware, "192.0.2.50:443", nil); recorder.Code != http.StatusForbidden {
		t.Errorf("non-Tor listed address status = %d, want 403", recorder.Code)
	}

	// A second middleware instance shares the Tor cache.
	secondConfig := testConfig(blockServer.URL)
	secondConfig.AllowTor = true
	second := newTestMiddleware(t, secondConfig, nil)
	if second.tor != middleware.tor {
		t.Error("Tor cache should be shared across middleware instances")
	}
	if got := torList.requestCount(); got != 1 {
		t.Errorf("tor downloads = %d, want 1 after second instance", got)
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/_threatdb/status", nil)
	recorder := httptest.NewRecorder()
	middleware.ServeHTTP(recorder, req)

	var status statusResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &status); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if status.Tor == nil || !status.Tor.Loaded || status.Tor.Entries != 2 {
		t.Errorf("tor status = %+v, want 2 loaded entries", status.Tor)
	}
	if status.Stats.AllowedTor != 2 || status.Stats.Allowed != 2 {
		t.Errorf("stats = %+v, want 2 Tor-allowed requests", status.Stats)
	}

	req = httptest.NewRequest(http.MethodGet, "http://example.com/_threatdb/status?format=prometheus", nil)
	recorder = httptest.NewRecorder()
	middleware.ServeHTTP(recorder, req)
	for _, want := range []string{
		"threatdb_allowed_tor_total 2",
		"threatdb_tor_loaded 1",
		"threatdb_tor_entries 2",
		"threatdb_tor_refresh_total{result=\"success\"} 1",
	} {
		if !strings.Contains(recorder.Body.String(), want+"\n") {
			t.Errorf("metrics missing %q:\n%s", want, recorder.Body.String())
		}
	}
}

func TestAllowTorDisabledByDefault(t *testing.T) {
	list := &listHandler{body: "203.0.113.5\n"}
	server := newListServer(t, list)
	middleware := newTestMiddleware(t, testConfig(server.URL), nil)
	if middleware.tor != nil {
		t.Error("tor cache should be disabled by default")
	}
}
