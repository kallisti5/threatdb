package threatdb

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func TestProvidersSharedAcrossMiddlewareInstances(t *testing.T) {
	list := &listHandler{body: "203.0.113.5\n"}
	server := newListServer(t, list)

	first := newTestMiddleware(t, testConfig(server.URL), nil)
	second := newTestMiddleware(t, testConfig(server.URL), nil)

	if first.providers[0].cache != second.providers[0].cache {
		t.Fatal("identical provider configurations should share one cache")
	}
	if got := list.requestCount(); got != 1 {
		t.Fatalf("downloads = %d, want 1 shared download", got)
	}

	// Match counters belong to the middleware instance, not the shared cache.
	if recorder := performRequest(first, "203.0.113.5:443", nil); recorder.Code != http.StatusForbidden {
		t.Fatalf("first middleware status = %d, want 403", recorder.Code)
	}
	if recorder := performRequest(second, "203.0.113.5:443", nil); recorder.Code != http.StatusForbidden {
		t.Fatalf("second middleware status = %d, want 403", recorder.Code)
	}

	firstStatus := first.providers[0].status(time.Now(), time.Hour)
	secondStatus := second.providers[0].status(time.Now(), time.Hour)
	if firstStatus.Matches != 1 || secondStatus.Matches != 1 {
		t.Errorf("matches = %d/%d, want 1/1 (independent per instance)", firstStatus.Matches, secondStatus.Matches)
	}

	// A refresh through either instance updates the list seen by both.
	list.setBody("203.0.113.6\n")
	if ok := first.providers[0].refresh(context.Background()); !ok {
		t.Fatal("shared refresh failed")
	}
	if _, loaded := second.providers[0].snapshot(); !loaded {
		t.Fatal("second instance lost the shared list")
	}
	if recorder := performRequest(second, "203.0.113.6:443", nil); recorder.Code != http.StatusForbidden {
		t.Errorf("second instance should see the refreshed list, got %d", recorder.Code)
	}
	if recorder := performRequest(second, "203.0.113.5:443", nil); recorder.Code != http.StatusOK {
		t.Errorf("removed address should be allowed after shared refresh, got %d", recorder.Code)
	}
	if got := list.requestCount(); got != 2 {
		t.Errorf("downloads = %d, want 2 after one explicit refresh", got)
	}
}

func TestProvidersNotSharedWhenSettingsDiffer(t *testing.T) {
	list := &listHandler{body: "203.0.113.5\n"}
	server := newListServer(t, list)

	config := testConfig(server.URL)
	config.Providers["test"] = Provider{URL: server.URL, Name: "TestList", MinEntries: 1}
	first := newTestMiddleware(t, config, nil)

	// MinEntries changes the acceptance rules, so this must not reuse the
	// first cache even though the URL is identical.
	second := newTestMiddleware(t, testConfig(server.URL), nil)

	if first.providers[0].cache == second.providers[0].cache {
		t.Fatal("providers with different settings must not share a cache")
	}
	if got := list.requestCount(); got != 2 {
		t.Errorf("downloads = %d, want 2 for distinct settings", got)
	}
}

func TestSharedProviderStatusUsesLocalNames(t *testing.T) {
	list := &listHandler{body: "203.0.113.5\n"}
	server := newListServer(t, list)

	first := newTestMiddleware(t, testConfig(server.URL), nil)

	secondConfig := testConfig(server.URL)
	secondConfig.Providers = map[string]Provider{
		"other": {URL: server.URL, Name: "OtherName"},
	}
	second := newTestMiddleware(t, secondConfig, nil)

	if first.providers[0].cache != second.providers[0].cache {
		t.Fatal("providers with identical list settings should share a cache")
	}

	status := second.providers[0].status(time.Now(), time.Hour)
	if status.Key != "other" || status.Name != "OtherName" {
		t.Errorf("status key/name = %q/%q, want other/OtherName", status.Key, status.Name)
	}
	if !status.Loaded || status.Entries != 1 {
		t.Errorf("status = %+v, want one shared loaded entry", status)
	}
}
