package threatdb

import (
	"context"
	"testing"
	"time"
)

func TestZeroRefreshIntervalFetchesOnce(t *testing.T) {
	list := &listHandler{body: "203.0.113.5\n"}
	server := newListServer(t, list)

	config := testConfig(server.URL)
	config.Providers["test"] = Provider{
		URL:             server.URL,
		Name:            "TestList",
		RefreshInterval: "0",
	}
	newTestMiddleware(t, config, nil)

	if got := list.requestCount(); got != 1 {
		t.Fatalf("downloads = %d, want 1", got)
	}

	// A zero interval means fetch once and stop. Without the guard in run()
	// this turns into a tight loop of zero-delay timers.
	time.Sleep(100 * time.Millisecond)
	if got := list.requestCount(); got != 1 {
		t.Errorf("downloads = %d after waiting, want 1", got)
	}
}

func TestIdenticalBodySkipsReparse(t *testing.T) {
	list := &listHandler{body: "203.0.113.5\n"}
	server := newListServer(t, list)

	middleware := newTestMiddleware(t, testConfig(server.URL), nil)
	provider := middleware.providers[0]

	before, _ := provider.snapshot()
	if ok := provider.refresh(context.Background()); !ok {
		t.Fatal("refresh failed")
	}
	after, _ := provider.snapshot()

	if before != after {
		t.Error("identical response body should keep the existing parsed set")
	}
	if got := list.requestCount(); got != 2 {
		t.Errorf("downloads = %d, want 2", got)
	}

	list.setBody("203.0.113.6\n")
	if ok := provider.refresh(context.Background()); !ok {
		t.Fatal("refresh after change failed")
	}
	changed, loaded := provider.snapshot()
	if !loaded || changed == before {
		t.Error("changed response body should produce a new parsed set")
	}
	if !changed.contains(parseIP("203.0.113.6")) {
		t.Error("new set should contain the changed address")
	}
}
