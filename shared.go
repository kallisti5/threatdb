package threatdb

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// providerShareGrace is how long a shared provider is kept after the last
// middleware instance using it is torn down. Traefik cancels the old plugin
// context immediately before creating the replacement middleware on a dynamic
// configuration reload; the grace period lets the replacement attach to the
// existing list instead of downloading and parsing it again.
const providerShareGrace = 5 * time.Second

// providerShareSettings is the part of a provider configuration that affects
// the downloaded list. Middleware instances with identical settings share one
// parsed copy; display names and middleware prefixes do not affect the list and
// are therefore not part of the identity.
type providerShareSettings struct {
	kind         string
	url          string
	headers      map[string]string
	interval     time.Duration
	timeout      time.Duration
	minEntries   int
	maxListBytes int
	userAgent    string
}

// providerPlan is a validated provider entry waiting to be attached to a
// shared cache.
type providerPlan struct {
	key      string
	name     string
	settings providerShareSettings
}

// key returns a deterministic identity for the settings. Values are
// length-prefixed so field boundaries cannot be confused, and headers are
// sorted because map iteration order is random.
func (s providerShareSettings) key() string {
	var b strings.Builder

	writeShareField(&b, s.kind)
	writeShareField(&b, s.url)
	writeShareField(&b, s.interval.String())
	writeShareField(&b, s.timeout.String())
	writeShareField(&b, fmt.Sprintf("%d/%d", s.minEntries, s.maxListBytes))
	writeShareField(&b, s.userAgent)

	keys := make([]string, 0, len(s.headers))
	for key := range s.headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	writeShareField(&b, fmt.Sprintf("%d", len(keys)))
	for _, key := range keys {
		writeShareField(&b, key)
		writeShareField(&b, s.headers[key])
	}

	return b.String()
}

func writeShareField(b *strings.Builder, value string) {
	fmt.Fprintf(b, "%d:", len(value))
	b.WriteString(value)
}

var (
	sharedProvidersMu sync.Mutex
	sharedProviders   = make(map[string]*providerCache)
)

// acquireSharedProvider returns the shared cache for id, creating it from
// candidate when this is the first user. refs is protected by sharedProvidersMu.
func acquireSharedProvider(id string, candidate *providerCache) *providerCache {
	sharedProvidersMu.Lock()

	if existing := sharedProviders[id]; existing != nil {
		existing.refs++
		sharedProvidersMu.Unlock()
		return existing
	}

	provider := candidate
	provider.id = id
	provider.ctx, provider.cancel = context.WithCancel(context.Background())
	provider.ready = make(chan struct{})
	provider.refs = 1
	sharedProviders[id] = provider

	sharedProvidersMu.Unlock()

	// run performs the first download and closes ready once it has finished.
	go provider.run()

	return provider
}

// releaseSharedProvider drops one reference. When the last middleware instance
// goes away the refresh loop is stopped and the parsed list becomes garbage.
func releaseSharedProvider(provider *providerCache) {
	sharedProvidersMu.Lock()
	defer sharedProvidersMu.Unlock()

	if provider.refs > 0 {
		provider.refs--
	}
	if provider.refs > 0 {
		return
	}

	// The entry may already have been replaced if this is a duplicate release.
	if sharedProviders[provider.id] == provider {
		delete(sharedProviders, provider.id)
	}
	if provider.cancel != nil {
		provider.cancel()
	}
}

// releaseSharedProviders waits for the middleware's context to be cancelled,
// then releases its references after a short grace period.
func (m *Middleware) releaseSharedProviders(ctx context.Context) {
	<-ctx.Done()
	time.Sleep(providerShareGrace)

	for _, provider := range m.providers {
		releaseSharedProvider(provider.cache)
	}
	if m.tor != nil {
		releaseSharedProvider(m.tor)
	}
}
