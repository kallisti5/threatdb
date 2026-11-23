package threatdb

import (
	"encoding/json"
	"net/http"
	"time"
)

// statusResponse is the JSON document served on Config.StatusPath.
type statusResponse struct {
	Middleware      string           `json:"middleware,omitempty"`
	Version         string           `json:"version"`
	FailClosed      bool             `json:"failClosed"`
	BlockStatusCode int              `json:"blockStatusCode"`
	MaxStaleSeconds int64            `json:"maxStaleSeconds"`
	Providers       []providerStatus `json:"providers"`
}

// serveStatus serves an operational snapshot of the loaded lists. It is only
// reachable when Config.StatusPath is set, and it bypasses the block logic.
func (m *Middleware) serveStatus(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		rw.Header().Set("Allow", "GET, HEAD")
		http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	now := time.Now()
	status := statusResponse{
		Middleware:      m.name,
		Version:         Version,
		FailClosed:      m.opts.failClosed,
		BlockStatusCode: m.opts.statusCode,
		MaxStaleSeconds: int64(m.opts.maxStale.Seconds()),
		Providers:       make([]providerStatus, 0, len(m.providers)),
	}

	for _, provider := range m.providers {
		status.Providers = append(status.Providers, provider.status(now, m.opts.maxStale))
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
