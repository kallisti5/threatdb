package threatdb

import (
	"net/http/httptest"
	"testing"
)

func TestClientIPRemoteAddr(t *testing.T) {
	tests := []struct {
		remote string
		want   string
	}{
		{"203.0.113.5:4321", "203.0.113.5"},
		{"203.0.113.5", "203.0.113.5"},
		{"[2001:db8::1]:443", "2001:db8::1"},
		{"2001:db8::1", "2001:db8::1"},
		{"not-an-address", ""},
	}

	for _, test := range tests {
		req := httptest.NewRequest("GET", "http://example.com/", nil)
		req.RemoteAddr = test.remote

		ip := clientIP(req, "X-Forwarded-For", 0)
		got := ""
		if ip != nil {
			got = ip.String()
		}
		if got != test.want {
			t.Errorf("clientIP(%q, depth 0) = %q, want %q", test.remote, got, test.want)
		}
	}
}

func TestClientIPForwardedHeader(t *testing.T) {
	tests := []struct {
		name   string
		header string
		value  string
		depth  int
		remote string
		want   string
	}{
		{
			name:   "depth 1 uses last entry",
			header: "X-Forwarded-For",
			value:  "198.51.100.1, 203.0.113.5",
			depth:  1,
			remote: "10.0.0.9:5000",
			want:   "203.0.113.5",
		},
		{
			name:   "depth 2 uses second to last",
			header: "X-Forwarded-For",
			value:  "198.51.100.1, 203.0.113.5",
			depth:  2,
			remote: "10.0.0.9:5000",
			want:   "198.51.100.1",
		},
		{
			name:   "depth 1 single value",
			header: "X-Real-IP",
			value:  "203.0.113.5",
			depth:  1,
			remote: "10.0.0.9:5000",
			want:   "203.0.113.5",
		},
		{
			name:   "too few hops falls back",
			header: "X-Forwarded-For",
			value:  "203.0.113.5",
			depth:  2,
			remote: "10.0.0.9:5000",
			want:   "10.0.0.9",
		},
		{
			name:   "invalid value falls back",
			header: "X-Forwarded-For",
			value:  "not-an-ip",
			depth:  1,
			remote: "10.0.0.9:5000",
			want:   "10.0.0.9",
		},
		{
			name:   "missing header falls back",
			header: "X-Forwarded-For",
			depth:  1,
			remote: "10.0.0.9:5000",
			want:   "10.0.0.9",
		},
		{
			name:   "header with ports",
			header: "X-Forwarded-For",
			value:  "203.0.113.5:1234",
			depth:  1,
			remote: "10.0.0.9:5000",
			want:   "203.0.113.5",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com/", nil)
			req.RemoteAddr = test.remote
			if test.value != "" {
				req.Header.Set(test.header, test.value)
			}

			ip := clientIP(req, test.header, test.depth)
			got := ""
			if ip != nil {
				got = ip.String()
			}
			if got != test.want {
				t.Errorf("clientIP = %q, want %q", got, test.want)
			}
		})
	}
}

func TestClientIPIgnoresHeaderWhenUntrusted(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.RemoteAddr = "192.0.2.10:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.5")

	ip := clientIP(req, "X-Forwarded-For", 0)
	if ip == nil || ip.String() != "192.0.2.10" {
		t.Fatalf("clientIP = %v, want 192.0.2.10", ip)
	}
}

func TestIsInternalIP(t *testing.T) {
	internal := []string{
		"10.1.2.3",
		"172.16.0.1",
		"192.168.1.1",
		"127.0.0.1",
		"::1",
		"fe80::1",
		"fd00::1",
		"0.0.0.0",
		"100.64.0.1",
		"100.127.255.254",
		"224.0.0.1",
	}
	for _, value := range internal {
		if !isInternalIP(parseIP(value)) {
			t.Errorf("%s should be considered internal", value)
		}
	}

	external := []string{
		"203.0.113.5",
		"8.8.8.8",
		"2001:db8::1",
		"100.128.0.1",
	}
	for _, value := range external {
		if isInternalIP(parseIP(value)) {
			t.Errorf("%s should not be considered internal", value)
		}
	}
}
