package threatdb

import (
	"bytes"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"testing"
)

func TestAddListParsesCommonFormats(t *testing.T) {
	body := []byte("\ufeff203.0.113.5\r\n" +
		"198.51.100.0/24\r\n" +
		"# a comment line\n" +
		"\n" +
		"  2001:db8::1  \n" +
		"2001:db8:beef::/48 # inline comment\n" +
		"192.0.2.10 ; 192.0.2.11\n" +
		"0.0.0.0 some.host.example\n" +
		"not-an-address\n" +
		"443/tcp\n")

	set, valid, invalid, err := parseList(body)
	if err != nil {
		t.Fatalf("parseList returned error: %v", err)
	}

	if valid != 6 {
		t.Errorf("valid lines = %d, want 6", valid)
	}
	if invalid != 2 {
		t.Errorf("invalid lines = %d, want 2", invalid)
	}

	blocked := []string{
		"203.0.113.5",
		"198.51.100.0",
		"198.51.100.77",
		"2001:db8::1",
		"2001:db8:beef::1234",
		"192.0.2.10",
		"0.0.0.0",
	}
	for _, value := range blocked {
		if !set.contains(net.ParseIP(value)) {
			t.Errorf("%s should be in the set", value)
		}
	}

	allowed := []string{"198.51.101.1", "2001:db8:cafe::1", "192.0.2.11", "0.0.0.1", "1.1.1.1"}
	for _, value := range allowed {
		if set.contains(net.ParseIP(value)) {
			t.Errorf("%s should not be in the set", value)
		}
	}
}

func TestAddListDeduplicates(t *testing.T) {
	set, valid, _, err := parseList([]byte("203.0.113.5\n203.0.113.5\n198.51.100.0/24\n198.51.100.0/24\n"))
	if err != nil {
		t.Fatalf("parseList returned error: %v", err)
	}
	if valid != 4 {
		t.Errorf("valid lines = %d, want 4", valid)
	}
	if set.size != 2 {
		t.Errorf("set size = %d, want 2", set.size)
	}
}

func TestAddListMappedIPv4CIDR(t *testing.T) {
	set, _, _, err := parseList([]byte("::ffff:198.51.100.0/120\n"))
	if err != nil {
		t.Fatalf("parseList returned error: %v", err)
	}

	if !set.contains(net.ParseIP("198.51.100.5")) {
		t.Error("mapped IPv4 network should match plain IPv4 client")
	}
	if set.contains(net.ParseIP("198.51.101.5")) {
		t.Error("address outside the /24 portion should not match")
	}
}

func TestAddListRejectsGarbage(t *testing.T) {
	set, valid, invalid, err := parseList([]byte("<html><body>oops</body></html>\nnot an ip\n"))
	if err != nil {
		t.Fatalf("parseList returned error: %v", err)
	}
	if valid != 0 {
		t.Errorf("valid lines = %d, want 0", valid)
	}
	if invalid != 2 {
		t.Errorf("invalid lines = %d, want 2", invalid)
	}
	if set.size != 0 {
		t.Errorf("set size = %d, want 0", set.size)
	}
}

func TestMaskIP(t *testing.T) {
	tests := []struct {
		cidr string
		ones int
		want string
	}{
		{"192.0.2.0/24", 24, "192.0.2.0"},
		{"192.0.2.129/25", 25, "192.0.2.128"},
		{"192.0.2.129/32", 32, "192.0.2.129"},
		{"192.0.2.129/0", 0, "0.0.0.0"},
		{"2001:db8::1/64", 64, "2001:db8::"},
	}

	for _, test := range tests {
		host := test.cidr[:strings.IndexByte(test.cidr, '/')]
		ip := net.ParseIP(host)
		if ip == nil {
			t.Fatalf("could not parse %q", test.cidr)
		}
		if v4 := ip.To4(); v4 != nil {
			ip = v4
		}

		masked := net.IP([]byte(maskIP(ip, test.ones))).String()
		if masked != test.want {
			t.Errorf("maskIP(%s, %d) = %s, want %s", test.cidr, test.ones, masked, test.want)
		}
	}
}

func TestIPSetNilAndInvalid(t *testing.T) {
	var set *ipSet
	if set.contains(net.ParseIP("1.2.3.4")) {
		t.Error("nil set should not contain anything")
	}

	set = newIPSet()
	if set.contains(nil) {
		t.Error("nil IP should not match")
	}
	if set.contains(net.IP{1, 2, 3}) {
		t.Error("invalid IP should not match")
	}
}

// TestIPSetMatchesIPNet cross-checks the prefix bucketing against the standard
// library's net.IPNet.Contains for randomly generated networks and addresses.
func TestIPSetMatchesIPNet(t *testing.T) {
	random := rand.New(rand.NewSource(42))

	randomIP := func(v6 bool) net.IP {
		if v6 {
			ip := make(net.IP, net.IPv6len)
			_, _ = random.Read(ip)
			return ip
		}
		return net.IPv4(byte(random.Intn(256)), byte(random.Intn(256)), byte(random.Intn(256)), byte(random.Intn(256)))
	}

	set := newIPSet()
	var networks []*net.IPNet

	for i := 0; i < 200; i++ {
		ip := randomIP(i%2 == 1)
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		ones := random.Intn(bits + 1)

		_, network, err := net.ParseCIDR(fmt.Sprintf("%s/%d", ip, ones))
		if err != nil {
			t.Fatalf("could not build random network: %v", err)
		}
		set.addCIDR(network)
		networks = append(networks, network)

		// Also add an exact address from time to time.
		if i%5 == 0 {
			set.addIP(ip)
		}
	}

	for i := 0; i < 5000; i++ {
		ip := randomIP(i%3 == 0)

		want := false
		for _, network := range networks {
			if network.Contains(ip) {
				want = true
				break
			}
		}

		if got := set.contains(ip); got != want {
			t.Fatalf("contains(%s) = %v, want %v", ip, got, want)
		}
	}
}

func BenchmarkIPSetContains(b *testing.B) {
	var body bytes.Buffer
	for i := 0; i < 50000; i++ {
		fmt.Fprintf(&body, "10.%d.%d.%d\n", (i>>16)&0xff, (i>>8)&0xff, i&0xff)
	}
	for i := 0; i < 200; i++ {
		fmt.Fprintf(&body, "172.%d.0.0/16\n", i)
	}

	set, _, _, err := parseList(body.Bytes())
	if err != nil {
		b.Fatal(err)
	}

	hit := net.ParseIP("10.0.156.64")
	miss := net.ParseIP("8.8.8.8")
	cidrHit := net.ParseIP("172.100.1.1")

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if !set.contains(hit) {
			b.Fatal("expected hit")
		}
		if set.contains(miss) {
			b.Fatal("expected miss")
		}
		if !set.contains(cidrHit) {
			b.Fatal("expected CIDR hit")
		}
	}
}
