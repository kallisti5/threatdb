package threatdb

import (
	"bufio"
	"bytes"
	"net"
	"strings"
)

// ipSet is an immutable set of IP addresses and CIDR networks.
//
// Exact addresses are stored in hash sets. CIDR networks are bucketed by
// prefix length and stored with their host bits masked, so a lookup costs one
// hash probe per distinct prefix length (usually a handful) instead of a
// linear scan over every network.
type ipSet struct {
	exact4 map[string]struct{}
	exact6 map[string]struct{}

	cidr4 map[int]map[string]struct{}
	cidr6 map[int]map[string]struct{}

	lengths4 []int
	lengths6 []int

	size int
}

func newIPSet() *ipSet {
	return &ipSet{
		exact4: make(map[string]struct{}),
		exact6: make(map[string]struct{}),
		cidr4:  make(map[int]map[string]struct{}),
		cidr6:  make(map[int]map[string]struct{}),
	}
}

// addEntry parses one list field (an address, optionally host:port, or a CIDR
// network) and adds it to the set. It reports whether the field was valid.
func addEntry(set *ipSet, field string) bool {
	field = strings.TrimSpace(field)
	if field == "" {
		return false
	}

	if strings.Contains(field, "/") {
		_, network, err := net.ParseCIDR(field)
		if err != nil {
			return false
		}
		set.addCIDR(network)
		return true
	}

	ip := parseIP(field)
	if ip == nil {
		return false
	}
	set.addIP(ip)
	return true
}

// addIP adds a single address. IPv4-mapped IPv6 addresses are normalised to
// IPv4 so that providers do not need to be consistent about representation.
func (s *ipSet) addIP(ip net.IP) {
	if v4 := ip.To4(); v4 != nil {
		key := string(v4)
		if _, exists := s.exact4[key]; !exists {
			s.exact4[key] = struct{}{}
			s.size++
		}
		return
	}

	v6 := ip.To16()
	if v6 == nil {
		return
	}
	key := string(v6)
	if _, exists := s.exact6[key]; !exists {
		s.exact6[key] = struct{}{}
		s.size++
	}
}

// addCIDR adds a network. The network's address is used, so host bits are
// discarded.
func (s *ipSet) addCIDR(network *net.IPNet) {
	if network == nil {
		return
	}

	ones, bits := network.Mask.Size()
	if ones < 0 {
		return
	}

	switch bits {
	case 32:
		ip4 := network.IP.To4()
		if ip4 == nil {
			return
		}
		s.addCIDR4(ip4, ones)

	case 128:
		// Treat IPv4-mapped IPv6 networks as IPv4 so lookups for plain IPv4
		// clients still match.
		if ones >= 96 {
			if ip4 := network.IP.To4(); ip4 != nil {
				s.addCIDR4(ip4, ones-96)
				return
			}
		}
		ip6 := network.IP.To16()
		if ip6 == nil {
			return
		}
		key := maskIP(ip6, ones)
		if s.cidr6[ones] == nil {
			s.cidr6[ones] = make(map[string]struct{})
			s.lengths6 = append(s.lengths6, ones)
		}
		if _, exists := s.cidr6[ones][key]; !exists {
			s.cidr6[ones][key] = struct{}{}
			s.size++
		}
	}
}

func (s *ipSet) addCIDR4(ip4 net.IP, ones int) {
	if ones < 0 || ones > 32 {
		return
	}
	key := maskIP(ip4, ones)
	if s.cidr4[ones] == nil {
		s.cidr4[ones] = make(map[string]struct{})
		s.lengths4 = append(s.lengths4, ones)
	}
	if _, exists := s.cidr4[ones][key]; !exists {
		s.cidr4[ones][key] = struct{}{}
		s.size++
	}
}

// contains reports whether ip is present in the set.
func (s *ipSet) contains(ip net.IP) bool {
	if s == nil || ip == nil {
		return false
	}

	if v4 := ip.To4(); v4 != nil {
		if _, exists := s.exact4[string(v4)]; exists {
			return true
		}
		for _, ones := range s.lengths4 {
			if _, exists := s.cidr4[ones][maskIP(v4, ones)]; exists {
				return true
			}
		}
		return false
	}

	v6 := ip.To16()
	if v6 == nil {
		return false
	}
	if _, exists := s.exact6[string(v6)]; exists {
		return true
	}
	for _, ones := range s.lengths6 {
		if _, exists := s.cidr6[ones][maskIP(v6, ones)]; exists {
			return true
		}
	}
	return false
}

// maskIP returns ip with all bits after the first ones bits cleared, encoded
// as a map key.
func maskIP(ip net.IP, ones int) string {
	buf := make([]byte, len(ip))
	copy(buf, ip)

	for i := range buf {
		remaining := ones - i*8
		switch {
		case remaining >= 8:
			// Keep the whole byte.
		case remaining <= 0:
			buf[i] = 0
		default:
			buf[i] &= byte(0xff << uint(8-remaining))
		}
	}

	return string(buf)
}

// parseList parses a whitespace/comma separated threat list and returns the set
// together with the number of lines that contained at least one valid entry
// and the number of lines that did not.
func parseList(body []byte) (*ipSet, int, int, error) {
	scanner := newLineScanner(body)
	set := newIPSet()

	valid := 0
	invalid := 0

	first := true
	for scanner.Scan() {
		line := scanner.Text()
		if first {
			line = strings.TrimPrefix(line, "\ufeff")
			first = false
		}

		// Everything after a # or ; is a comment (Spamhaus style lists use ;).
		if index := strings.IndexAny(line, "#;"); index >= 0 {
			line = line[:index]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		lineValid := false
		for _, field := range strings.FieldsFunc(line, isListSeparator) {
			if addEntry(set, field) {
				lineValid = true
			}
		}

		if lineValid {
			valid++
		} else {
			invalid++
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, 0, 0, err
	}

	return set, valid, invalid, nil
}

func isListSeparator(r rune) bool {
	switch r {
	case ' ', '\t', '\r', '\v', '\f', ',', '|':
		return true
	default:
		return false
	}
}

// newLineScanner returns a scanner for a list body. Lines longer than a
// megabyte are rejected rather than silently truncated.
func newLineScanner(body []byte) *bufio.Scanner {
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	return scanner
}
