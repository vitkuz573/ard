package main

import (
	"fmt"
	"net"
	"strings"
)

// parseSANs splits a comma-separated SAN list into DNS names and IP addresses.
//
// Both forms matter: the gateway is reached by hostname in a deployment and by
// raw IPv4 while testing, and a certificate carrying only DNS names will fail
// verification for a client that dials the IP. Leaving the IP out of the SAN set
// would produce a connection that works only from a laptop with DNS.
func parseSANs(in string) (dnsNames []string, ips []net.IP, err error) {
	for _, raw := range strings.Split(in, ",") {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if ip := net.ParseIP(s); ip != nil {
			ips = append(ips, ip)
			continue
		}
		if strings.ContainsAny(s, " \t/") {
			return nil, nil, fmt.Errorf("SAN %q is not a valid DNS name or IP", s)
		}
		dnsNames = append(dnsNames, s)
	}
	if len(dnsNames) == 0 && len(ips) == 0 {
		return nil, nil, fmt.Errorf("no SANs given; server certificate would be unusable")
	}
	return dnsNames, ips, nil
}