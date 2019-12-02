package helpers

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"strings"

	types "github.com/adevinta/vulcan-types"
	"github.com/miekg/dns"
)

const (
	dnsConfFilePath      = "/etc/resolv.conf"
	noSuchHostErrorToken = "no such host"
)

var (
	dnsConf *dns.ClientConfig
	// ErrFailedToGetDNSAnswer represents error returned when unable to get a valid answer from the current configured dns
	// servers.
	ErrFailedToGetDNSAnswer = errors.New("failed to get a valid answer")
	reservedIPV4s           = []string{
		"0.0.0.0/8",
		"10.0.0.0/8",
		"100.64.0.0/10",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"172.16.0.0/12",
		"192.0.0.0/24",
		"192.0.2.0/24",
		"192.88.99.0/24",
		"192.168.0.0/16",
		"198.18.0.0/15",
		"198.51.100.0/24",
		"203.0.113.0/24",
		"224.0.0.0/4",
		"240.0.0.0/4",
		"255.255.255.255/32",
	}
	reservedIPV6s = []string{
		"::1/128",
		"64:ff9b::/96",
		"100::/64",
		"2001::/32",
		"2001:20::/28",
		"2001:db8::/32",
		"2002::/16",
		"fc00::/7",
		"fe80::/10",
		"ff00::/8",
	}
	NotScannableNetsIPV4 []*net.IPNet
	NotScannableNetsIPV6 []*net.IPNet
)

func init() {
	// Add the reserved ip v4 nets as not scannable.
	for _, ip := range reservedIPV4s {
		_, reserved, _ := net.ParseCIDR(ip) // nolint
		NotScannableNetsIPV4 = append(NotScannableNetsIPV4, reserved)
	}

	// Add the reserved ip v6 nets as not scannable.
	for _, ip := range reservedIPV6s {
		_, reserved, _ := net.ParseCIDR(ip) // nolint
		NotScannableNetsIPV6 = append(NotScannableNetsIPV6, reserved)
	}
}

// IsScannable tells you whether an asset can be scanned or not,
// based in its type and value.
// The goal it's to prevent scanning hosts that are not public.
// Limitation: as the asset type is not available the function
// tries to guess the asset type, and that can lead to the scenario
// where we want to scan a domain that also is a hostname which
// resolves to a private IP. In that case the domain won't be scanned
// while it should.
func IsScannable(asset string) bool {
	if types.IsIP(asset) || types.IsCIDR(asset) {
		log.Printf("%s is IP or CIDR", asset)
		ok, _ := isAllowed(asset) // nolint
		return ok
	}

	if types.IsURL(asset) {
		u, _ := url.ParseRequestURI(asset) // nolint
		asset = u.Hostname()
	}

	addrs, _ := net.LookupHost(asset) // nolint

	return verifyIPs(addrs)
}

func verifyIPs(addrs []string) bool {
	for _, addr := range addrs {
		if ok, err := isAllowed(addr); err != nil || !ok {
			return false
		}
	}
	return true
}

func isAllowed(addr string) (bool, error) {
	addrCIDR := addr
	var nets []*net.IPNet
	if strings.Contains(addr, ".") {
		if !strings.Contains(addr, "/") {
			addrCIDR = fmt.Sprintf("%s/32", addr)
		}
		nets = NotScannableNetsIPV4
	} else {
		if !strings.Contains(addr, "/") {
			addrCIDR = fmt.Sprintf("%s/128", addr)
		}
		nets = NotScannableNetsIPV6
	}
	_, addrNet, err := net.ParseCIDR(addrCIDR)
	if err != nil {
		return false, fmt.Errorf("error parsing the ip address %s", addr)
	}
	for _, n := range nets {
		if n.Contains(addrNet.IP) {
			return false, nil
		}
	}
	return true, nil
}
