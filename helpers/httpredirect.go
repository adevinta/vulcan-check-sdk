package helpers

import (
	"crypto/tls"
	"net/http"
	"strings"
)

const (
	// OKTADomain contains the domainname of OKTA service.
	OKTADomain = "okta.com"
)

// walkHTTPRedirects sends a request to the given url, follows up to 10 redirects
// and returns the hostname of the last one.
func walkHTTPRedirects(url string) (string, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: tr,
	}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	return resp.Request.URL.Hostname(), nil
}

// IsRedirectingTo checks if the url that the url param is pointing to is redirecting
// to a given domain name.
func IsRedirectingTo(url, domain string) (res bool, lastHostname string, err error) {
	lastHostname, err = walkHTTPRedirects(url)
	if err != nil {
		return res, lastHostname, err
	}
	// We consider a hostname is belonging to a domain if the domain is a suffix of the hostname.
	res = strings.HasSuffix(strings.ToLower(lastHostname), strings.ToLower(domain))
	return res, lastHostname, nil
}
