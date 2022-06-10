/*
Copyright 2019 Adevinta
*/

package helpers

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/credentials"
	git "gopkg.in/src-d/go-git.v4"
	"gopkg.in/src-d/go-git.v4/config"
	gitauth "gopkg.in/src-d/go-git.v4/plumbing/transport/http"
	"gopkg.in/src-d/go-git.v4/storage/memory"

	types "github.com/adevinta/vulcan-types"
)

const (
	// Supported types.
	ipType        = "IP"
	ipRangeType   = "IPRange"
	domainType    = "DomainName"
	hostnameType  = "Hostname"
	webAddrsType  = "WebAddress"
	awsAccType    = "AWSAccount"
	dockerImgType = "DockerImage"
	gitRepoType   = "GitRepository"

	// minSesstime is the minimum session
	// time (seconds) allowed by AWS to
	// assume role into an account.
	minSessTime = 900
)

var (
	// ErrFailedToGetDNSAnswer represents error returned
	// when unable to get a valid answer from the current
	// configured dns servers.
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

	if types.IsWebAddress(asset) {
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

// ServiceCreds represents the credentials
// necessary to access an authenticated service.
// There are constructors available in this same
// package for:
//    - AWS Assume role through vulcan-assume-role svc.
//    - Docker registry.
//    - Github repository.
type ServiceCreds interface {
	URL() string
	Username() string
	Password() string
}

// AWSCreds holds data required
// to perform an assume role request.
type AWSCreds struct {
	AssumeRoleURL string
	Role          string
}

// NewAWSCreds creates a new AWS Credentials for Assume Role.
func NewAWSCreds(assumeRoleURL, role string) *AWSCreds {
	return &AWSCreds{
		AssumeRoleURL: assumeRoleURL,
		Role:          role,
	}
}
func (c *AWSCreds) URL() string {
	return c.AssumeRoleURL
}
func (c *AWSCreds) Username() string {
	return c.Role
}
func (c *AWSCreds) Password() string {
	return ""
}

type DockerCreds struct {
	User string
	Pass string
}

// DockerHubCreds represents a void
// DockerCreds struct allowed to be
// used with Docker Hub registry.
var DockerHubCreds = &DockerCreds{}

// NewDockerCreds creates a new Docker Credentials struct.
func NewDockerCreds(user, pass string) *DockerCreds {
	return &DockerCreds{
		User: user,
		Pass: pass,
	}
}
func (c *DockerCreds) URL() string {
	return ""
}
func (c *DockerCreds) Username() string {
	return c.User
}
func (c *DockerCreds) Password() string {
	return c.Pass
}

type GitCreds struct {
	User string
	Pass string
}

// NewGitCreds creates a new Git Credentials struct.
// User and pass can be void if no auth is required.
func NewGitCreds(user, pass string) *GitCreds {
	return &GitCreds{
		User: user,
		Pass: pass,
	}
}
func (c *GitCreds) URL() string {
	return ""
}
func (c *GitCreds) Username() string {
	return c.User
}
func (c *GitCreds) Password() string {
	return c.Pass
}

// IsReachable returns whether target is reachable
// so the check execution can be performed.
//
// ServiceCredentials are required for AWS, Docker and Git types.
// Constructors for AWS, Docker and Git credentials can be found
// in this same package.
//
// Verifications made depend on the asset type:
//    - IP: None.
//    - IPRange: None.
//    - Hostname: NS Lookup resolution.
//    - WebAddress: HTTP GET request.
//    - DomainName: NS Lookup checking SOA record.
//    - AWSAccount: Assume Role.
//    - DockerImage: Check image exists in registry.
//    - GitRepository: Git ls-remote.
//
// This function does not return any output related to the process in order to
// verify the target's reachability. This output can be useful for some cases
// in order to not repeat work in the check execution (e.g.: Obtaining the
// Assume Role token). For this purpose other individual methods can be called
// from this same package with further options for AWS, Docker and Git types.
func IsReachable(target, assetType string, creds ServiceCreds) (bool, error) {
	var isReachable bool
	var err error

	if (assetType == awsAccType || assetType == dockerImgType ||
		assetType == gitRepoType) && creds == nil {
		return false, fmt.Errorf("ServiceCredentials are required")
	}

	switch assetType {
	case hostnameType:
		isReachable = IsHostnameReachable(target)
	case webAddrsType:
		isReachable = IsWebAddrsReachable(target)
	case domainType:
		isReachable, err = IsDomainReachable(target)
	case awsAccType:
		isReachable, _, err = IsAWSAccReachable(target, creds.URL(), creds.Username(), minSessTime)
	case dockerImgType:
		isReachable, err = IsDockerImgReachable(target, creds.Username(), creds.Password())
	case gitRepoType:
		isReachable = IsGitRepoReachable(target, creds.Username(), creds.Password())
	default:
		// Return true if we don't have a
		// verification in place for asset type.
		isReachable = true
	}

	return isReachable, err
}

// IsHostnameReachable returns whether the
// input hostname target can be resolved.
func IsHostnameReachable(target string) bool {
	_, err := net.LookupHost(target)
	if err != nil {
		if dnsErr, ok := err.(*net.DNSError); ok {
			return !dnsErr.IsNotFound
		}
	}
	return true
}

// IsWebAddrsReachable returns whether the
// input web address accepts HTTP requests.
func IsWebAddrsReachable(target string) bool {
	_, err := http.Get(target)
	if err != nil {
		return false
	}
	return true
}

// IsDomainReachable returns whether the input target
// is a reachable Domain Name. The criteria to determine
// a target as a Domain is the existence of a SOA record.
func IsDomainReachable(target string) (bool, error) {
	return types.IsDomainName(target)
}

// IsAWSAccReachable returns whether the AWS account associated with the input ARN
// allows to assume role with the given params through the vulcan-assume-role service.
// If role is assumed correctly for the given account, STS credentials are returned.
func IsAWSAccReachable(accARN, assumeRoleURL, role string, sessDuration int) (bool, *credentials.Credentials, error) {
	parsedARN, err := arn.Parse(accARN)
	if err != nil {
		return false, nil, err
	}
	params := map[string]interface{}{
		"account_id": parsedARN.AccountID,
		"role":       role,
	}
	if sessDuration > 0 {
		params["duration"] = sessDuration
	}
	jsonBody, _ := json.Marshal(params)
	req, err := http.NewRequest("POST", assumeRoleURL, bytes.NewBuffer(jsonBody))
	if err != nil {
		return false, nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer resp.Body.Close()

	// If we are not allowed to assume role on the
	// target AWS account, check can not be executed
	// on asset, so return false.
	if resp.StatusCode == http.StatusForbidden {
		return false, nil, nil
	}

	assumeRoleResp := struct {
		AccessKey       string `json:"access_key"`
		SecretAccessKey string `json:"secret_access_key"`
		SessionToken    string `json:"session_token"`
	}{}
	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, nil, err
	}
	err = json.Unmarshal(buf, &assumeRoleResp)
	if err != nil {
		return false, nil, err
	}

	return true, credentials.NewStaticCredentials(
		assumeRoleResp.AccessKey,
		assumeRoleResp.SecretAccessKey,
		assumeRoleResp.SessionToken), nil
}

// IsDockerImgReachable returns whether the input Docker image exists in the
// registry. Void user and pass does not produce an error as long as a token
// can be generated without authentication.
//
// In order to verify if the Docker image exists, we perform a request to
// registry API endpoint to get data for given image and tag.  This
// functionality at the moment of this writing is still not implemented in
// Docker client, so we have to contact registry's REST API directly.
// Reference: https://github.com/moby/moby/issues/14254
func IsDockerImgReachable(target, user, pass string) (bool, error) {
	repo, err := parseDockerRepo(target)
	if err != nil {
		return false, err
	}

	token, err := dockerAPIToken(repo, user, pass)
	if err != nil {
		return false, err
	}

	// Check there exist tags for the image.
	tagEndpoint := fmt.Sprintf("https://%s/v2/%s/tags/list/", repo.Registry, repo.Img)

	req, err := http.NewRequest(http.MethodGet, tagEndpoint, nil)
	if err != nil {
		return false, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, err
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("unexpected status code while checking Docker image tags: %d", resp.StatusCode)
	}
	defer resp.Body.Close()

	// Check that the target specified tag exists for the image.
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	img := struct {
		Name string
		Tags []string
	}{}
	if err := json.Unmarshal(body, &img); err != nil {
		return false, err
	}
	if img.Name != repo.Img {
		return false, fmt.Errorf("image differs. want: %v, have: %v", repo.Img, img.Name)
	}
	found := false
	for _, tag := range img.Tags {
		if tag == repo.Tag {
			found = true
			break
		}
	}
	if !found {
		return false, errors.New("tag does not exist for the image")
	}

	return true, nil
}

// dockerAPIToken generates a bearer token for the Docker Registry API (v2).
// Reference: https://docs.docker.com/registry/spec/api/#api-version-check
func dockerAPIToken(repo dockerRepo, user, pass string) (string, error) {
	// Check that the registry API supports version 2.
	resp, err := http.Get(fmt.Sprintf("https://%s/v2/", repo.Registry))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusUnauthorized {
		return "", fmt.Errorf("unexpected status code while checking docker registry API version: %d", resp.StatusCode)
	}

	versionH := resp.Header["Docker-Distribution-Api-Version"]
	found := false
	for _, v := range versionH {
		if v == "registry/2.0" {
			found = true
			break
		}
	}
	if !found {
		return "", errors.New("missing or unexpected version header")
	}

	// Request token to the auth service specified via authenticate header.
	re, err := regexp.Compile(`Bearer realm="(.+)",service="(.+)"`)
	if err != nil {
		return "", err
	}

	var realm string
	var service string
	authH := resp.Header["Www-Authenticate"]
	found = false
	for _, v := range authH {
		matches := re.FindStringSubmatch(v)
		if len(matches) == 3 {
			found = true
			realm = matches[1]
			service = matches[2]
			break
		}
	}
	if !found {
		return "", errors.New("missing or unexpected authentication header")
	}

	req, err := http.NewRequest("GET", realm, nil)
	if err != nil {
		return "", err
	}

	q := req.URL.Query()
	q.Add("service", service)
	q.Add("scope", fmt.Sprintf("repository:%s:pull", repo.Img))
	req.URL.RawQuery = q.Encode()

	if user != "" && pass != "" {
		req.SetBasicAuth(user, pass)
	}

	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	t := struct {
		Token string
	}{}
	if err := json.Unmarshal(body, &t); err != nil {
		return "", err
	}

	return t.Token, nil
}

type dockerRepo struct {
	Registry string
	Img      string
	Tag      string
}

func parseDockerRepo(repo string) (dockerRepo, error) {
	// NOTE(julianvilas): Defaulting to latest opens the door to scan images
	// without tags.
	tag := "latest"

	imgParts := strings.Split(repo, ":")
	if len(imgParts) == 2 && imgParts[1] != "" {
		tag = imgParts[1]
	}

	imgWithOutTag := imgParts[0]
	u, err := url.Parse(fmt.Sprintf("http://%s", imgWithOutTag))
	if err != nil {
		return dockerRepo{}, fmt.Errorf("Error parsing Docker repo")
	}

	return dockerRepo{
		Registry: u.Host,
		Img:      strings.TrimPrefix(u.Path, "/"),
		Tag:      tag,
	}, nil
}

// IsGitRepoReachable returns whether the input Git repository is reachable
// by performing a ls-remote.
// If no authentication is required, user and pass parameters can be void.
func IsGitRepoReachable(target, user, pass string) bool {
	rem := git.NewRemote(memory.NewStorage(), &config.RemoteConfig{
		Name: "origin",
		URLs: []string{target},
	})
	auth := &gitauth.BasicAuth{
		Username: user,
		Password: pass,
	}
	_, err := rem.List(&git.ListOptions{Auth: auth})
	return err == nil
}
