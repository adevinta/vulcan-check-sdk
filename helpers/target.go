package helpers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/credentials"
	docker "github.com/docker/docker/client"
	git "gopkg.in/src-d/go-git.v4"
	gitauth "gopkg.in/src-d/go-git.v4/plumbing/transport/http"

	dockerutils "github.com/adevinta/dockerutils"
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
// If asset type is void, it will be inferred from target.
//
// The goal it's to prevent scanning hosts that are not public.
// Limitation: as the asset type is not available the function
// tries to guess the asset type, and that can lead to the scenario
// where we want to scan a domain that also is a hostname which
// resolves to a private IP. In that case the domain won't be scanned
// while it should.
func IsScannable(target, assetType string) bool {
	// In order to support backward compatibility
	// we have to support assetType being void.
	var err error
	if assetType == "" {
		assetType, err = detectAssetType(target)
		if err != nil {
			log.Printf("Unable to detect asset type for: %s", target)
			return false
		}
	}

	if assetType == ipType || assetType == ipRangeType {
		ok, _ := isAllowed(target) // nolint
		return ok
	}

	if assetType == webAddrsType {
		u, _ := url.ParseRequestURI(target) // nolint
		target = u.Hostname()
	}

	addrs, _ := net.LookupHost(target) // nolint

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

func detectAssetType(target string) (string, error) {
	if types.IsAWSARN(target) {
		return awsAccType, nil
	}
	if types.IsDockerImage(target) {
		return dockerImgType, nil
	}
	if types.IsGitRepository(target) {
		return gitRepoType, nil
	}
	if types.IsIP(target) {
		return ipType, nil
	}
	if types.IsCIDR(target) {
		return ipRangeType, nil
	}
	if types.IsURL(target) {
		return webAddrsType, nil
	}
	if types.IsHostname(target) {
		return hostnameType, nil
	}
	if isDomain, _ := types.IsDomainName(target); isDomain {
		return domainType, nil
	}

	return "", errors.New("Unable to detect asset type")
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
	RegistryURL string
	User        string
	Pass        string
}

// DockerHubCreds represents a void
// DockerCreds struct allowed to be
// used with Docker Hub registry.
var DockerHubCreds = &DockerCreds{}

// NewDockerCreds creates a new Docker Credentials struct.
func NewDockerCreds(registryURL, user, pass string) *DockerCreds {
	return &DockerCreds{
		RegistryURL: registryURL,
		User:        user,
		Pass:        pass,
	}
}
func (c *DockerCreds) URL() string {
	return c.RegistryURL
}
func (c *DockerCreds) Username() string {
	return c.User
}
func (c *DockerCreds) Password() string {
	return c.Pass
}

type GitCreds struct {
	RepoURL string
	User    string
	Pass    string
}

// NewGitCreds creates a new Git Credentials struct.
// user and pass can be void if no auth is required.
func NewGitCreds(repoURL, user, pass string) *GitCreds {
	return &GitCreds{
		RepoURL: repoURL,
		User:    user,
		Pass:    pass,
	}
}
func (c *GitCreds) URL() string {
	return c.RepoURL
}
func (c *GitCreds) Username() string {
	return c.User
}
func (c *GitCreds) Password() string {
	return c.Pass
}

// IsReachable returns wether target is reachable
// so the check execution can be performed.
// If asset type is void, it will be inferred from target.
//
// ServiceCredentials are required for AWS, Docker and Git types.
// Constructors for AWS, Docker and Git credentials can be found
// in this same package.
//
// Verifications made depend on the asset type:
//    - IP: None.
//    - IPRange: None.
//    - DomainName: None.
//    - Hostname: NS Lookup resolution.
//    - WebAddress: HTTP GET request.
//    - AWSAccount: Assume Role.
//    - DockerImage: Docker pull.
//    - GitRepository: Git clone.
//
// This function does not return any output related to the process in order to
// verify the target's reachability. This output can be useful for some cases
// in order to not repeat work in the check execution (e.g.: Obtaining the
// Assume Role token). For this purpose other individual methods can be called
// from this same package with further options for AWS, Docker and Git types.
func IsReachable(target, assetType string, creds ServiceCreds) (bool, error) {
	var isReachable bool
	var err error

	// In order to support backward compatibility
	// we have to support assetType being void.
	if assetType == "" {
		assetType, err = detectAssetType(target)
		if err != nil {
			return false, err
		}
	}

	if (assetType == awsAccType || assetType == dockerImgType ||
		assetType == gitRepoType) && creds == nil {
		return false, fmt.Errorf("ServiceCredentials are required")
	}

	switch assetType {
	case hostnameType:
		isReachable = IsHostnameReachable(target)
	case webAddrsType:
		isReachable = IsWebAddrsReachable(target)
	case awsAccType:
		isReachable, _, err = IsAWSAccReachable(target, creds.URL(), creds.Username(), 1)
	case dockerImgType:
		isReachable, err = IsDockerImgReachable(target, creds.URL(), creds.Username(), creds.Password())
	case gitRepoType:
		outPath := fmt.Sprintf("/tmp/%s", time.Now().String()) // Should be safe due to single thread execution
		isReachable, err = IsGitRepoReachable(target, creds.Username(), creds.Password(), outPath, 1, true)
	default:
		// Return true if we don't have a
		// verification in place for asset type.
		isReachable = true
	}

	return isReachable, err
}

// IsHostnameReachable returns wether the
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

// IsWebAddrsReachable returns wether the
// input web address accepts HTTP requests.
func IsWebAddrsReachable(target string) bool {
	_, err := http.Get(target)
	if err != nil {
		return false
	}
	return true
}

// IsAWSAccReachable returns wether the AWS account associated with the input ARN
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
	buf, err := ioutil.ReadAll(resp.Body)
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

// IsDockerImgReachable returns wether the input Docker image can be
// pulled with given creds. A void registry URL is no error, and will
// target public Docker Hub without authentication.
func IsDockerImgReachable(target, registryURL, user, pass string) (bool, error) {
	ctx := context.Background()

	envCli, err := docker.NewEnvClient()
	if err != nil {
		return false, err
	}
	cli := dockerutils.NewClient(envCli)

	// If registry has not been set
	// do not perform login.
	if registryURL != "" {
		err = cli.Login(
			ctx,
			registryURL,
			user,
			pass,
		)
		if err != nil {
			return false, err
		}
	}

	if err := cli.Pull(ctx, target); err != nil {
		if strings.Contains(err.Error(), "docker daemon") {
			// If error is related to comm with Docker daemon,
			// return err. Otherwise return not reachable.
			return false, err
		}
		return false, nil
	}
	return true, nil
}

// IsGitRepoReachable returns wether the input Git repository can be cloned.
// If no authentication is required, user and pass parameters can be void.
//    - outPath specifies the output path to clone the repo.
//    - depth indicates the clone depth.
//    - clean indicates that cloned repo dir must be removed before exit function.
func IsGitRepoReachable(target, user, pass, outPath string, depth int, clean bool) (bool, error) {
	if err := os.MkdirAll(outPath, 0755); err != nil {
		return false, err
	}
	if clean {
		defer os.RemoveAll(outPath)
	}

	auth := &gitauth.BasicAuth{
		Username: user,
		Password: pass,
	}

	_, err := git.PlainClone(outPath, false, &git.CloneOptions{
		URL:   target,
		Auth:  auth,
		Depth: depth,
	})
	if err != nil {
		// If we get an error on clone,
		// return not reachable.
		return false, nil
	}

	return true, nil
}
