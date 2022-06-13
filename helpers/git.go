package helpers

import (
	"fmt"
	"net/url"
	"os"
	"path"
	"strings"

	"github.com/adevinta/vulcan-check-sdk/state"
	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
)

const (
	repoPathPattern = "vulcan-repo-*"
	gheEndpointVar  = "GITHUB_ENTERPRISE_ENDPOINT"
	gheTokenVar     = "GITHUB_ENTERPRISE_TOKEN"
)

// CloneGitRepository clones a Git repository into a temporary directory and returns the path and branch name.
// If a branch is not specified, the default branch will be used and its name will be returned.
func CloneGitRepository(target string, branch string, depth int) (string, string, error) {
	// Check if the target repository is on Github Enterprise and return populated credentials if necessary.
	auth, err := gheAuth(target)
	if err != nil {
		return "", "", err
	}

	// Check that the repository is accessible with those credentials.
	isReachable, err := IsReachable(target, gitRepoType, &GitCreds{
		User: auth.Username,
		Pass: auth.Password,
	})
	if err != nil {
		return "", "", err
	}
	if !isReachable {
		return "", "", state.ErrAssetUnreachable
	}

	// Create a non-bare clone of the target repository referencing the provided branch.
	repoPath, err := os.MkdirTemp(os.TempDir(), repoPathPattern)
	if err != nil {
		return "", "", fmt.Errorf("error creating directory for repository: %w", err)
	}
	cloneOptions := git.CloneOptions{
		URL:   target,
		Auth:  auth,
		Depth: depth,
	}
	if branch != "" {
		cloneOptions.ReferenceName = plumbing.ReferenceName(path.Join("refs/heads", branch))
	}
	repo, err := git.PlainClone(repoPath, false, &cloneOptions)
	if err != nil {
		return "", "", fmt.Errorf("error cloning the repository: %w", err)
	}

	// Check that the target branch exists.
	branchRef, err := repo.Head()
	if err != nil {
		return "", "", fmt.Errorf("error retrieving the branch: %w", err)
	}

	branchName := strings.TrimPrefix(string(branchRef.Name()), "refs/heads/")

	return repoPath, branchName, nil
}

// gheAuth returns Github Enterprise credentials for the target repository, empty credentials or an error.
func gheAuth(target string) (*http.BasicAuth, error) {
	targetURL, err := url.Parse(target)
	if err != nil {
		return &http.BasicAuth{}, fmt.Errorf("error parsing \"%s\" as a URL: %w", target, err)
	}

	endpoint := os.Getenv(gheEndpointVar)
	gheURL, err := url.Parse(endpoint)
	if err != nil {
		return &http.BasicAuth{}, fmt.Errorf("error parsing \"%s\" as a URL: %w", endpoint, err)
	}

	// If Github Enterprise credentials are set, use them if target is on the same Github Enterprise.
	if gheURL.Host != "" && targetURL.Host == gheURL.Host {
		return &http.BasicAuth{
			Username: "username", // Can be anything except blank.
			Password: os.Getenv(gheTokenVar),
		}, nil
	}

	return &http.BasicAuth{}, nil
}

// GenerateGithubURL returns a URL poiting to a line of a file on a specific branch in the Github web application.
func GenerateGithubURL(target string, branch string, file string, line int) string {
	return fmt.Sprintf("%s/%s#L%v", strings.TrimSuffix(target, ".git"), path.Join("blob", branch, file), line)
}
