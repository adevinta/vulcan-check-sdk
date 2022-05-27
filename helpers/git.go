package helpers

import (
	"fmt"
	"net/url"
	"os"
	"path"

	git "gopkg.in/src-d/go-git.v4"
	"gopkg.in/src-d/go-git.v4/plumbing"
	"gopkg.in/src-d/go-git.v4/plumbing/transport/http"
)

const (
	repoPathPrefix = "vulcan-repo"
	gheEndpointVar = "GITHUB_ENTERPRISE_ENDPOINT"
	gheTokenVar    = "GITHUB_ENTERPRISE_TOKEN"
)

// CloneGitRepository clones a Git repository into a temporary directory and returns the path or an error.
func CloneGitRepository(target string, branch string, depth int) (string, error) {
	// Check if the repository is on Github Enterprise and return populated credentials if necessary.
	auth, err := gheAuth(target)
	if err != nil {
		return "", err
	}

	// Check that repository is accessible with those credentials.
	isReachable, err := IsReachable(target, gitRepoType, &GitCreds{
		User: auth.Username,
		Pass: auth.Password,
	})
	if err != nil {
		return "", err
	}
	if !isReachable {
		return "", checkstate.ErrAssetUnreachable
	}

	// Create a non-bare clone of the target repository referencing the provided branch.
	repoPath, err := os.MkdirTemp(os.TempDir(), repoPathPrefix)
	if err != nil {
		return "", fmt.Errorf("error creating directory for repository: %w", err)
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
		return "", fmt.Errorf("error cloning the repository: %w", err)
	}

	// Check that the target branch exists.
	_, err := repo.Head()
	if err != nil {
		return "", fmt.Errorf("error retrieving the branch: %w", err)
	}

	return repoPath, nil
}

// gheAuth returns Github Enterprise credentials for the target repository, empty credentials or an error.
func gheAuth(target string) (*http.BasicAuth, error) {
	endpoint := os.Getenv(gheEndpointVar)
	gheURL, err := url.Parse(endpoint)
	if err != nil {
		return &GitCreds{}, fmt.Errorf("error parsing \"%s\" as a Github Enterprise endpoint: %w", endpoint, err)
	}

	var auth *http.BasicAuth
	// If Github Enterprise credentials are set, use them if target is on the same Github Enterprise.
	if gheURL.Host != "" && target.Host == gheURL.Host {
		return &http.BasicAuth{
			Username: "username", // Can be anything except blank.
			Password: os.Getenv(gheTokenVar),
		}, nil
	}

	return &http.BasicAuth{}, nil
}
