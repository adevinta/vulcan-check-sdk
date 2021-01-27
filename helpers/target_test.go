package helpers

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"testing"

	"github.com/aws/aws-sdk-go/aws/credentials"
)

func TestTarget_IsScannable(t *testing.T) {
	tests := []struct {
		name   string
		target string
		want   bool
	}{
		{
			name:   "ValidCIDR",
			target: "1.1.1.1/24",
			want:   true,
		},
		{
			name:   "ValidIP",
			target: "1.1.1.1",
			want:   true,
		},
		{
			name:   "ValidHostname",
			target: "www.google.com",
			want:   true,
		},
		{
			name:   "ValidURL",
			target: "http://www.google.com",
			want:   true,
		},
		{
			name:   "ValidDomainName",
			target: "google.com",
			want:   true,
		},
		{
			name:   "ValidDockerImage",
			target: "registry.hub.docker.com/library/alpine:latest",
			want:   true,
		},
		{
			name:   "ValidAWSAccount",
			target: "arn:aws:iam::111111111111:root",
			want:   true,
		},
		{
			name:   "HostnameNotResolve",
			target: "test.example.com",
			want:   true,
		},
		{
			name:   "PrivateCIDR",
			target: "127.0.0.1/24",
			want:   false,
		},
		{
			name:   "PrivateIP",
			target: "127.0.0.1",
			want:   false,
		},
		{
			name:   "HostnameResolvesPrivate",
			target: "localhost",
			want:   false,
		},
		{
			name:   "URLResolvesPrivate",
			target: "https://localhost",
			want:   false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := IsScannable(tt.target)
			if got != tt.want {
				t.Errorf("Target.IsScannable() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTarget_IsHostnameReachable(t *testing.T) {
	testCases := []struct {
		name   string
		target string
		want   bool
	}{
		{
			name:   "Should return true, hostname reachable",
			target: "google.com",
			want:   true,
		},
		{
			name:   "Should return false, hostname NOT reachable",
			target: "thisIsProbablyAnUnexistentHostnameIReallyHope.com",
			want:   false,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			if isReachable := IsHostnameReachable(tt.target); isReachable != tt.want {
				t.Fatalf("Expected reachability for %s to be %v, but got %v",
					tt.target, tt.want, isReachable)
			}
		})
	}
}

func TestTarget_IsWebAddrsReachable(t *testing.T) {
	testCases := []struct {
		name   string
		target string
		want   bool
	}{
		{
			name:   "Should return true, website reachable",
			target: "https://www.adevinta.com",
			want:   true,
		},
		{
			name:   "Should return false, website NOT reachable",
			target: "http://www.thisIsProbablyAnUnexistentHostnameIReallyHope.com",
			want:   false,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			if isReachable := IsWebAddrsReachable(tt.target); isReachable != tt.want {
				t.Fatalf("Expected reachability for %s to be %v, but got %v",
					tt.target, tt.want, isReachable)
			}
		})
	}
}

func TestTarget_IsAWSAccReachable(t *testing.T) {
	// Test http handler for granted assume role
	okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify payload is correct
		payload, err := ioutil.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var assumeRoleReq map[string]string
		err = json.Unmarshal(payload, &assumeRoleReq)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		accID, okAcc := assumeRoleReq["account_id"]
		_, okRole := assumeRoleReq["role"]
		if !okAcc || !okRole {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if !isAWSAccountID(accID) {
			t.Log("Mock server payload is not a valid accID")
			w.WriteHeader(http.StatusBadRequest)
		}

		// Build response body
		respBody, err := json.Marshal(struct {
			AccessKey       string `json:"access_key"`
			SecretAccessKey string `json:"secret_access_key"`
			SessionToken    string `json:"session_token"`
		}{
			AccessKey:       "accessKey",
			SecretAccessKey: "secretAccessKey",
			SessionToken:    "sessionToken",
		})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Write(respBody)
		w.WriteHeader(http.StatusOK)
	})
	// Test http handler for forbidden assume role
	koHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify payload is correct
		payload, err := ioutil.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var assumeRoleReq map[string]string
		err = json.Unmarshal(payload, &assumeRoleReq)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, okAcc := assumeRoleReq["account_id"]
		_, okRole := assumeRoleReq["role"]
		if !okAcc || !okRole {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Deny assume role
		w.WriteHeader(http.StatusForbidden)
	})

	type input struct {
		accID string
		// assumeRoleURL string // Set by httptest srv
		role         string
		sessDuration int
	}

	testCases := []struct {
		name       string
		input      input
		srvHandler http.Handler
		want       bool
		wantCreds  *credentials.Credentials
	}{
		{
			name: "Should return true, granted assume role",
			input: input{
				accID: "arn:aws:iam::000000000000:root",
				role:  "role1",
			},
			srvHandler: okHandler,
			want:       true,
			wantCreds: credentials.NewStaticCredentials(
				"accessKey",
				"secretAccessKey",
				"sessionToken",
			),
		},
		{
			name: "Should return false, forbidden assume role",
			input: input{
				accID: "arn:aws:iam::111111111111:root",
				role:  "role2",
			},
			srvHandler: koHandler,
			want:       false,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			testSrv := httptest.NewServer(tt.srvHandler)

			isReachable, creds, err := IsAWSAccReachable(tt.input.accID, testSrv.URL, tt.input.role, tt.input.sessDuration)
			if err != nil {
				t.Fatalf("Expected no error but got: %v", err)
			}
			if isReachable != tt.want {
				t.Fatalf("Expected reachability for %s to be %v, but got %v",
					tt.input.accID, tt.want, isReachable)
			}
			if isReachable && !reflect.DeepEqual(tt.wantCreds, creds) {
				t.Fatalf("Expected creds to be: %v\nBut got: %v",
					tt.wantCreds, creds)
			}

			testSrv.Close()
		})
	}
}

func isAWSAccountID(accID string) bool {
	if _, err := strconv.Atoi(accID); err == nil && len(accID) == 12 {
		return true
	}
	return false
}

func TestTarget_IsDockerImgReachable(t *testing.T) {
	testCases := []struct {
		name    string
		target  string
		user    string
		pass    string
		want    bool
		wantErr bool
	}{
		{
			name:    "Should return true, image is reachable",
			target:  "registry.hub.docker.com/library/hello-world:latest",
			want:    true,
			wantErr: false,
		},
		{
			name:    "Should return true, image without specified tag is reachable",
			target:  "registry.hub.docker.com/library/hello-world",
			want:    true,
			wantErr: false,
		},
		{
			name:    "Should return false, image with wrong tag is NOT reachable",
			target:  "registry.hub.docker.com/library/hello-world:wrongtag",
			want:    false,
			wantErr: true,
		},
		{
			name:    "Should return false, image is NOT reachable",
			target:  "registry.hub.docker.com/thisissomegiberishaweioanwe/giberishaweoij:latest",
			want:    false,
			wantErr: true,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			isReachable, err := IsDockerImgReachable(tt.target, tt.user, tt.pass)
			if err != nil && !tt.wantErr {
				t.Fatalf("Expected no error but got: %v", err)
			}
			if isReachable != tt.want {
				t.Fatalf("Expected Docker img '%s' reachability to be %v but was %v",
					tt.target, tt.want, isReachable)
			}
		})
	}
}

func TestTarget_parseDockerRepo(t *testing.T) {
	testCases := []struct {
		repo string
		want dockerRepo
	}{
		{
			repo: "registry.hub.docker.com/library/hello-world:latest",
			want: dockerRepo{
				Registry: "registry.hub.docker.com",
				Img:      "library/hello-world",
				Tag:      "latest",
			},
		},
		{
			repo: "artifactory.company.com/project/img_alpine:3.10.1",
			want: dockerRepo{
				Registry: "artifactory.company.com",
				Img:      "project/img_alpine",
				Tag:      "3.10.1",
			},
		},
	}

	for _, tt := range testCases {
		repo, err := parseDockerRepo(tt.repo)
		if err != nil {
			t.Fatalf("Expected no error but got: %v", err)
		}
		if !reflect.DeepEqual(tt.want, repo) {
			t.Fatalf("Expected repo to be: %v\nBut got: %v", tt.want, repo)
		}
	}
}

func TestTarget_IsGitRepoReachable(t *testing.T) {
	type input struct {
		target string
		user   string
		pass   string
	}

	testCases := []struct {
		name  string
		input input
		want  bool
	}{
		{
			name: "Should return true",
			input: input{
				target: "https://github.com/adevinta/errors.git",
			},
			want: true,
		},
		{
			name: "Should return false",
			input: input{
				target: "https://github.com/adevinta/thisissomegiberishaweno.git",
			},
			want: false,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			isReachable := IsGitRepoReachable(tt.input.target, tt.input.user, tt.input.pass)
			if isReachable != tt.want {
				t.Fatalf("Expected Git repo '%s' reachability to be %v, but got %v",
					tt.input.target, tt.want, isReachable)
			}
		})
	}
}
