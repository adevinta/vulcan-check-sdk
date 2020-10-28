package helpers

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go/aws/credentials"
)

func TestTarget_IsScannable(t *testing.T) {
	tests := []struct {
		name       string
		target     string
		targetType string
		want       bool
	}{
		{
			name:       "ValidCIDR",
			target:     "1.1.1.1/24",
			targetType: ipRangeType,
			want:       true,
		},
		{
			name:       "ValidIP",
			target:     "1.1.1.1",
			targetType: ipType,
			want:       true,
		},
		{
			name:       "ValidHostname",
			target:     "www.google.com",
			targetType: hostnameType,
			want:       true,
		},
		{
			name:       "ValidURL",
			target:     "http://www.google.com",
			targetType: webAddrsType,
			want:       true,
		},
		{
			name:       "ValidDomainName",
			target:     "google.com",
			targetType: domainType,
			want:       true,
		},
		{
			name:       "ValidDockerImage",
			target:     "registry.hub.docker.com/library/alpine:latest",
			targetType: dockerImgType,
			want:       true,
		},
		{
			name:       "ValidAWSAccount",
			target:     "arn:aws:iam::111111111111:root",
			targetType: awsAccType,
			want:       true,
		},
		{
			name:       "HostnameNotResolve",
			target:     "test.example.com",
			targetType: hostnameType,
			want:       true,
		},
		{
			name:       "PrivateCIDR",
			target:     "127.0.0.1/24",
			targetType: ipRangeType,
			want:       false,
		},
		{
			name:       "PrivateIP",
			target:     "127.0.0.1",
			targetType: ipType,
			want:       false,
		},
		{
			name:       "HostnameResolvesPrivate",
			target:     "localhost",
			targetType: hostnameType,
			want:       false,
		},
		{
			name:       "URLResolvesPrivate",
			target:     "https://localhost",
			targetType: webAddrsType,
			want:       false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := IsScannable(tt.target, tt.targetType)
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
			target: "http://www.example.com",
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
	type input struct {
		accID string
		// assumeRoleURL string // Set by httptest srv
		role string
	}

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
		_, okAcc := assumeRoleReq["account_id"]
		_, okRole := assumeRoleReq["role"]
		if !okAcc || !okRole {
			w.WriteHeader(http.StatusBadRequest)
			return
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
				accID: "accID1",
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
				accID: "accID2",
				role:  "role2",
			},
			srvHandler: koHandler,
			want:       false,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			testSrv := httptest.NewServer(tt.srvHandler)

			isReachable, creds, err := IsAWSAccReachable(tt.input.accID, testSrv.URL, tt.input.role)
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

func TestTarget_IsDockerImgReachable(t *testing.T) {
	testCases := []struct {
		name   string
		target string
		want   bool
	}{
		{
			name:   "Should return true, image is reachable",
			target: "registry.hub.docker.com/library/hello-world:latest",
			want:   true,
		},
		{
			name:   "Should return false, image is NOT reachable",
			target: "registry.hub.docker.com/thisissomegiberishaweioanwe/giberishaweoij:latest",
			want:   false,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			isReachable, err := IsDockerImgReachable(tt.target, "", "", "")
			if err != nil {
				t.Fatalf("Expected no error but got: %v", err)
			}
			if isReachable != tt.want {
				t.Fatalf("Expected Docker img '%s' reachability to be %v but was %v",
					tt.target, tt.want, isReachable)
			}
		})
	}
}

func TestTarget_IsGitRepoReachable(t *testing.T) {
	type input struct {
		target  string
		user    string
		pass    string
		outPath string
		depth   int
		clean   bool
	}

	testCases := []struct {
		name  string
		input input
		want  bool
	}{
		{
			name: "Should return true and clean",
			input: input{
				target:  "https://github.com/adevinta/errors",
				outPath: "/tmp/helpersTest/target/git1",
				depth:   1,
				clean:   true,
			},
			want: true,
		},
		{
			name: "Should return true and NOT clean",
			input: input{
				target:  "https://github.com/adevinta/errors",
				outPath: "/tmp/helpersTest/target/git2",
				depth:   1,
				clean:   false,
			},
			want: true,
		},
		{
			name: "Should return false",
			input: input{
				target:  "https://github.com/adevinta/thisissomegiberishaweno",
				outPath: "/tmp/helpersTest/target/git3",
				depth:   1,
				clean:   true,
			},
			want: false,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			isReachable, err := IsGitRepoReachable(tt.input.target, tt.input.user, tt.input.pass,
				tt.input.outPath, tt.input.depth, tt.input.clean)
			if err != nil {
				t.Fatalf("Expected no error but got: %v", err)
			}
			if isReachable != tt.want {
				t.Fatalf("Expected Git repo '%s' reachability to be %v, but got %v",
					tt.input.target, tt.want, isReachable)
			}
			if isReachable {
				_, err = os.Stat(tt.input.outPath)
				dirExists := !os.IsNotExist(err)

				if tt.input.clean && dirExists {
					t.Fatalf("Expected outPath dir to not exist after cleanup, but it does")
				}
				if !tt.input.clean && !dirExists {
					t.Fatalf("Expected outPath dir to still exist, but was cleaned up")
				}
			}
		})
	}
}
