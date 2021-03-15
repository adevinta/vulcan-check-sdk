/*
Copyright 2019 Adevinta
*/

package helpers

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		DualStack: true,
	}

	client.Transport.(*http.Transport).DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		addr = "127.0.0.1"
		addr = net.JoinHostPort(addr, port)
		return dialer.DialContext(ctx, network, addr)
	}
	os.Exit(m.Run())
}

type redirectMap map[string]string

func buildRedirector(m redirectMap) *httptest.Server {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current := r.Host
		host, port, err := net.SplitHostPort(current)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		next, ok := m[host]
		if !ok {
			return
		}

		addr := net.JoinHostPort(next, port)
		redirect := fmt.Sprintf("http://%s", addr)
		http.Redirect(w, r, redirect, http.StatusFound)
	})
	srv := httptest.NewServer(h)
	return srv
}

func TestIsRedirectingTo(t *testing.T) {
	type args struct {
		addr   string
		domain string
	}
	tests := []struct {
		name         string
		redirects    redirectMap
		args         args
		wantFinalLoc string
		want         bool
		wantErr      bool
	}{
		{
			name: "DetectsRedirectsToHostname",
			redirects: map[string]string{
				"test.example.com": "second.com",
				"second.com":       "test.okta.com",
			},
			args: args{
				domain: OKTADomain,
				addr:   "http://test.example.com",
			},
			want:         true,
			wantFinalLoc: "test.okta.com",
		},
		{
			name:      "DetectsNotRedirectingToHostname",
			redirects: map[string]string{},
			args: args{
				domain: OKTADomain,
				addr:   "http://test.example.com",
			},
			want:         false,
			wantFinalLoc: "test.example.com",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := buildRedirector(tt.redirects)
			addr := srv.URL
			addrURL, err := url.Parse(addr)
			if err != nil {
				t.Fatal(err)
				return
			}
			srvPort := addrURL.Port()
			addr = fmt.Sprintf("%s:%s", tt.args.addr, srvPort)
			got, gotLoc, err := IsRedirectingTo(addr, tt.args.domain)
			if (err != nil) != tt.wantErr {
				t.Errorf("IsRedirectingTo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("IsRedirectingTo() = %v, want %v", got, tt.want)
			}
			if gotLoc != tt.wantFinalLoc {
				t.Errorf("IsRedirectingTo() = %s, wantFinalLoc %s", gotLoc, tt.wantFinalLoc)
			}
		})
	}
}
