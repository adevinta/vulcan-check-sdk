/*
Copyright 2021 Adevinta
*/

package tools

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

	"github.com/adevinta/vulcan-check-sdk/agent"
)

// Reporter represents a "fake" agent suitable to be used in tests.
type Reporter struct {
	srv  *httptest.Server
	URL  string
	Msgs chan agent.State
}

// Stop the underlaying HTTPServer and closes the channel used to receive messages.
func (r *Reporter) Stop() {
	r.srv.Close()
	// The call above only returns when all pending requests are processed, thus is safe to close the channel.
	close(r.Msgs)

}

// NewReporter creates a minimal http server that receives and sends to a channel the messages received
// by a check with a given checkID. Should be only used for test pourposes.
func NewReporter(checkID string) *Reporter {
	c := make(chan agent.State, 10)
	srv := buildHTTPServer(checkID, c)
	agentAddress, _ := url.Parse(srv.URL) //nolint
	r := &Reporter{
		Msgs: c,
		srv:  srv,
		URL:  agentAddress.Hostname() + ":" + agentAddress.Port(),
	}
	return r
}

func buildHTTPServer(checkID string, msgs chan<- agent.State) (s *httptest.Server) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check the the id if the check is present.
		parts := strings.Split(r.URL.Path, "/")
		if len(parts) < 1 {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if parts[len(parts)-1] != checkID {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		decoder := json.NewDecoder(r.Body)
		msg := agent.State{}
		err := decoder.Decode(&msg)
		if err != nil {
			w.WriteHeader(http.StatusNotAcceptable)
			return
		}
		msgs <- msg
		w.WriteHeader(http.StatusOK)
	})
	return httptest.NewServer(h)
}
