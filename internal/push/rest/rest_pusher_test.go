/*
Copyright 2019 Adevinta
*/

package rest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/kr/pretty"
	log "github.com/sirupsen/logrus"
)

func buildMockAgentRestAPI(checkID string) (*httptest.Server, *[]testPushMessage) {
	msgs := &[]testPushMessage{}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//check the id
		parts := strings.Split(r.URL.Path, "/")
		if len(parts) < 2 {
			return
		}
		if parts[len(parts)-2] != "check" {
			return
		}
		if parts[len(parts)-1] != checkID {
			return
		}
		decoder := json.NewDecoder(r.Body)
		msg := &testPushMessage{}
		err := decoder.Decode(msg)
		if err != nil {
			return
		}
		*msgs = append(*msgs, *msg)
		w.WriteHeader(http.StatusOK)

	})
	return httptest.NewServer(h), msgs
}

type updateStateTest struct {
	name string
	args updateStateTestArgs
	want []testPushMessage
}
type updateStateTestArgs struct {
	messages []testPushMessage
	checkID  string
}
type testPushMessage struct {
	Progress *float32
	Report   interface{}
	Status   *string
}

func TestUpdateState(t *testing.T) {
	tests := []updateStateTest{
		{
			name: "HappyPath",
			args: updateStateTestArgs{
				messages: []testPushMessage{
					testPushMessage{
						Progress: &(&struct{ x float32 }{0}).x,
						Report:   nil,
						Status:   &(&struct{ p string }{"RUNNING"}).p,
					},
				},
				checkID: "id",
			},
			want: []testPushMessage{
				testPushMessage{
					Progress: &(&struct{ x float32 }{0}).x,
					Report:   nil,
					Status:   &(&struct{ p string }{"RUNNING"}).p,
				},
			},
		},
	}
	for _, tt := range tests {
		tt := tt

		srv, gotMsgs := buildMockAgentRestAPI(tt.args.checkID)
		agentAddress, err := url.Parse(srv.URL)
		if err != nil {
			t.Error(err)
		}
		c := RestPusherConfig{
			AgentAddr: agentAddress.Hostname() + ":" + agentAddress.Port(),
		}
		l := log.New()
		l.Level = log.DebugLevel
		p := NewRestPusher(c, tt.args.checkID, l.WithField("test", tt.name))
		sendPushMessages(tt.args.messages, p)
		p.Shutdown()
		srv.Close()
		equals, want, got := comparePushMessages(*gotMsgs, tt.want)
		if !equals {
			t.Errorf("Error in test %s. \nWant: %s Got: %s.\n diffs %+v", tt.name, pretty.Sprint(want), pretty.Sprint(got), pretty.Diff(want, got))
		}

	}
}
func comparePushMessages(got []testPushMessage, want []testPushMessage) (equal bool, wantMsg testPushMessage, gotMsg testPushMessage) {
	equal = true
	for i, wm := range want {
		if i > len(got)-1 {
			equal = false
			wantMsg = wm
			break
		} else {
			gotMsg = got[i]
		}
		if !reflect.DeepEqual(wm, gotMsg) {
			wantMsg = wm
			equal = false
			break
		}
	}
	return
}

func sendPushMessages(messages []testPushMessage, pusher *RestPusher) {
	for _, m := range messages {
		pusher.UpdateState(m)
	}
}
