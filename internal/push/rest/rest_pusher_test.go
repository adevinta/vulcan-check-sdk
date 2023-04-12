/*
Copyright 2019 Adevinta
*/

package rest

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/kr/pretty"
	log "github.com/sirupsen/logrus"
)

func checkIDAccMsgsHandler(checkID string) mockHandler {
	h := func(w http.ResponseWriter, r *http.Request, msgs *[]testPushMessage) {
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
	}
	return h
}

type mockHandler func(w http.ResponseWriter, r *http.Request, msgs *[]testPushMessage)

func buildMockWithHandler(handler mockHandler, failures *int) (*httptest.Server, *[]testPushMessage) {
	msgs := &[]testPushMessage{}

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failures != nil && *failures > 0 {
			*failures = *failures - 1
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		handler(w, r, msgs)
	})
	return httptest.NewServer(h), msgs
}

type updateStateTest struct {
	name      string
	args      updateStateTestArgs
	want      []testPushMessage
	wantError error
}
type updateStateTestArgs struct {
	messages []testPushMessage
	checkID  string
	handler  mockHandler
	failures int
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
					{
						Progress: &(&struct{ x float32 }{0}).x,
						Report:   nil,
						Status:   &(&struct{ p string }{"RUNNING"}).p,
					},
				},
				checkID: "id",
				handler: checkIDAccMsgsHandler("id"),
			},
			want: []testPushMessage{
				{
					Progress: &(&struct{ x float32 }{0}).x,
					Report:   nil,
					Status:   &(&struct{ p string }{"RUNNING"}).p,
				},
			},
		},
		{
			name: "SucceedLastAttempt",
			args: updateStateTestArgs{
				messages: []testPushMessage{
					{
						Progress: &(&struct{ x float32 }{0}).x,
						Report:   nil,
						Status:   &(&struct{ p string }{"RUNNING"}).p,
					},
				},
				failures: retryCount - 1,
				checkID:  "id",
				handler:  checkIDAccMsgsHandler("id"),
			},
			want: []testPushMessage{
				{
					Progress: &(&struct{ x float32 }{0}).x,
					Report:   nil,
					Status:   &(&struct{ p string }{"RUNNING"}).p,
				},
			},
		},
		{
			name: "FailAllAttempts",
			args: updateStateTestArgs{
				messages: []testPushMessage{
					{
						Progress: &(&struct{ x float32 }{0}).x,
						Report:   nil,
						Status:   &(&struct{ p string }{"RUNNING"}).p,
					},
				},
				failures: retryCount,
				checkID:  "id",
				handler:  checkIDAccMsgsHandler("id"),
			},
			wantError: ErrSendMessage,
			want:      []testPushMessage{},
		},
		{
			name: "ShutdownsErrorWhenUnableToSendMsg",
			args: updateStateTestArgs{
				messages: []testPushMessage{
					{
						Progress: &(&struct{ x float32 }{0}).x,
						Report:   nil,
						Status:   &(&struct{ p string }{"RUNNING"}).p,
					},
				},
				checkID: "id",
				handler: func(w http.ResponseWriter, r *http.Request, msgs *[]testPushMessage) {
					w.WriteHeader(http.StatusBadRequest)
				},
			},
			wantError: ErrSendMessage,
			want:      []testPushMessage{},
		},
	}
	for _, tt := range tests {
		tt := tt
		srv, gotMsgs := buildMockWithHandler(tt.args.handler, &tt.args.failures)
		agentAddress, err := url.Parse(srv.URL)
		if err != nil {
			t.Error(err)
		}
		c := PusherConfig{
			AgentAddr: agentAddress.Hostname() + ":" + agentAddress.Port(),
		}
		l := log.New()
		l.Level = log.ErrorLevel
		p := NewPusher(c, tt.args.checkID, l.WithField("test", tt.name))
		sendPushMessages(tt.args.messages, p)
		err = p.Shutdown()
		srv.Close()
		if !errors.Is(err, tt.wantError) {
			t.Errorf("error!=wantError, %+v!=%+v", err, tt.wantError)
		}
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

func sendPushMessages(messages []testPushMessage, pusher *Pusher) {
	for _, m := range messages {
		pusher.UpdateState(m)
	}
}
