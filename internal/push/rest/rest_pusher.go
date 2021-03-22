/*
Copyright 2019 Adevinta
*/

package rest

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"

	log "github.com/sirupsen/logrus"
	"gopkg.in/resty.v1"
)

const (
	defaultPushMsgBufferLen = 10
	backPresureMsg          = "Push queue can't handle the pressure with current size, sdk is pushing back the pressure to the check."
	agentURLScheme          = "http"
	agentURLBase            = "check"
)

// ErrSendMessage is returned by the ShutDown function when there were any error
// trying to send a message to the agent.
var ErrSendMessage = errors.New("error sending message to the agent")

// PusherConfig holds the configuration needed by a RestPusher to send push notifications to the agent
type PusherConfig struct {
	AgentAddr string `toml:"AgentEndpoint"`
	BufferLen int    `toml:"BufferLen"`
}

// Pusher communicate state changes to agent by performing http calls
type Pusher struct {
	logger     *log.Entry
	c          *resty.Client
	checkID    string
	msgsToSend chan pusherMsg
	finished   chan error
}
type pusherMsg struct {
	id  string
	msg interface{}
}

// UpdateState sends a update state message to an agent by calling the
// rest api the agent must expose. Note that the function
// doesn't return any kind of error, that's because a Pusher is expected to handle
// error in sending push messages by it's own. WARN: Calling this method after calling ShutDown
// method will cause the program to panic.
func (p *Pusher) UpdateState(state interface{}) {
	l := p.logger.WithField("msg", state)
	l.Debug("Queuing message to be sent to the agent.")
	select {
	case p.msgsToSend <- pusherMsg{id: p.checkID, msg: state}:
		l.Debug("Msg queued")
	default:
		l.WithField("QueueSize", len(p.msgsToSend)).Warn(backPresureMsg)
		p.msgsToSend <- pusherMsg{id: p.checkID, msg: state}
	}
}

// Shutdown signals the pusher to stop accepting messages and wait for the pending messages to be send.
func (p *Pusher) Shutdown() error {
	// Closing the pusher channel forces the pusher goroutine to send pending messages
	// and exit.
	p.logger.Debug("Shutdown")
	close(p.msgsToSend)
	// Wait for pusher and queuer to finish.
	err := <-p.finished
	p.logger.Debug("Shutdown end")
	return err
}

// NewPusher Creates a new push component that can be used to inform the agent state changes
// of the check by using http rest calls.
func NewPusher(config PusherConfig, checkID string, logger *log.Entry) *Pusher {
	logger.WithFields(log.Fields{"config": config, checkID: checkID}).Debug("Creating new Pusher with params")
	hostURL := url.URL{
		Host:   config.AgentAddr,
		Scheme: agentURLScheme,
		Path:   agentURLBase,
	}
	logger.WithField("agent_url", hostURL.String()).Debug("Setting agent URL end point")
	client := resty.New()
	client.SetHostURL(hostURL.String())
	// Assign a default value to buffer len.
	if config.BufferLen == 0 {
		config.BufferLen = defaultPushMsgBufferLen
	}
	r := &Pusher{
		c:          client,
		checkID:    checkID,
		msgsToSend: make(chan pusherMsg, config.BufferLen),
		logger:     logger,
		finished:   make(chan error, 1),
	}
	// The wg only has to monitor pusher state
	goPusher(r.msgsToSend, client, logger.WithField("subcomponent", "gopusher"), r.finished)
	logger.Debug("Creating NewRestPusher created")
	return r
}

// Pusher loops over buffered channel. Range only exits when the channel is
// closed.
func goPusher(c chan pusherMsg, client *resty.Client, l *log.Entry, finished chan<- error) {
	go func() {
		var err error
		l.Debug("goPusher running")
		defer func() { finished <- err }()
		for msg := range c {
			l.WithField("msg", msg.msg).Debug("Sending message")
			err = sendPushMsg(msg.msg, msg.id, client, l.WithField("sendPushMsg", ""))
			// We don't stop reading from the channel intentionally even if there is
			// an error because we want to still try to send other messages to the agent
			// even knowing the check would be FAILED.
		}
	}()
}

func sendPushMsg(msg interface{}, id string, c *resty.Client, l *log.Entry) error {
	r := c.R()
	r.SetBody(msg)
	resp, err := r.Patch(id)
	if err != nil {
		l.WithError(err).Error("sending message to the agent")
		return fmt.Errorf("%w, %s", ErrSendMessage, err)
	}
	if resp.StatusCode() != http.StatusOK {
		err = fmt.Errorf("%w, received status %s, expected 200", ErrSendMessage, resp.Status())
		l.Error(err)
		return err
	}
	l.WithField("msg", msg).Debug("Message sent to the agent")
	return nil
}
