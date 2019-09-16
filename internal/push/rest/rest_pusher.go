package rest

import (
	"fmt"
	"net/http"
	"sync"

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

// RestPusherConfig holds the configuration needed by a RestPusher to send push notifications to the agent
type RestPusherConfig struct {
	AgentAddr string
	BufferLen int
}

// RestPusher communicate state changes to agent by performing http calls
type RestPusher struct {
	logger     *log.Entry
	c          *resty.Client
	checkID    string
	msgsToSend chan pusherMsg
	finished   *sync.WaitGroup
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
func (p *RestPusher) UpdateState(state interface{}) {
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
func (p *RestPusher) Shutdown() {
	// Closing the pusher channel forces the pusher goroutine to send pending messages
	// and exit
	p.logger.Debug("Shutdown")
	close(p.msgsToSend)
	//Wait for pusher and queuer to finish
	p.finished.Wait()
	p.logger.Debug("Shutdown end")
}

// NewRestPusher Creates a new push component that can be used to inform the agent state changes
// of the check by using http rest calls.
func NewRestPusher(config RestPusherConfig, checkID string, logger *log.Entry) *RestPusher {
	logger.WithFields(log.Fields{"config": config, checkID: checkID}).Debug("Creating NewRestPusher with params")
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
	r := &RestPusher{
		c:          client,
		checkID:    checkID,
		msgsToSend: make(chan pusherMsg, config.BufferLen),
		logger:     logger,
		finished:   &sync.WaitGroup{},
	}
	// The wg only has to monitor pusher state
	r.finished.Add(1)
	goPusher(r.msgsToSend, client, logger.WithField("subcomponent", "gopusher"), r.finished)
	logger.Debug("Creating NewRestPusher created")
	return r
}

/* Pusher loops over buffered channel. Range only exits when the channel
is closed. */
func goPusher(c chan pusherMsg, client *resty.Client, l *log.Entry, wg *sync.WaitGroup) {
	go func() {
		// NOTE: race condition found #2
		// NOTE: race condition found #3
		l.Debug("goPusher running")
		defer wg.Done()
		for msg := range c {
			l.WithField("msg", msg.msg).Debug("Sending message")
			sendPushMsg(msg.msg, msg.id, client, l.WithField("sendPushMsg", ""))
		}
	}()
}

func sendPushMsg(msg interface{}, id string, c *resty.Client, l *log.Entry) {
	r := c.R()
	r.SetBody(msg)
	resp, err := r.Patch(id)
	if err != nil {
		l.WithError(err).Error("Error sending message to agent")
		retry()
		return
	}
	if resp.StatusCode() != http.StatusOK {
		err = fmt.Errorf("Error while sending msg to agent, received status %s, expected 200", resp.Status())
		l.WithError(err).Error("Error sending message to agent")
		retry()
		return
	}
	l.WithField("msg", msg).Debug("Message sent to the agent")
}

func retry() {
	// NOTE: Consider implementing retries and circuit breaking
}
