package push

import (
	"time"

	"github.com/adevinta/vulcan-check-sdk/agent"
	log "github.com/sirupsen/logrus"
)

// StatePusher defines the shape a pusher communications component must satisfy in order to be used
// by the PushState. This is usefull to write unit tests because makes mocking dependencies of this component easier.
type StatePusher interface {
	UpdateState(state interface{})
	Shutdown()
}

// State implements a state that uses a pusher to send state changes to an agent. This implementation is  NOT SYNCHRONIZED, that is not
// not suitable to be be used by multiple goroutines
type State struct {
	pusher StatePusher
	logger *log.Entry
	state  agent.State
}

// State returns current state.
func (p *State) State() (state *agent.State) {
	return &p.state

}

// SetStartTime sets the time when the check started.
// This method does not send notification to the agent.
func (p *State) SetStartTime(t time.Time) {
	p.state.Report.StartTime = t

}

// SetEndTime sets the time when the check has finished.
// This method does not send notification to the agent.
func (p *State) SetEndTime(t time.Time) {
	p.state.Report.EndTime = t

}

// SetProgress sets the progress of the current state, but only if
// the status is agent.StatusRunning and progress has increased.
// This method sends a notification to the agent.
func (p *State) SetProgress(progress float32) {
	if p.state.Status == agent.StatusRunning && progress > p.state.Progress {
		p.state.Progress = progress
		p.pusher.UpdateState(p.state)
	}
}

// SetStatusRunning sets the state of the current check to Running and the progress to 1.0.
func (p *State) SetStatusRunning() {
	p.state.Status = agent.StatusRunning
	p.state.Progress = 0.0
	p.state.Report.Status = string(agent.StatusRunning)
	p.pusher.UpdateState(p.state)
}

// SetStatusAborted sets the state of the current check to Running and the progress to 1.0.
// This method sends a notification to the agent.
func (p *State) SetStatusAborted() {
	p.state.Status = agent.StatusAborted
	p.state.Progress = 1.0
	p.state.Report.Status = agent.StatusAborted
	p.pusher.UpdateState(p.state)
}

// SetStatusFinished sets the state of the current check to Running and the progress to 1.0.
// This method sends a notification to the agent.
func (p *State) SetStatusFinished() {
	p.state.Status = agent.StatusFinished
	p.state.Progress = 1.0
	p.state.Report.Status = agent.StatusFinished
	p.pusher.UpdateState(p.state)

}

// SetStatusFailed sets the state of the current check to Running and the progress to 1.0
// This method sends a notification to the agent.
func (p *State) SetStatusFailed(err error) {
	p.state.Status = agent.StatusFailed
	p.state.Progress = 1.0
	p.state.Report.Error = err.Error()
	p.state.Report.Status = agent.StatusFailed
	p.pusher.UpdateState(p.state)
}

// SetStatusUnreachable sets the state of the current check to Unreachable and the progress to 1.0
// This method sends a notification to the agent.
func (p *State) SetStatusUnreachable() {
	p.state.Status = agent.StatusUnreachable
	p.state.Progress = 1.0
	p.state.Report.Status = agent.StatusUnreachable
	p.pusher.UpdateState(p.state)
}

// Shutdown the state gracefully.
func (p *State) Shutdown() error {
	p.pusher.Shutdown()
	return nil
}

// newState creates a new synchronized State.
func newState(s agent.State, p StatePusher, logger *log.Entry) *State {
	state := &State{
		state:  s,
		pusher: p,
		logger: logger,
	}
	return state
}
