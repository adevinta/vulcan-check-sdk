/*
Copyright 2019 Adevinta
*/

package push

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/adevinta/vulcan-check-sdk/agent"
	"github.com/adevinta/vulcan-check-sdk/config"
	"github.com/adevinta/vulcan-check-sdk/helpers"
	"github.com/adevinta/vulcan-check-sdk/internal/logging"
	"github.com/adevinta/vulcan-check-sdk/internal/push/rest"
	"github.com/adevinta/vulcan-check-sdk/state"
	log "github.com/sirupsen/logrus"
)

// API defines the shape the api, that basically ony listens for events to abort the check,
// must satisfy in order to be used by the check. This is usefull to write unit tests because makes
// mocking dependencies of this component easier.
type checkAPI interface {
	Run()
	Shutdown() error
}

// Check stores the 'pieces' needed to run a checker.
type Check struct {
	Logger          *log.Entry
	Name            string
	api             checkAPI
	checkState      *State
	checker         Checker
	config          *config.Config
	cancel          context.CancelFunc
	ctx             context.Context
	checkerFinished *sync.WaitGroup
}

// Checker defines the shape a checker must have in order to be executed as vulcan-check.
type Checker interface {
	Run(ctx context.Context, target, assetType string, opts string, state state.State) error
	CleanUp(ctx context.Context, target, assetType, opts string)
}

// Abort recives the Abort message from the api that is listening for a term signal.
func (c *Check) Abort() (err error) {
	c.Logger.Warn("Aborting check")
	c.cancel()
	return
}

// Shutdown causes the Check to shutdown the API and the State provider. Also as
// a side effect, RunAndServe will also return.
func (c *Check) Shutdown() error {
	c.Logger.Debug("Shutting down check services")
	var err error
	// This ensures push state sent all the pending messages to the agent.
	if err = c.checkState.Shutdown(); err != nil {
		return err
	}
	// This ensures the goroutines for the api terminate gracefully.
	if err = c.api.Shutdown(); err != nil {
		return err
	}
	c.Logger.Debug("Check services shutted down")
	return err
}

// RunAndServe start running the check.
func (c *Check) RunAndServe() {
	// Initialize sync point for the checker and the push state to be finished.
	c.checkerFinished.Add(1)
	c.api.Run()
	c.checkState.SetStatusRunning()
	// Run the checker.
	go c.executeChecker()
	c.checkerFinished.Wait()
	err := c.Shutdown()
	if err != nil {
		c.Logger.WithError(err).Error("error finishing the check")
		// If we are here it's because either there is an error in the code of
		// the sdk or we were unable to send all the state updates to the agent,
		// in any case we panic.
		panic(err)
	}
}

func (c *Check) executeChecker() {
	var err error
	defer c.checkerFinished.Done()
	c.Logger.Info("Check start")
	startTime := time.Now()
	runtimeCheckState := state.State{
		ResultData:       &c.checkState.state.Report.ResultData,
		ProgressReporter: c.checkState,
	}

	// Do not run checks against hostnames that resolve to private IPs unless allowed.
	if ptrToBool(c.config.AllowPrivateIPs) || helpers.IsScannable(c.config.Check.Target) {
		err = c.checker.Run(c.ctx, c.config.Check.Target, c.config.Check.AssetType, c.config.Check.Opts, runtimeCheckState)
		// We always execute the cleanup function after the check has finished.
		// We use a fresh new context because here the origin context created for
		// running the check can be finalized.
		c.checker.CleanUp(context.Background(), c.config.Check.Target, c.config.Check.AssetType, c.config.Check.Opts)
	} else {
		err = state.ErrNonPublicAsset
	}

	c.checkState.SetEndTime(time.Now())
	elapsedTime := time.Since(startTime)
	// If an error has been returned, we set the correct status.
	if err != nil {
		if errors.Is(err, context.Canceled) {
			log.Info("Check aborted")
			c.checkState.SetStatusAborted()
		} else if errors.Is(err, state.ErrAssetUnreachable) {
			log.Info("Check asset is unreachable")
			c.checkState.SetStatusInconclusive()
		} else if errors.Is(err, state.ErrNonPublicAsset) {
			log.Info("Check asset is not public")
			c.checkState.SetStatusInconclusive()
		} else {
			c.Logger.WithError(err).Error("Error running check")
			c.checkState.SetStatusFailed(err)
		}
	} else {
		c.checkState.SetStatusFinished()
	}
	currentState := c.checkState.State()
	c.Logger.WithFields(log.Fields{"time": elapsedTime, "state": currentState}).Info("Check finished")
}

func ptrToBool(b *bool) bool {
	if b != nil {
		return *b
	}
	return false
}

// NewCheckWithConfig creates a check with a given configuration
func NewCheckWithConfig(name string, checker Checker, logger *log.Entry, conf *config.Config) *Check {
	c := &Check{
		Name:   name,
		Logger: logger,
		config: conf,
	}
	c.ctx, c.cancel = context.WithCancel(context.Background())
	pushLogger := logging.BuildRootLogWithNameAndConfig("sdk.restPusher", conf, name)
	pusher := rest.NewPusher(conf.Push, conf.Check.CheckID, pushLogger)
	r := agent.NewReportFromConfig(conf.Check)
	stateLogger := logging.BuildRootLogWithNameAndConfig("sdk.pushState", conf, name)
	agentState := agent.State{Report: r}
	c.checkState = newState(agentState, pusher, stateLogger)
	c.api = newPushAPI(logger, c)
	// Initialize a sync point for goroutines to wait for the checker run method
	// to be finished, for instance a call to an abort method should wait in this sync point.
	c.checkerFinished = &sync.WaitGroup{}
	c.checker = checker
	c.Logger.Debug("New check created")
	return c
}
