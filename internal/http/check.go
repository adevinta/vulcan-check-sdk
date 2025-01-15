/*
Copyright 2024 Adevinta
*/

package http

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	report "github.com/adevinta/vulcan-report"
	log "github.com/sirupsen/logrus"

	"github.com/adevinta/vulcan-check-sdk/agent"
	"github.com/adevinta/vulcan-check-sdk/config"
	"github.com/adevinta/vulcan-check-sdk/state"
)

// Check stores all the information needed to run a check locally.
type Check struct {
	Logger      *log.Entry
	Name        string
	checker     Checker
	config      *config.Config
	port        int
	server      *http.Server
	exitSignal  chan os.Signal // used to stopt the server either by an os Signal or by calling Shutdown()
	shuttedDown chan int       // used to wait for the server to shut down.
}

// ServeHTTP implements an HTTP POST handler that receives a JSON encoded job, and returns an
// agent.State JSON encoded response.
func (c *Check) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "error reading request body", http.StatusBadRequest)
		return
	}
	var job Job
	if err = json.Unmarshal(body, &job); err != nil {
		w.WriteHeader(500)
		return
	}

	logger := c.Logger.WithFields(log.Fields{
		"target":  job.Target,
		"checkID": job.CheckID,
	})
	ctx := context.WithValue(r.Context(), "logger", logger)
	checkState := &State{
		state: agent.State{
			Report: report.Report{
				CheckData: report.CheckData{
					CheckID:          job.CheckID,
					StartTime:        job.StartTime, // TODO: Is this correct or should be time.Now()
					ChecktypeName:    c.config.Check.CheckTypeName,
					ChecktypeVersion: c.config.Check.CheckTypeVersion,
					Options:          job.Options,
					Target:           job.Target,
				},
				ResultData: report.ResultData{},
			},
		},
	}

	runtimeState := state.State{
		ResultData:       &checkState.state.Report.ResultData,
		ProgressReporter: state.ProgressReporterHandler(checkState.SetProgress),
	}
	logger.WithField("opts", job.Options).Info("Starting check")
	err = c.checker.Run(ctx, job.Target, job.AssetType, job.Options, runtimeState)
	c.checker.CleanUp(ctx, job.Target, job.AssetType, job.Options)
	checkState.state.Report.CheckData.EndTime = time.Now()
	elapsedTime := time.Since(startTime)
	// If an error has been returned, we set the correct status.
	if err != nil {
		if errors.Is(err, context.Canceled) {
			checkState.state.Status = agent.StatusAborted
		} else if errors.Is(err, state.ErrAssetUnreachable) {
			checkState.state.Status = agent.StatusInconclusive
		} else if errors.Is(err, state.ErrNonPublicAsset) {
			checkState.state.Status = agent.StatusInconclusive
		} else {
			logger.WithError(err).Error("Error running check")
			checkState.state.Status = agent.StatusFailed
			checkState.state.Report.Error = err.Error()
		}
	} else {
		checkState.state.Status = agent.StatusFinished
	}
	checkState.state.Report.Status = checkState.state.Status

	logger.WithFields(log.Fields{"seconds": elapsedTime.Round(time.Millisecond * 100).Seconds(), "state": checkState.state.Status}).Info("Check finished")

	// Initialize sync point for the checker and the push state to be finished.
	out, err := json.Marshal(checkState.state)
	if err != nil {
		logger.WithError(err).Error("error marshalling the check state")
		http.Error(w, "error marshalling the check state", http.StatusInternalServerError)
		return
	}
	w.Write(out)
}

// RunAndServe implements the behavior needed by the sdk for a check runner to
// execute a check.
func (c *Check) RunAndServe() {
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if c.shuttedDown == nil {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`"OK"`))
		} else {
			// the server is shutting down
			http.Error(w, "shuttingDown", http.StatusServiceUnavailable)
		}
	})
	http.HandleFunc("/run", c.ServeHTTP)
	c.Logger.Info(fmt.Sprintf("Listening at %s", c.server.Addr))
	go func() {
		if err := c.server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			c.Logger.WithError(err).Error("Starting http server")
		}
		c.Logger.Info("Stopped serving new connections.")
		if c.shuttedDown != nil {
			c.Logger.Info("Notifying shuttedDown")
			c.shuttedDown <- 1
			c.Logger.Info("Notified shuttedDown")
		}
	}()

	s := <-c.exitSignal

	c.Logger.WithField("signal", s.String()).Info("Stopping server")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second) // TODO: Allow configure value.
	defer cancel()
	if err := c.server.Shutdown(ctx); err != nil {
		c.Logger.WithError(err).Error("Shutting down server")
	}
	c.Logger.Info("Finished RunAndServe.")
}

type Job struct {
	CheckID      string            `json:"check_id"`      // Required
	StartTime    time.Time         `json:"start_time"`    // Required
	Image        string            `json:"image"`         // Required
	Target       string            `json:"target"`        // Required
	Timeout      int               `json:"timeout"`       // Required
	AssetType    string            `json:"assettype"`     // Optional
	Options      string            `json:"options"`       // Optional
	RequiredVars []string          `json:"required_vars"` // Optional
	Metadata     map[string]string `json:"metadata"`      // Optional
	RunTime      int64
}

// Shutdown is needed to fulfil the check interface and in this case we are
// shutting down the http server and waiting
func (c *Check) Shutdown() error {
	// Send the exit signal to shutdown the server.
	c.exitSignal <- syscall.SIGTERM

	c.shuttedDown = make(chan int)
	// Wait for the server to shutdown.
	c.Logger.Info("Shutdown: waiting for shuttedDown")
	<-c.shuttedDown
	c.Logger.Info("Shutdown:shutted down")
	return nil
}

// NewCheck creates new check to be run from the command line without having an agent.
func NewCheck(name string, checker Checker, logger *log.Entry, conf *config.Config) *Check {
	c := &Check{
		Name:        name,
		Logger:      logger,
		config:      conf,
		exitSignal:  make(chan os.Signal, 1),
		port:        *conf.Port,
		shuttedDown: nil,
	}
	c.server = &http.Server{Addr: fmt.Sprintf(":%d", c.port)}
	signal.Notify(c.exitSignal, syscall.SIGINT, syscall.SIGTERM)
	c.checker = checker
	return c
}

// State holds the state for a local check.
type State struct {
	state agent.State
}

// Checker defines the shape a checker must have in order to be executed as vulcan-check.
type Checker interface {
	Run(ctx context.Context, target, assetType, opts string, state state.State) error
	CleanUp(ctx context.Context, target, assetType, opts string)
}

// SetProgress updates the progress of the state.
func (p *State) SetProgress(progress float32) {
	if p.state.Status == agent.StatusRunning && progress > p.state.Progress {
		p.state.Progress = progress
	}
}
