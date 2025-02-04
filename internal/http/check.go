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
	Logger  *log.Entry
	Name    string
	checker Checker
	config  *config.Config
	port    int

	exitSignal     chan os.Signal // used to stop the server via OS signal.
	shutdownSignal chan struct{}  // used to stop the server via Check.Shutdown call.
	serverErr      chan error     // used to handle server errors.
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
}

// handleRun implements an HTTP POST handler that receives a JSON encoded job, and returns an
// agent.State JSON encoded response.
func (c *Check) handleRun(w http.ResponseWriter, r *http.Request) {
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

	if job.StartTime.IsZero() {
		job.StartTime = time.Now()
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
					StartTime:        job.StartTime,
					ChecktypeName:    c.config.Check.CheckTypeName,
					ChecktypeVersion: c.config.Check.CheckTypeVersion,
					Options:          job.Options,
					Target:           job.Target,
				},
				ResultData: report.ResultData{},
			},
		},
	}

	var cancel context.CancelFunc
	if job.Timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, time.Duration(job.Timeout)*time.Second)
		defer cancel()
	}

	runtimeState := state.State{
		ResultData:       &checkState.state.Report.ResultData,
		ProgressReporter: state.ProgressReporterHandler(checkState.SetProgress),
	}
	logger.WithField("opts", job.Options).Info("Starting check")

	err = c.checker.Run(ctx, job.Target, job.AssetType, job.Options, runtimeState)
	c.checker.CleanUp(ctx, job.Target, job.AssetType, job.Options)

	// This allows to capture if the context was canceled (i.e. by the http request) or job.Timeout was reached.
	select {
	case <-ctx.Done():
		err = ctx.Err()
	default:
	}

	checkState.state.Report.CheckData.EndTime = time.Now()
	elapsedTime := time.Since(startTime)
	logger.WithField("elapsedTime", elapsedTime).Info("Check finished")

	if err != nil {
		logger.WithError(err).Error("Error running check")
		if errors.Is(err, context.DeadlineExceeded) {
			checkState.state.Status = agent.StatusAborted
		} else if errors.Is(err, context.Canceled) {
			checkState.state.Status = agent.StatusAborted
		} else if errors.Is(err, state.ErrAssetUnreachable) {
			checkState.state.Status = agent.StatusInconclusive
		} else if errors.Is(err, state.ErrNonPublicAsset) {
			checkState.state.Status = agent.StatusInconclusive
		} else {
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

// handleHealth implements an HTTP GET handler that returns a simple "OK" response.
func (c *Check) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`"OK"`))
}

// RunAndServe implements the behavior needed by the sdk for a check runner to
// execute a check.
func (c *Check) RunAndServe() {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", c.handleHealth)
	mux.HandleFunc("/run", c.handleRun)

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", c.port),
		Handler: mux,
	}

	c.Logger.Info(fmt.Sprintf("Listening at %s", server.Addr))
	go func() {
		if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			c.serverErr <- err
		} else {
			c.serverErr <- nil
		}
		close(c.serverErr)
	}()

	select {
	case err := <-c.serverErr:
		// No need to shutdow the server because it was not started.
		c.Logger.WithError(err).Error("ListenAndServe: Unable to start server")
		return
	case s := <-c.exitSignal:
		c.Logger.WithField("signal", s.String()).Info("Signal received")
	case <-c.shutdownSignal:
		c.Logger.Info("Shutdown request received")
	}

	c.Logger.Info("Stopping server")

	secs := 30
	if c.config.ShutdownTimeout != nil {
		secs = *c.config.ShutdownTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*time.Duration(secs))
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		c.Logger.WithError(err).Warn("Shutting down server")
	}

	c.Logger.Info("Finished RunAndServe")
}

// Shutdown is needed to fulfil the check interface and in this case
// we are shutting down the HTTP server and waiting.
func (c *Check) Shutdown() error {
	// Signal the server to shutdown.
	close(c.shutdownSignal)

	c.Logger.Info("Shutdown: waiting for server shutdown")
	return <-c.serverErr
}

// NewCheck creates new check to be run from the command line without having an agent.
func NewCheck(name string, checker Checker, logger *log.Entry, conf *config.Config) *Check {
	c := &Check{
		Name:           name,
		Logger:         logger,
		config:         conf,
		exitSignal:     make(chan os.Signal, 1),
		shutdownSignal: make(chan struct{}),
		port:           *conf.Port,
		serverErr:      make(chan error),
	}
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
