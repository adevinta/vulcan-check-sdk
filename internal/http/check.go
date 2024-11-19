/*
Copyright 2019 Adevinta
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

	"github.com/adevinta/vulcan-check-sdk/agent"
	"github.com/adevinta/vulcan-check-sdk/config"
	"github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
	log "github.com/sirupsen/logrus"
)

// Check stores all the information needed to run a check locally.
type Check struct {
	Logger     *log.Entry
	Name       string
	checker    Checker
	config     *config.Config
	port       int
	ctx        context.Context
	cancel     context.CancelFunc
	exitSignal chan os.Signal
}

// RunAndServe implements the behavior needed by the sdk for a check runner to
// execute a check.
func (c *Check) RunAndServe() {
	http.HandleFunc("/run", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "error reading request body", http.StatusBadRequest)
			return
		}
		var job Job
		err = json.Unmarshal(body, &job)
		if err != nil {
			w.WriteHeader(500)
			return
		}

		logger := c.Logger.WithFields(log.Fields{
			"target":  job.Target,
			"checkID": job.CheckID,
		})
		ctx := context.WithValue(c.ctx, "logger", logger)
		checkState := &State{
			state: agent.State{
				Report: report.Report{
					CheckData: report.CheckData{
						CheckID:          job.CheckID,
						StartTime:        time.Now(),
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
		c.checker.CleanUp(context.Background(), job.Target, job.AssetType, job.Options)
		checkState.state.Report.CheckData.EndTime = time.Now()
		elapsedTime := time.Since(checkState.state.Report.CheckData.StartTime)
		// If an error has been returned, we set the correct status.
		if err != nil {
			if errors.Is(err, context.Canceled) {
				checkState.state.Status = agent.StatusAborted
			} else if errors.Is(err, state.ErrAssetUnreachable) {
				checkState.state.Status = agent.StatusInconclusive
			} else if errors.Is(err, state.ErrNonPublicAsset) {
				checkState.state.Status = agent.StatusInconclusive
			} else {
				c.Logger.WithError(err).Error("Error running check")
				checkState.state.Status = agent.StatusFailed
				checkState.state.Report.Error = err.Error()
			}
		} else {
			checkState.state.Status = agent.StatusFinished
		}
		checkState.state.Report.Status = checkState.state.Status

		logger.WithField("seconds", elapsedTime.Seconds()).WithField("state", checkState.state.Status).Info("Check finished")

		// Initialize sync point for the checker and the push state to be finished.
		out, err := json.Marshal(checkState.state)
		if err != nil {
			logger.WithError(err).Error("error marshalling the check state")
			http.Error(w, "error marshalling the check state", http.StatusInternalServerError)
			return
		}
		w.Write(out)
	})

	addr := fmt.Sprintf(":%d", c.port)
	c.Logger.Info(fmt.Sprintf("Listening at %s", addr))
	log.Fatal(http.ListenAndServe(addr, nil))
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

// Shutdown is needed to fullfil the check interface but we don't need to do
// anything in this case.
func (c *Check) Shutdown() error {
	return nil
}

// NewCheck creates  new check to be run from the command line without having an agent.
func NewCheck(name string, checker Checker, logger *log.Entry, conf *config.Config) *Check {
	c := &Check{
		Name:       name,
		Logger:     logger,
		config:     conf,
		exitSignal: make(chan os.Signal, 1),
		port:       conf.Port,
	}
	signal.Notify(c.exitSignal, syscall.SIGINT, syscall.SIGTERM)
	c.ctx, c.cancel = context.WithCancel(context.Background())
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

func (p *State) SetProgress(progress float32) {
	if p.state.Status == agent.StatusRunning && progress > p.state.Progress {
		p.state.Progress = progress
	}
}
