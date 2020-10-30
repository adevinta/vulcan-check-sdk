package local

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/adevinta/vulcan-check-sdk/agent"
	"github.com/adevinta/vulcan-check-sdk/config"
	astate "github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
	log "github.com/sirupsen/logrus"
)

// Check stores all the information needed to run a check locally.
type Check struct {
	Logger     *log.Entry
	Name       string
	checkState *State
	checker    Checker
	config     *config.Config
	formatter  resultFormatter
	ctx        context.Context
	cancel     context.CancelFunc
	done       chan error
	exitSignal chan os.Signal
}

// RunAndServe implements the behavior needed by the sdk for a check runner to
// execute a check.
func (c *Check) RunAndServe() {
	runtimeState := astate.State{
		ResultData:       &c.checkState.state.Report.ResultData,
		ProgressReporter: astate.ProgressReporterHandler(c.formatter.progress),
	}
	go func() {
		c.done <- c.checker.Run(c.ctx, c.config.Check.Target, c.config.Check.AssetType, c.config.Check.Opts, runtimeState)
	}()
	var err error
LOOP:
	for {
		select {
		case <-c.exitSignal:
			c.cancel()
			c.exitSignal = nil
		case err = <-c.done:
			break LOOP
		}
	}
	c.checker.CleanUp(context.Background(), c.config.Check.Target, c.config.Check.AssetType, c.config.Check.Opts)
	c.formatter.result(err, runtimeState.ResultData)
	if err != nil {
		os.Exit(0)
	}
	os.Exit(1)
}

// Shutdown is needed to fullfil the check interface but we don't need to do
// anything in this case.
func (c *Check) Shutdown() error {
	return nil
}

// NewCheck creates  new check to be run from the command line without having an agent.
func NewCheck(name string, checker Checker, logger *log.Entry, conf *config.Config, json bool) *Check {
	var formatter resultFormatter = &textFmt{
		Stdout: os.Stdout,
		Stderr: os.Stderr,
	}
	if json {
		formatter = &jsonFmt{
			Stderr: os.Stderr,
			Stdout: os.Stdout,
		}
	}
	c := &Check{
		Name:       name,
		Logger:     logger,
		config:     conf,
		formatter:  formatter,
		done:       make(chan error, 1),
		exitSignal: make(chan os.Signal, 1),
	}
	signal.Notify(c.exitSignal, syscall.SIGINT, syscall.SIGTERM)
	c.ctx, c.cancel = context.WithCancel(context.Background())
	c.checker = checker
	r := agent.NewReportFromConfig(conf.Check)
	agentState := agent.State{Report: r}
	c.checkState = &State{state: agentState}
	return c
}

// State holds the state for a local check.
type State struct {
	state agent.State
}

// Checker defines the shape a checker must have in order to be executed as vulcan-check.
type Checker interface {
	Run(ctx context.Context, target, targetType, opts string, state astate.State) error
	CleanUp(ctx context.Context, target, targetType, opts string)
}

type resultFormatter interface {
	progress(float32)
	result(error, *report.ResultData)
}
