package check

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/adevinta/vulcan-check-sdk/agent"
	"github.com/adevinta/vulcan-check-sdk/config"
	"github.com/adevinta/vulcan-check-sdk/internal/local"
	"github.com/adevinta/vulcan-check-sdk/internal/logging"
	"github.com/adevinta/vulcan-check-sdk/internal/push"
	"github.com/adevinta/vulcan-check-sdk/state"
	"github.com/adevinta/vulcan-check-sdk/tools"
	"github.com/kr/pretty"
	log "github.com/sirupsen/logrus"
)

var (
	testMode     bool
	runTarget    string
	options      string
	json         bool
	cachedConfig *config.Config

	// VoidCheckerCleanUp defines a clean up function that does nothing this is usefull
	// for checks that don't need to do any cleanup when the check finalizes.
	VoidCheckerCleanUp = func(ctx context.Context, target, targetType, opts string) {}
)

func mustParseFlags() {
	set := flag.CommandLine
	if flag.Lookup("test.v") == nil {
		set = flag.NewFlagSet("", flag.ExitOnError)
	}
	set.BoolVar(&testMode, "t", false, "executes a check in test mode locally")
	set.StringVar(&runTarget, "r", "", "executes a check from the command line using the target specified in this flag")
	set.StringVar(&options, "o", "", "specifies the options to pass to the check, applies only when using the r flag")
	set.BoolVar(&json, "j", false, "sets the output format to json, applies only when using the r flag")
	_ = set.Parse(os.Args[1:]) // nolint
}

// Check defines a check as seen by a checker, that is a concrete check implementor.
type Check interface {
	RunAndServe()
	Shutdown() error
}

// Checker defines the shape a checker must have in order to be executed as vulcan-check.
type Checker interface {
	Run(ctx context.Context, target, targetType string, opts string, state state.State) error
	CleanUp(ctx context.Context, target, targetType, opts string)
}

// CheckerHandleRun func type to specify a Run handler function for a checker.
type CheckerHandleRun func(ctx context.Context, target, targetType string, opts string, state state.State) error

// Run is used as adapter to satisfy the method with same name in interface Checker.
func (handler CheckerHandleRun) Run(ctx context.Context, target, targetType string, opts string, state state.State) error {
	return (handler(ctx, target, targetType, opts, state))
}

// CheckerHandleCleanUp func type to specify a CleanUp handler function for a checker.
type CheckerHandleCleanUp func(ctx context.Context, target, targetType, opts string)

// CleanUp is used as adapter to satisfy the method with same name in interface Checker.
func (handler CheckerHandleCleanUp) CleanUp(ctx context.Context, target, targetType, opts string) {
	(handler(ctx, target, targetType, opts))
}

// NewCheckFromHandlerWithCleanUp creates a new check given a checker run handler.
func NewCheckFromHandlerWithCleanUp(name string, run CheckerHandleRun, cleanUp CheckerHandleCleanUp) Check {
	checkerAdapter := struct {
		CheckerHandleRun
		CheckerHandleCleanUp
	}{
		run,
		cleanUp,
	}
	return NewCheck(name, checkerAdapter)
}

// NewCheckFromHandler creates a new check given a checker run handler.
func NewCheckFromHandler(name string, run CheckerHandleRun) Check {
	checkerAdapter := struct {
		CheckerHandleRun
		CheckerHandleCleanUp
	}{
		run,
		VoidCheckerCleanUp,
	}
	return NewCheck(name, checkerAdapter)
}

// NewCheck creates a check given a Checker.
func NewCheck(name string, checker Checker) Check {
	mustParseFlags()
	conf, err := config.BuildConfig()
	if err != nil {
		// In case config can not be built the the only thing we can do is to raise a panic!!
		panic(err)
	}

	var c Check
	logger := logging.BuildRootLogWithNameAndConfig("check", conf, name)
	logger.WithFields(log.Fields{"config": conf}).Debug("Building check with configuration")

	b := true
	if testMode {
		logger.WithField("testMode", testMode).Debug("Test mode")

		// In test mode allow scanning private IPs by default.
		if conf.AllowPrivateIPs == nil {
			conf.AllowPrivateIPs = &b
		}
		c = newCheckWithTestAgent(name, checker, logger, conf)
	} else if runTarget != "" {
		// In run mode allow scanning private IPs by default.
		if conf.AllowPrivateIPs == nil {
			conf.AllowPrivateIPs = &b
		}

		conf.Check.Target = runTarget
		conf.Check.Opts = options
		c = newLocalCheck(name, checker, logger, conf, json)
	} else {
		logger.Debug("Push mode")
		c = push.NewCheckWithConfig(name, checker, logger, conf)
	}
	cachedConfig = conf
	return c
}

// NewCheckLog creates a log suitable to be used by a check
func NewCheckLog(name string) *log.Entry {
	var l *log.Entry
	if cachedConfig == nil {
		l = logging.BuildRootLog(name)
	} else {
		l = logging.BuildRootLogWithConfig(name, cachedConfig)
	}
	return (l)
}

// NewCheckFromHandlerWithConfig creates a new check from run and abort handlers using provided config.
func NewCheckFromHandlerWithConfig(name string, conf *config.Config, run CheckerHandleRun) Check {
	checkerAdapter := struct {
		CheckerHandleRun
		CheckerHandleCleanUp
	}{
		run,
		VoidCheckerCleanUp,
	}
	var c Check
	logger := logging.BuildRootLogWithNameAndConfig("check", conf, name)
	c = push.NewCheckWithConfig(name, checkerAdapter, logger, conf)
	cachedConfig = conf
	return c
}

// testCheck is used only for test pourposes when a check is invoked with -t flag to run it with a test agent.
type testCheck struct {
	c      Check
	r      *tools.Reporter
	logger *log.Entry
	w      sync.WaitGroup
	status agent.State
}

func (t *testCheck) RunAndServe() {
	t.w.Add(1)
	go t.readMsgs()
	t.c.RunAndServe()
	t.r.Stop()
	// Wait all messages to be read.
	t.w.Wait()
	// Write status to the output
	fmt.Print(pretty.Sprint(t.status))

}

func (t *testCheck) readMsgs() {
	// Just read messages to simulate the agent.
	var msg agent.State
	for msg = range t.r.Msgs {
	}
	msg.Report.EndTime = time.Time{}
	msg.Report.StartTime = time.Time{}
	t.status = msg
	t.w.Done()
}

func (t *testCheck) Shutdown() error {
	err := t.c.Shutdown()
	// Always stop the test agent, no mather if an error was returned shutting down the check.
	t.r.Stop()
	return err
}

func newCheckWithTestAgent(name string, c Checker, logger *log.Entry, conf *config.Config) Check {
	if conf.Check.CheckID == "" {
		// Set a default checkID, this is needed for the test agent.
		conf.Check.CheckID = "testCheckID"
	}
	// Set the Required env vars from the local.toml file.
	for n, v := range conf.RequiredVars {
		os.Setenv(n, v)
	}
	r := tools.NewReporter(conf.Check.CheckID)
	conf.Push.AgentAddr = r.URL
	logger.WithField("URL", r.URL).Warn("Building test agent listening on URL")
	check := push.NewCheckWithConfig(name, c, logger, conf)
	t := &testCheck{
		c:      check,
		r:      r,
		logger: logger,
	}
	return t
}

func newLocalCheck(name string, checker Checker, logger *log.Entry, conf *config.Config, json bool) Check {
	check := local.NewCheck(name, checker, logger, conf, json)
	return check
}
