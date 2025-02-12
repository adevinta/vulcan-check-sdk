/*
Copyright 2019 Adevinta
*/

package check

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/adevinta/vulcan-check-sdk/internal/logging"
	log "github.com/sirupsen/logrus"
)

const (
	// NOTE: if we perform the conversion from number to time in here, then we can
	// avoid multiple calculations in the WaitForFile method
	retryTime = 100
)

// ProcessCheckRunner defines interface a check must implement in order to use the process helper.
type ProcessCheckRunner interface {
	Run(ctx context.Context) (pState *os.ProcessState, err error)
}

// ProcessChecker Declares the method a checker must implement in order to use processChecker.
type ProcessChecker interface {
	ProcessOutputChunk(chunk []byte) bool
}

// ProcessCheckerProcessOutputHandler handy adapter to specify a ProcessFinished
// method deifined in the ProcessChecker interface using a function.
type ProcessCheckerProcessOutputHandler func([]byte) bool

// ProcessOutputChunk handy adapter to specify a ProcessFinished
// method defined in the ProcessChecker interface using a function.
func (h ProcessCheckerProcessOutputHandler) ProcessOutputChunk(chunk []byte) bool {
	return (h(chunk))
}

// ProcessCheck simplifies developing a check that runs a process.
type ProcessCheck struct {
	checker    ProcessChecker
	executable string
	args       []string
	cmd        *exec.Cmd
	stdout     io.ReadCloser
	stderr     io.ReadCloser
	cancel     context.CancelFunc
	splitFunc  bufio.SplitFunc
	logger     *log.Entry
}

// Run starts the execution of the process.
func (p *ProcessCheck) Run(ctx context.Context) (pState *os.ProcessState, err error) {
	// In case a logger is in the context we override the default logger.
	if l, ok := ctx.Value("logger").(*log.Entry); ok {
		p.logger = l
	}

	childCtx, cancel := context.WithCancel(ctx)
	p.cancel = cancel
	p.logger.WithFields(log.Fields{"process_exec": p.executable, "process_params": p.args}).Info("Running process")
	p.cmd = exec.CommandContext(ctx, p.executable, p.args...) //nolint
	p.cmd.Env = os.Environ()
	p.logger.WithField("ProcessCmdEnv", p.cmd).Debug("Process environment set")
	p.stdout, err = p.cmd.StdoutPipe()
	if err != nil {
		p.logger.WithError(err).Error("Error trying to pipe stdout")
		return nil, err
	}
	p.stderr, err = p.cmd.StderrPipe()
	if err != nil {
		p.logger.WithError(err).Error("Error trying to pipe stderr")
		return nil, err
	}
	done := make(chan interface{})
	go p.readAndProcess(childCtx, &p.stdout, p.splitFunc, done)
	err = p.cmd.Start()
	if err != nil {
		p.logger.WithError(err).Error("Error starting process")
	}
	stderr, err := io.ReadAll(p.stderr)
	if err != nil {
		p.logger.WithError(err).Error("Error reading from process stderr")
	} else {
		if len(stderr) > 0 {
			p.logger.WithError(errors.New(string(stderr))).Error("Process stderr")
		}
	}

	<-done
	err = p.cmd.Wait()
	if err != nil {
		p.logger.WithError(err).Error("Error running process")
	} else {
		p.logger.WithField("ProcessStater", p.cmd.ProcessState).Info("Process finished")
	}
	return p.cmd.ProcessState, err
}

func (p *ProcessCheck) readAndProcess(ctx context.Context, src *io.ReadCloser,
	splitFunc bufio.SplitFunc, done chan interface{}) {
	p.logger.Debug("Start readAndProcess")
	defer func() {
		p.logger.Debug("Finished readAndProcess")
		done <- true
	}()
	scanner := bufio.NewScanner(*src)
	if splitFunc != nil {
		scanner.Split(splitFunc)
	}

	for scanner.Scan() {
		payload := scanner.Bytes()
		if err := ctx.Err(); err != nil {
			p.logger.WithError(err).Warn("Finished reading process output")
			return
		}
		p.logger.WithField("ProcessOutput", string(payload)).Debug("Process output read")
		cont := p.checker.ProcessOutputChunk(payload)
		// Processor can signal to not continue scanning by returning false.
		if !cont {
			p.logger.Info("Check signaled to stop processing output")
			return
		}
	}
}

// NewProcessChecker creates a new ProcessChecker that launch a process and optionally
// process the standard output spliting it in chunks defined by a custom bufio.SplitFunc.
func NewProcessChecker(executable string, args []string, split bufio.SplitFunc, checker ProcessChecker) ProcessCheckRunner {
	p := &ProcessCheck{}
	p.checker = checker
	if split != nil {
		p.splitFunc = split
	}
	p.executable = executable
	p.args = args
	// We don't have a safe way to know the check name from the helper
	// because check name is passed by the concrete check when calling NewCheck.
	p.logger = logging.BuildRootLog("sdk.process")
	return p
}

// WaitForFile  waits for a file to be created.
func WaitForFile(filepath string) (*os.File, error) {
	for {
		_, err := os.Stat(filepath)
		if os.IsNotExist(err) {
			time.Sleep(retryTime * time.Millisecond)
		} else if err != nil {
			return nil, err
		} else {
			break
		}
	}

	file, err := os.Open(filepath) //nolint
	if err != nil {
		return nil, err
	}

	return file, nil
}
