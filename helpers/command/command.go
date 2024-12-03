/*
Copyright 2019 Adevinta
*/

// Package command provides helpers to execute process and parse the output.
package command

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/adevinta/vulcan-check-sdk/internal/logging"
	log "github.com/sirupsen/logrus"
)

// ParseError reports a failure when trying to parse a process output.
type ParseError struct {
	// ProcessOutput output of the process that couldn't be parsed.
	ProcessOutput []byte

	// ProcessErrOutput output written by the process to the standard error.
	ProcessErrOutput []byte

	// ProcessStatus contains the process status returned by the execution of the process.
	ProcessStatus int

	// ParserError contains the error returned by the parser when trying to parse the result.
	ParserError string
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("ProcessOutput:\n%sParser error:%s\n", string(e.ProcessOutput), e.ParserError)
}

// ExecuteWithStdErr executes ExecuteWithEnvStdErr without env variables.
func ExecuteWithStdErr(ctx context.Context, logger *log.Entry, exe string, params ...string) ([]byte, []byte, int, error) {
	return ExecuteWithEnvStdErr(ctx, logger, nil, exe, params...)
}

// ExecuteWithEnvStdErr executes a 'command' in a new process
// Parameter command must contain a path to the command, or simply the command name if lookup in path is wanted.
// A nil value can be passed in parameters ctx and logger.
// Returns the outputs of the process written to the standard output and error, also returns the status code returned by the command.
// Note that, contrary to the standard library, the function doesn't return an error if the command execution returned a value different from 0.
// The new process where the command is executed inherits all the env vars of the current process.
func ExecuteWithEnvStdErr(ctx context.Context, logger *log.Entry, appendEnv []string, exe string, params ...string) ([]byte, []byte, int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if logger == nil {
		logger = logging.BuildRootLog("sdk.process")
	}
	logger = logger.WithFields(log.Fields{"cmd": exe, "params": params})
	var returnCode int
	cmd := exec.CommandContext(ctx, exe, params...) //nolint
	cmd.Env = os.Environ()
	if appendEnv != nil {
		cmd.Env = append(cmd.Env, appendEnv...)
	}
	logger.Info("Executing command")
	stdErr := &bytes.Buffer{}
	stdOut := &bytes.Buffer{}
	cmd.Stderr = stdErr
	cmd.Stdout = stdOut
	err := cmd.Run()
	output := stdOut.Bytes()
	errOutput := stdErr.Bytes()
	if err != nil {
		if exitE, ok := err.(*exec.ExitError); ok {
			// Cmd will only return an error of type exec.ExitError when the process returned a different value than zero,
			// at least in the unix family.
			// This tries to get the os dependant return code of the execute
			status, ok := exitE.ProcessState.Sys().(syscall.WaitStatus)
			if !ok {
				panic("Can not get exit code of the executed command, likely because running in an unsupported OS")
			}
			returnCode = status.ExitStatus()
		} else {
			return output, errOutput, 0, err
		}
	}
	return output, errOutput, returnCode, nil
}

// Execute executes ExecuteEnv without appendEnv variables.
func Execute(ctx context.Context, logger *log.Entry, exe string, params ...string) (output []byte, exitCode int, err error) {
	output, _, exitCode, err = ExecuteWithEnvStdErr(ctx, logger, nil, exe, params...)
	return
}

// Execute executes a 'command' in a new process
// Parameter command must contain a path to the command, or simply the command name if lookup in path is wanted.
// A nil value can be passed in parameters ctx and logger.
// Returns the outputs of the process written to the standard output and the status code returned by the command.
// Where there is an error,
// Note that, contrary to the standard library, the function doesn't return an error if the command execution returned a value different from 0.
// The new process where the command is executed inherits all the env vars of the current process.
func ExecuteEnv(ctx context.Context, logger *log.Entry, appendEnv []string, exe string, params ...string) (output []byte, exitCode int, err error) {
	output, _, exitCode, err = ExecuteWithEnvStdErr(ctx, logger, appendEnv, exe, params...)
	return
}

// ExecuteAndParseJSON executes ExecuteEnvAndParseJSON without appendEnv.
func ExecuteAndParseJSON(ctx context.Context, logger *log.Entry, result interface{}, exe string, params ...string) (int, error) {
	return ExecuteEnvAndParseJSON(ctx, logger, result, nil, exe, params...)
}

// ExecuteAndParseJSON executes a command, using the func Execute.
// After execution:
// returned error is nil and the param result contains the output parsed as json.
// (x)or
// error is not nil and the result doesn't contain the process output parsed as json.
// If an error is raised when trying to parse the process output, the function returns an error of type ParseError that contains the
// raw output of the process and the error returned by the json parser.
func ExecuteEnvAndParseJSON(ctx context.Context, logger *log.Entry, result interface{}, appendEnv []string, exe string, params ...string) (int, error) {
	jsonParser := func(output []byte, result interface{}) error {
		return json.Unmarshal(output, result)
	}
	return ExecuteAndParse(ctx, logger, jsonParser, result, exe, params...)
}

// ExecuteAndParseXML executes ExecuteEnvAndParseXML without appendEnv.
func ExecuteAndParseXML(ctx context.Context, logger *log.Entry, result interface{}, exe string, params ...string) (int, error) {
	return ExecuteEnvAndParseXML(ctx, logger, result, nil, exe, params...)
}

// ExecuteAndParseXML executes a command, using the func Execute.
// After execution:
// returned error is nil and the param result contains the output parsed as XML.
// (x)or
// error is not nil and the result doesn't contain the process output parsed as XML.
// If an error is raised when trying to parse the process output, the function returns an error of type ParseError that contains the
// the raw output of the process and the error returned by the json parser.
func ExecuteEnvAndParseXML(ctx context.Context, logger *log.Entry, result interface{}, appendEnv []string, exe string, params ...string) (int, error) {
	xmlParser := func(output []byte, result interface{}) error {
		return xml.Unmarshal(output, result)
	}
	return ExecuteEnvAndParse(ctx, logger, xmlParser, result, appendEnv, exe, params...)
}

// OutputParser represent a function that parses an output from process
type OutputParser func(output []byte, result interface{}) error

// ExecuteAndParse executes ExecuteEnvAndParse without appendEnv.
func ExecuteAndParse(ctx context.Context, logger *log.Entry, parser OutputParser, result interface{}, exe string, params ...string) (int, error) {
	return ExecuteEnvAndParse(ctx, logger, parser, result, nil, exe, params...)
}

// ExecuteAndParse executes a command, using the func Execute and parsing the output using the provided parser function.
// After execution:
// returned error is nil and the param result contains the output parsed as json.
// (x)or
// error is not nil and the result doesn't contain the result parsed as json.
// If an error is raised when trying to parse the output, the function returns an error of type ParseError that contains the
// the raw output of the process and the error returned by the json parser.
func ExecuteEnvAndParse(ctx context.Context, logger *log.Entry, parser OutputParser, result interface{}, appendEnv []string, exe string, params ...string) (int, error) {
	output, errOutput, status, err := ExecuteWithEnvStdErr(ctx, logger, appendEnv, exe, params...)
	if err != nil {
		return status, err
	}
	if err = parser(output, result); err != nil {
		return 0, &ParseError{
			ParserError:      err.Error(),
			ProcessOutput:    output,
			ProcessErrOutput: errOutput,
			ProcessStatus:    status,
		}
	}
	return status, nil
}
