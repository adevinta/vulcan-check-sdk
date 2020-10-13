package agent

import (
	"time"

	"github.com/adevinta/vulcan-check-sdk/config"
	vulcanreport "github.com/adevinta/vulcan-report"
)

const (
	// StatusRunning represents the state for a check when running
	StatusRunning = "RUNNING"
	// StatusFinished represents the state after a check has finished
	StatusFinished = "FINISHED"
	// StatusAborted represents the state for a check when it has been aborted
	StatusAborted = "ABORTED"
	// StatusFailed represents the state for a check when has failed it's execution
	StatusFailed = "FAILED"
	// StatusInconclusive represents the state for a check when it could not be executed.
	// E.g.: Asset was unreachable.
	StatusInconclusive = "INCONCLUSIVE"
)

// State holds all the data that must be sent to the agent to communicate check status and report.
type State struct {
	Status   string              `json:"status,omitempty"`
	Progress float32             `json:"progress,omitempty"`
	Report   vulcanreport.Report `json:"report,omitempty"`
}

// NewReportFromConfig creates a new report initializing the fields that should be extracted from the config.
func NewReportFromConfig(c config.CheckConfig) vulcanreport.Report {
	return vulcanreport.Report{
		CheckData: vulcanreport.CheckData{
			CheckID:          c.CheckID,
			StartTime:        time.Now(),
			ChecktypeName:    c.CheckTypeName,
			ChecktypeVersion: c.CheckTypeVersion,
			Options:          c.Opts,
			Target:           c.Target,
		},
	}
}
