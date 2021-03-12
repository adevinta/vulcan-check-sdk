/*
Copyright 2021 Adevinta
*/

package state

import (
	"errors"

	report "github.com/adevinta/vulcan-report"
)

var (
	// ErrAssetUnreachable indicates that the asset to be scanned is not reachable.
	ErrAssetUnreachable = errors.New("Asset is Unreachable")
)

// State defines the fields and function a check must use to generare a result
// and inform about the progress of the its execution.
// The type is not intended be instanciated by external packages, the instances to be used will be provided by the sdk.
type State struct {
	ProgressReporter
	*report.ResultData
}

// ProgressReporter is intended to be used by the sdk.
type ProgressReporter interface {
	SetProgress(float32)
}

// ProgressReporterHandler allows to define a ProgressReporter using a function
// instead of  a struct.
type ProgressReporterHandler func(progress float32)

// SetProgress implements the required ProgressReporter interface from a
// function.
func (p ProgressReporterHandler) SetProgress(progress float32) {
	p(progress)
}
