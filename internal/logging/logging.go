/*
Copyright 2021 Adevinta
*/

package logging

import (
	"github.com/adevinta/vulcan-check-sdk/config"
	log "github.com/sirupsen/logrus"
)

func getLogLevel(logLevel string) log.Level {
	if logLevel == "" {
		logLevel = "info"
	}
	level, err := log.ParseLevel(logLevel)
	if err != nil {
		level = log.ErrorLevel
	}
	return level
}

// BuildLoggerWithConfigAndFields Self explanatory
func BuildLoggerWithConfigAndFields(config config.LogConfig, fields log.Fields) *log.Entry {
	logger := log.StandardLogger()
	// NOTE: race condition found #2
	logger.Level = getLogLevel(config.LogLevel)

	// NOTE: race condition found #3
	logger.Formatter = &log.TextFormatter{
		FullTimestamp:    true,
		TimestampFormat:  "2006-01-02 15:04:05",
		DisableTimestamp: false,
	}
	// By now the only valid log formatter names are 'text and 'json'.
	// Anything different to 'json' will set the formatter to text.
	if config.LogFmt == "json" {
		logger.Formatter = &log.JSONFormatter{}

	}
	return logger.WithFields(fields)
}

func BuildRootLogWithName(component, checkName string) *log.Entry {
	return BuildRootLog(component).WithField("check", checkName)
}
func BuildRootLogWithNameAndConfig(component string, config *config.Config, checkName string) *log.Entry {
	return BuildRootLogWithConfig(component, config).WithField("check", checkName)
}

func BuildRootLogWithLevelFatal() *log.Entry {
	logger := log.StandardLogger()
	logger.SetLevel(1)
	return logger.WithField("vulcan-check-sdk", "local")
}

// BuildRootLogWithConfig builds a new log setted up according to a given config.
// This method is usefull for testing
func BuildRootLogWithConfig(component string, config *config.Config) *log.Entry {
	fields := log.Fields{
		"target":           config.Check.Target,
		"opts":             config.Check.Opts,
		"checkID":          config.Check.CheckID,
		"checkTypeName":    config.Check.CheckTypeName,
		"checkTypeVersion": config.Check.CheckTypeVersion,
		"component":        component}
	return BuildLoggerWithConfigAndFields(config.Log, fields)
}

// BuildRootLog builds a top level logger.
func BuildRootLog(component string) *log.Entry {
	config, err := config.BuildConfig()
	if err != nil {
		// Is there is an error in building config struct check can not run
		// so the only thing that can be done is panic!!
		panic(err)
	}
	return BuildRootLogWithConfig(component, config)
}
