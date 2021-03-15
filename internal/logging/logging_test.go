/*
Copyright 2019 Adevinta
*/

package logging

import (
	"reflect"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/adevinta/vulcan-check-sdk/config"
)

type buildRootLogTestArgs struct {
	target           string
	opt              string
	checkID          string
	checkTypeName    string
	checkTypeVersion string
	logLevel         string
	formatter        string
}

type buildRootlogTest struct {
	name       string
	args       buildRootLogTestArgs
	wantFields map[string]string
}

func TestBuildRootLog(t *testing.T) {

	tests := []buildRootlogTest{
		{
			name: "SetGlobalFields",
			args: buildRootLogTestArgs{
				target:           "testTarget",
				opt:              "{\"option\":\"a-option\"}",
				checkID:          "id",
				checkTypeName:    "typeName",
				checkTypeVersion: "typeVersion",
				logLevel:         "info",
				formatter:        "text",
			},
			wantFields: map[string]string{
				"opts":             "{\"option\":\"a-option\"}",
				"target":           "testTarget",
				"checkID":          "id",
				"checkTypeName":    "typeName",
				"checkTypeVersion": "typeVersion",
				"component":        "sdk.test",
			},
		},
		{
			name: "SetDefaultFmtAndLevel",
			args: buildRootLogTestArgs{
				target:    "testTarget",
				opt:       "{\"option\":\"a-option\"}",
				checkID:   "id",
				logLevel:  "",
				formatter: "",
			},
			wantFields: map[string]string{
				"opts":             "{\"option\":\"a-option\"}",
				"target":           "testTarget",
				"checkID":          "id",
				"checkTypeName":    "",
				"checkTypeVersion": "",
				"component":        "sdk.test",
			},
		},
	}
	for _, tt := range tests {
		// Tests can not be executed in parallel because package level variables need to be assigned in each test,
		// because of that, there is no point in capturing the test struct in a local variable inside loop
		conf := &config.Config{
			Check: config.CheckConfig{
				Target:           tt.args.target,
				Opts:             tt.args.opt,
				CheckID:          tt.args.checkID,
				CheckTypeVersion: tt.args.checkTypeVersion,
				CheckTypeName:    tt.args.checkTypeName,
			},
			Log: config.LogConfig{
				LogFmt:   tt.args.formatter,
				LogLevel: tt.args.logLevel,
			},
		}

		lgot := BuildRootLogWithConfig("sdk.test", conf)
		got := extractFields(lgot)

		if !reflect.DeepEqual(got, tt.wantFields) {
			t.Errorf("Error executing test %s, got: %v want %v", tt.name, got, tt.wantFields)
		}

	}
}

func extractFields(out *log.Entry) map[string]string {
	data := out.Data
	result := make(map[string]string)
	for k, v := range data {
		result[k] = v.(string)
	}

	return result
}
