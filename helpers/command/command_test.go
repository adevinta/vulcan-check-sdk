/*
Copyright 2019 Adevinta
*/

package command

import (
	"context"
	"reflect"
	"testing"

	log "github.com/sirupsen/logrus"
)

type executeArgs struct {
	ctx    context.Context
	logger *log.Entry
	exe    string
	args   []string
}
type executeWant struct {
	output   string
	exitCode int
}
type executeTest struct {
	name      string
	args      executeArgs
	want      executeWant
	wantError bool
}

func TestExecute(t *testing.T) {

	tests := []executeTest{
		{
			name: "HappyPath",
			args: executeArgs{
				exe:    "echo",
				args:   []string{"hello"},
				ctx:    nil,
				logger: nil,
			},
			want: executeWant{
				exitCode: 0,
				output:   "hello\n",
			},
		},
		{
			name: "HappyPathNonZeroReturnCode",
			args: executeArgs{
				exe:    "sh",
				args:   []string{"-c", "echo 'hello';exit 25"},
				ctx:    nil,
				logger: nil,
			},
			want: executeWant{
				exitCode: 25,
				output:   "hello\n",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := executeWant{}
			output, exitCode, err := Execute(tt.args.ctx, tt.args.logger, tt.args.exe, tt.args.args...)
			got.exitCode = exitCode
			got.output = string(output)
			if (err != nil) != tt.wantError {
				t.Errorf("Execute() error = %v, wantErr %v", err, tt.wantError)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Execute test error. Got = ! want. got = %+v, want = %+v", got.output, tt.want)
			}
		})
	}
}

type executeJSONArgs struct {
	ctx    context.Context
	logger *log.Entry
	exe    string
	args   []string
	result interface{}
}

type executeJSONWant struct {
	result   interface{}
	exitCode int
}
type executeJSONTest struct {
	name        string
	args        executeJSONArgs
	want        executeJSONWant
	wantError   bool
	errorWanted *ParseError
}

type dummy struct {
	FieldA string `json:"field_a"`
	FieldB int    `json:"field_b"`
}

func TestExecuteJSON(t *testing.T) {
	tests := []executeJSONTest{
		{
			name: "HappyPath",
			args: executeJSONArgs{
				exe:    "echo",
				args:   []string{"{\"field_a\":\"may the force\",\"field_b\":1}"},
				ctx:    nil,
				logger: nil,
				result: &dummy{},
			},
			want: executeJSONWant{
				exitCode: 0,
				result: &dummy{
					FieldA: "may the force",
					FieldB: 1,
				},
			},
		},
		{
			name: "ReportsOutputInParseError",
			args: executeJSONArgs{
				exe:    "echo",
				args:   []string{"{\"field_a\"::1}"},
				ctx:    nil,
				logger: nil,
				result: &dummy{},
			},
			wantError: true,
			errorWanted: &ParseError{
				ParserError:   "invalid character ':' looking for beginning of value",
				ProcessOutput: []byte("{\"field_a\"::1}\n"),
				ProcessStatus: 0,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := executeJSONWant{}
			exitCode, err := ExecuteAndParseJSON(tt.args.ctx, tt.args.logger, tt.args.result, tt.args.exe, tt.args.args...)
			if err != nil {
				if tt.wantError {
					if err.Error() != tt.errorWanted.Error() {
						t.Fatalf("got error and want error are different. err:%s,wantErr:%s", err, tt.errorWanted)
					}
					return
				}
				t.Fatal(err)
			}
			got.exitCode = exitCode
			got.result = tt.args.result
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Got = ! want. got = %+v, want = %+v", got, tt.want)
			}
		})
	}
}
