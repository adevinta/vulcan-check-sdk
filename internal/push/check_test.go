package push

import (
	"context"
	"syscall"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/kr/pretty"
	log "github.com/sirupsen/logrus"

	"github.com/adevinta/vulcan-check-sdk/agent"
	"github.com/adevinta/vulcan-check-sdk/config"
	"github.com/adevinta/vulcan-check-sdk/internal/logging"
	"github.com/adevinta/vulcan-check-sdk/state"
	"github.com/adevinta/vulcan-check-sdk/tools"
	report "github.com/adevinta/vulcan-report"
)

type CheckerHandleRun func(ctx context.Context, target, targetType string, opts string, s state.State) error

// Run is used as adapter to satisfy the method with same name in interface Checker.
func (handler CheckerHandleRun) Run(ctx context.Context, target, targetType string, opts string, s state.State) error {
	return (handler(ctx, target, targetType, opts, s))
}

// CheckerHandleCleanUp func type to specify a CleanUp handler function for a checker.
type CheckerHandleCleanUp func(ctx context.Context, target, targetType, opts string)

// CleanUp is used as adapter to satisfy the method with same name in interface Checker.
func (handler CheckerHandleCleanUp) CleanUp(ctx context.Context, target, targetType, opts string) {
	(handler(ctx, target, targetType, opts))
}

// NewCheckFromHandler creates a new check given a checker run handler.
func NewCheckFromHandlerWithConfig(name string, run CheckerHandleRun, clean CheckerHandleCleanUp, conf *config.Config, l *log.Entry) *Check {
	if clean == nil {
		clean = func(ctx context.Context, target, targetType, opts string) {}
	}
	checkerAdapter := struct {
		CheckerHandleRun
		CheckerHandleCleanUp
	}{
		run,
		clean,
	}
	return NewCheckWithConfig(name, checkerAdapter, l, conf)
}

type pushIntTest struct {
	name              string
	args              pushIntParams
	want              []agent.State
	wantCancel        bool
	wantResourceState interface{}
}

type pushIntParams struct {
	checkRunner     CheckerHandleRun
	checkCleaner    func(resourceToClean interface{}, ctx context.Context, target, targetType, optJSON string)
	resourceToClean interface{}
	agent           *tools.Reporter
	checkName       string
	config          *config.Config
}

func TestIntegrationPushMode(t *testing.T) {
	pushIntTests := []pushIntTest{
		pushIntTest{
			name: "HappyPath",
			args: pushIntParams{
				agent: tools.NewReporter("checkID"),
				config: &config.Config{
					Check: config.CheckConfig{
						CheckID:       "checkID",
						Opts:          "",
						Target:        "www.example.com",
						TargetType:    "Hostname",
						CheckTypeName: "checkTypeName",
					},
					Log: config.LogConfig{
						LogFmt:   "text",
						LogLevel: "debug",
					},
					CommMode: "push",
				},
				checkRunner: func(ctx context.Context, target, targetType, optJSON string, state state.State) (err error) {
					log := logging.BuildRootLog("TestChecker")
					log.Debug("Check running")
					state.SetProgress(0.1)
					v := report.Vulnerability{Description: "Test Vulnerability"}
					v.AddVulnerabilities(report.Vulnerability{Description: "Test Vulnerability"})
					state.AddVulnerabilities(v)
					return nil
				},
				resourceToClean: map[string]string{"key": "initial"},
				checkCleaner: func(resource interface{}, ctx context.Context, target, targetType, optJSON string) {
					r := resource.(map[string]string)
					r["key"] = "cleaned"
				},
			},
			wantCancel:        false,
			wantResourceState: map[string]string{"key": "cleaned"},
			want: []agent.State{
				agent.State{
					Progress: 0,
					Status:   agent.StatusRunning,
					Report: report.Report{
						CheckData: report.CheckData{
							CheckID:          "checkID",
							ChecktypeName:    "checkTypeName",
							ChecktypeVersion: "",
							Target:           "www.example.com",
							Options:          "",
							StartTime:        time.Time{},
							EndTime:          time.Time{},
							Status:           string(agent.StatusRunning),
						},
						ResultData: report.ResultData{
							Error:           "",
							Data:            nil,
							Notes:           "",
							Vulnerabilities: nil,
						},
					}},
				agent.State{
					Progress: 0.1,
					Status:   agent.StatusRunning,
					Report: report.Report{
						CheckData: report.CheckData{
							CheckID:          "checkID",
							ChecktypeName:    "checkTypeName",
							ChecktypeVersion: "",
							Target:           "www.example.com",
							Options:          "",
							StartTime:        time.Time{},
							EndTime:          time.Time{},
							Status:           agent.StatusRunning,
						},
						ResultData: report.ResultData{
							Vulnerabilities: nil,
							Error:           "",
							Data:            nil,
							Notes:           "",
						},
					}},
				agent.State{
					Progress: 1,
					Status:   agent.StatusFinished,
					Report: report.Report{
						CheckData: report.CheckData{
							CheckID:          "checkID",
							ChecktypeName:    "checkTypeName",
							ChecktypeVersion: "",
							Target:           "www.example.com",
							Options:          "",
							Status:           agent.StatusFinished,
							StartTime:        time.Time{},
							EndTime:          time.Time{},
						},
						ResultData: report.ResultData{
							Vulnerabilities: []report.Vulnerability{
								report.Vulnerability{
									Description: "Test Vulnerability",
									Vulnerabilities: []report.Vulnerability{
										report.Vulnerability{
											Description: "Test Vulnerability",
										},
									},
								},
							},
							Error: "",
							Data:  nil,
							Notes: "",
						},
					}},
			},
		},
		pushIntTest{
			name: "Abort",
			args: pushIntParams{
				agent: tools.NewReporter("checkID"),
				config: &config.Config{
					Check: config.CheckConfig{
						CheckID: "checkID",
						Opts:    "",
						Target:  "www.example.com",
					},
					Log: config.LogConfig{
						LogFmt:   "text",
						LogLevel: "debug",
					},
					CommMode: "push",
				},
				checkRunner: func(ctx context.Context, target, targetType, optJSON string, state state.State) (err error) {
					<-ctx.Done()
					return ctx.Err()
				},
				resourceToClean: map[string]string{"key": "initial"},
				checkCleaner: func(resource interface{}, ctx context.Context, target, targetType, optJSON string) {
					r := resource.(map[string]string)
					r["key"] = "cleaned"
				},
			},
			wantCancel:        true,
			wantResourceState: map[string]string{"key": "cleaned"},
			want: []agent.State{
				agent.State{
					Progress: 0,
					Status:   agent.StatusRunning,
					Report: report.Report{
						CheckData: report.CheckData{
							CheckID:          "checkID",
							ChecktypeName:    "",
							ChecktypeVersion: "",
							Target:           "www.example.com",
							Options:          "",
							StartTime:        time.Time{},
							EndTime:          time.Time{},
							Status:           agent.StatusRunning,
						},
						ResultData: report.ResultData{
							Vulnerabilities: nil,
							Error:           "",
							Data:            nil,
							Notes:           "",
						},
					},
				},
				agent.State{
					Progress: 1,
					Status:   agent.StatusAborted,
					Report: report.Report{
						CheckData: report.CheckData{
							CheckID:          "checkID",
							ChecktypeName:    "",
							ChecktypeVersion: "",
							Target:           "www.example.com",
							Options:          "",
							Status:           agent.StatusAborted,
							StartTime:        time.Time{},
							EndTime:          time.Time{},
						},
						ResultData: report.ResultData{
							Vulnerabilities: nil,
							Error:           "",
							Data:            nil,
							Notes:           "",
						},
					},
				},
			},
		},
	}

	for _, tt := range pushIntTests {
		tt := tt
		t.Run(tt.name, func(t2 *testing.T) {
			a := tt.args.agent
			conf := tt.args.config
			conf.Push.AgentAddr = a.URL
			conf.Push.BufferLen = 10
			var cleaner func(ctx context.Context, target, targetType, opts string)
			if tt.args.checkCleaner != nil {
				cleaner = func(ctx context.Context, target, targetType, opts string) {
					tt.args.checkCleaner(tt.args.resourceToClean, ctx, target, targetType, opts)
				}
			}
			l := logging.BuildRootLog("pushCheck")
			c := NewCheckFromHandlerWithConfig(tt.args.checkName, tt.args.checkRunner, cleaner, conf, l)
			if tt.wantCancel {
				go func() {
					a, ok := c.api.(*API)
					if !ok {
						t.Errorf("Error type asserting pushApi")
						return
					}
					a.ExitSignal <- syscall.SIGTERM

				}()
			}
			var gotMsgs []agent.State
			go func() {
				for msg := range a.Msgs {
					// We clear the Time fields by setting then to zero val
					// this is because comparing times with equality has no sense.
					msg.Report.StartTime = time.Time{}
					msg.Report.EndTime = time.Time{}
					gotMsgs = append(gotMsgs, msg)
				}
			}()
			c.RunAndServe()
			a.Stop()
			if len(gotMsgs) != len(tt.want) {
				t.Errorf("Error in test %s, number of messages received different than expected. \nWant: %s Got: %s.\n diffs %+v", tt.name, pretty.Sprint(tt.want), pretty.Sprint(gotMsgs), pretty.Diff(tt.want, gotMsgs))
				return
			}
			equals, diffs := compareMsgs(gotMsgs, tt.want)
			if !equals {
				t.Errorf("Error in test %s. \nWant: %s Got: %s.\n diffs %+v", tt.name, pretty.Sprint(tt.want), pretty.Sprint(gotMsgs), diffs)
			}
			// Compare resource to clean up state with wanted state.
			diff := cmp.Diff(tt.wantResourceState, tt.args.resourceToClean)
			if diff != "" {
				t.Errorf("Error want resource to clean state != got. Diff %s", diff)
			}
		})
	}

}

// compareMsgs compares two arrays of messages  in a
// meanfull way, for instance: StartTime and EndTime can't be compared using equality.
func compareMsgs(got []agent.State, want []agent.State) (bool, interface{}) {
	ok := true
	// NOTE: race condition found #5
	diffs := pretty.Diff(want, got)
	if len(diffs) > 0 {
		ok = false
	}
	return ok, diffs
}
