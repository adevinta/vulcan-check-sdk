/*
Copyright 2019 Adevinta
*/

package http

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"go.uber.org/goleak"

	log "github.com/sirupsen/logrus"

	"github.com/adevinta/vulcan-check-sdk/agent"
	"github.com/adevinta/vulcan-check-sdk/config"
	"github.com/adevinta/vulcan-check-sdk/internal/logging"
	"github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
)

type CheckerHandleRun func(ctx context.Context, target, assetType, opts string, s state.State) error

// Run is used as adapter to satisfy the method with same name in interface Checker.
func (handler CheckerHandleRun) Run(ctx context.Context, target, assetType string, opts string, s state.State) error {
	return (handler(ctx, target, assetType, opts, s))
}

// CheckerHandleCleanUp func type to specify a CleanUp handler function for a checker.
type CheckerHandleCleanUp func(ctx context.Context, target, assetType, opts string)

// CleanUp is used as adapter to satisfy the method with same name in interface Checker.
func (handler CheckerHandleCleanUp) CleanUp(ctx context.Context, target, assetType, opts string) {
	(handler(ctx, target, assetType, opts))
}

// NewCheckFromHandler creates a new check given a checker run handler.
func NewCheckFromHandlerWithConfig(name string, run CheckerHandleRun, clean CheckerHandleCleanUp, conf *config.Config, l *log.Entry) *Check {
	if clean == nil {
		clean = func(ctx context.Context, target, assetType, opts string) {}
	}
	checkerAdapter := struct {
		CheckerHandleRun
		CheckerHandleCleanUp
	}{
		run,
		clean,
	}
	return NewCheck(name, checkerAdapter, l, conf)
}

type httpTest struct {
	name              string
	args              httpIntParams
	want              map[string]agent.State
	wantResourceState interface{}
}

type httpIntParams struct {
	checkRunner     CheckerHandleRun
	checkCleaner    func(resourceToClean interface{}, ctx context.Context, target, assetType, optJSON string)
	resourceToClean interface{}
	checkName       string
	config          *config.Config
	jobs            map[string]Job
}

// sleepCheckRunner implements a check that sleeps based on the options and generates inconclusive in case of a target with that name.
func sleepCheckRunner(ctx context.Context, target, assetType, optJSON string, st state.State) (err error) {
	log := logging.BuildRootLog("TestChecker")
	log.Debug("Check running")
	st.SetProgress(0.1)
	type t struct {
		SleepTime int
	}
	opt := t{}
	if optJSON == "" {
		return errors.New("error: missing sleep time")
	}
	if err := json.Unmarshal([]byte(optJSON), &opt); err != nil {
		return err
	}
	if target == "inconclusive" {
		return state.ErrAssetUnreachable
	}
	if opt.SleepTime <= 0 {
		return errors.New("error: missing or 0 sleep time")
	}
	log.Debugf("going sleep %v seconds.", strconv.Itoa(opt.SleepTime))

	select {
	case <-time.After(time.Duration(opt.SleepTime) * time.Second):
		log.Debugf("slept successfully %s seconds", strconv.Itoa(opt.SleepTime))
	case <-ctx.Done():
		log.Info("Check aborted")
	}
	st.AddVulnerabilities(report.Vulnerability{
		Summary:     "Summary",
		Description: "Test Vulnerability",
	})
	return nil
}

func TestIntegrationHttpMode(t *testing.T) {
	port := 8888
	startTime := time.Now()
	intTests := []httpTest{
		{
			name: "HappyPath",
			args: httpIntParams{
				config: &config.Config{
					Check: config.CheckConfig{
						CheckTypeName: "checkTypeName",
					},
					Log: config.LogConfig{
						LogFmt:   "text",
						LogLevel: "debug",
					},
					Port: &port,
				},
				checkRunner: sleepCheckRunner,
				jobs: map[string]Job{
					"checkHappy": {
						CheckID:   "checkHappy",
						Options:   `{"SleepTime": 1}`,
						Target:    "www.example.com",
						AssetType: "Hostname",
						StartTime: startTime,
					},
					"checkDeadline": {
						CheckID:   "checkDeadline",
						Options:   `{"SleepTime": 10}`,
						Target:    "www.example.com",
						AssetType: "Hostname",
						StartTime: startTime,
					},
					"checkInconclusive": {
						CheckID:   "checkInconclusive",
						Options:   `{"SleepTime": 1}`,
						Target:    "inconclusive",
						AssetType: "Hostname",
						StartTime: startTime,
					},
					"checkFailed": {
						CheckID:   "checkFailed",
						Options:   `{}`,
						Target:    "www.example.com",
						AssetType: "Hostname",
						StartTime: startTime,
					},
				},
				resourceToClean: map[string]string{"key": "initial"},
				checkCleaner: func(resource interface{}, ctx context.Context, target, assetType, opt string) {
					r := resource.(map[string]string)
					r["key"] = "cleaned"
				},
			},
			wantResourceState: map[string]string{"key": "cleaned"},
			want: map[string]agent.State{
				"checkHappy": {
					Status: agent.StatusFinished,
					Report: report.Report{
						CheckData: report.CheckData{
							CheckID:          "checkHappy",
							ChecktypeName:    "checkTypeName",
							ChecktypeVersion: "",
							Target:           "www.example.com",
							Options:          `{"SleepTime": 1}`,
							Status:           agent.StatusFinished,
							StartTime:        startTime,
							EndTime:          time.Time{},
						},
						ResultData: report.ResultData{
							Vulnerabilities: []report.Vulnerability{
								{
									Description: "Test Vulnerability",
									Summary:     "Summary",
								},
							},
							Error: "",
							Data:  nil,
							Notes: "",
						},
					}},
				"checkDeadline": {
					Status: agent.StatusAborted,
				},
				"checkInconclusive": {
					Status: agent.StatusInconclusive,
					Report: report.Report{
						CheckData: report.CheckData{
							CheckID:          "checkInconclusive",
							ChecktypeName:    "checkTypeName",
							ChecktypeVersion: "",
							Target:           "inconclusive",
							Options:          `{"SleepTime": 1}`,
							Status:           agent.StatusInconclusive,
							StartTime:        startTime,
							EndTime:          time.Time{},
						},
					},
				},
				"checkFailed": {
					Status: agent.StatusFailed,
					Report: report.Report{
						CheckData: report.CheckData{
							CheckID:          "checkFailed",
							ChecktypeName:    "checkTypeName",
							ChecktypeVersion: "",
							Target:           "www.example.com",
							Options:          `{}`,
							Status:           agent.StatusFailed,
							StartTime:        startTime,
							EndTime:          time.Time{},
						},
						ResultData: report.ResultData{
							Error: "error: missing or 0 sleep time",
						},
					},
				},
			},
		},
	}

	defer goleak.VerifyNone(t)

	for _, tt := range intTests {
		tt := tt
		t.Run(tt.name, func(t2 *testing.T) {
			conf := tt.args.config
			var cleaner func(ctx context.Context, target, assetType, opts string)
			if tt.args.checkCleaner != nil {
				cleaner = func(ctx context.Context, target, assetType, opts string) {
					tt.args.checkCleaner(tt.args.resourceToClean, ctx, target, assetType, opts)
				}
			}
			l := logging.BuildRootLog("httpCheck")
			c := NewCheckFromHandlerWithConfig(tt.args.checkName, tt.args.checkRunner, cleaner, conf, l)
			go c.RunAndServe()
			client := &http.Client{}
			url := fmt.Sprintf("http://localhost:%d/run", *tt.args.config.Port)

			type not struct {
				check string
				resp  agent.State
			}

			// ch will receibe the results of the concurrent job executions
			ch := make(chan not, len(tt.args.jobs))
			wg := sync.WaitGroup{}

			// Runs each job in a go routine with a 3 seconds deadline.
			for key, job := range tt.args.jobs {
				wg.Add(1)
				go func(key string, job Job) {
					defer wg.Done()
					var err error
					n := not{
						check: key,
					}
					defer func() {
						ch <- n
					}()
					cc, err := json.Marshal(job)
					if err != nil {
						l.Error("Marshal error", "error", err)
						return
					}
					ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
					defer cancel()
					req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(cc))
					if err != nil {
						l.Error("NewRequestWithContext error", "error", err)
						return
					}
					req.Header.Add("Content-Type", "application/json")
					resp, err := client.Do(req)
					if err != nil {
						if errors.Is(err, context.DeadlineExceeded) {
							n.resp = agent.State{Status: agent.StatusAborted}
							return
						}
						l.Error("request error", "error", err)
						return
					}
					defer resp.Body.Close()
					body, err := io.ReadAll(resp.Body)
					if err != nil {
						l.Error("failed to read response body", "error", err)
						return
					}
					r := agent.State{}
					err = json.Unmarshal(body, &r)
					if err != nil {
						l.Error("Unable to unmarshal response", "error", err)
						return
					}

					// Compare resource to clean up state with wanted state.
					diff := cmp.Diff(tt.wantResourceState, tt.args.resourceToClean)
					if diff != "" {
						t.Errorf("Error want resource to clean state != got. Diff %s", diff)
					}
					n.resp = r
				}(key, job)
			}
			wg.Wait()
			close(ch)

			results := map[string]agent.State{}
			for x := range ch {
				results[x.check] = x.resp
			}

			diff := cmp.Diff(results, tt.want, cmpopts.IgnoreFields(report.CheckData{}, "EndTime"))
			if diff != "" {
				t.Errorf("Error in test %s. diffs %+v", tt.name, diff)
			}
			c.Shutdown()
		})
	}
}
