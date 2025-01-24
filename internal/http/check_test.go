/*
Copyright 2024 Adevinta
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
	"syscall"
	"testing"
	"time"

	report "github.com/adevinta/vulcan-report"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	log "github.com/sirupsen/logrus"
	"go.uber.org/goleak"

	"github.com/adevinta/vulcan-check-sdk/agent"
	"github.com/adevinta/vulcan-check-sdk/config"
	"github.com/adevinta/vulcan-check-sdk/internal/logging"
	"github.com/adevinta/vulcan-check-sdk/state"
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
	handler(ctx, target, assetType, opts)
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
	resourceToClean interface{}
	checkName       string
	config          *config.Config
	jobs            map[string]Job
}

// sleepCheckRunner implements a check that sleeps based on the options and generates inconclusive in case of a target with that name.
func sleepCheckRunner(ctx context.Context, target, _, optJSON string, st state.State) (err error) {
	// Use the implementation of the logger from the check-sdk instead of NewCheckLogFromContext to prevent cycles.
	log, ok := ctx.Value("logger").(*log.Entry)
	if !ok {
		return errors.New("logger not found in context")
	}
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

// TestIntegrationHttpMode executes one test with numIters * len(jobs) concurrent http checks.
func TestIntegrationHttpMode(t *testing.T) {
	port := 8888
	requestTimeout := 3 * time.Second
	wantHealthz := `"OK"`
	numIters := 10
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
					},
					"checkDeadline": {
						CheckID:   "checkDeadline",
						Options:   `{"SleepTime": 10}`,
						Target:    "www.example.com",
						AssetType: "Hostname",
					},
					"checkInconclusive": {
						CheckID:   "checkInconclusive",
						Options:   `{"SleepTime": 1}`,
						Target:    "inconclusive",
						AssetType: "Hostname",
					},
					"checkFailed": {
						CheckID:   "checkFailed",
						Options:   `{}`,
						Target:    "www.example.com",
						AssetType: "Hostname",
					},
				},
				resourceToClean: map[string]string{"key": "initial"},
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
						},
						ResultData: report.ResultData{
							Error: "error: missing or 0 sleep time",
						},
					},
				},
			},
		},
	}

	for _, tt := range intTests {
		tt := tt
		t.Run(tt.name, func(t2 *testing.T) {
			conf := tt.args.config
			l := logging.BuildRootLog("httpCheck")
			c := NewCheckFromHandlerWithConfig(tt.args.checkName, tt.args.checkRunner, nil, conf, l)
			go c.RunAndServe()
			client := &http.Client{}
			url := fmt.Sprintf("http://localhost:%d/run", *tt.args.config.Port)

			type not struct {
				check string
				resp  agent.State
			}

			// Wait for the server to be healthy and test the healthz response.
			i := 5
			for i > 0 {
				i--
				res, err := http.Get(fmt.Sprintf("http://localhost:%d/healthz", *tt.args.config.Port))
				if err != nil {
					if errors.Is(err, syscall.ECONNREFUSED) {
						l.Infof("Connection refused - let's wait ... %d", i)
						time.Sleep(1 * time.Second)
						continue
					}

					// No other err should happen
					t.Errorf("staring server: %v", err)
					break
				}

				// Is not an error, let's check the status code and the reponse.
				if res.StatusCode != 200 {
					t.Errorf("unexpected status for healthz: %v", res.StatusCode)
				}
				defer res.Body.Close()
				body, _ := io.ReadAll(res.Body)
				if string(body) != wantHealthz {
					t.Errorf("unexpected body for healthz: %v", string(body))
				}
				break
			}
			// Do not wait more
			if i == 0 {
				t.Error("Unable to start the server")
			}

			// ch will receive the results of the concurrent job executions
			ch := make(chan not, len(tt.args.jobs)*numIters)
			wg := sync.WaitGroup{}

			// Runs each job in a go routine with a 3 seconds deadline.
			for i := 0; i < numIters; i++ {
				for key, job := range tt.args.jobs {
					wg.Add(1)
					go func(key string, iter int, job Job) {
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
							t.Errorf("Marshal error: %v", err)
						}
						ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
						defer cancel()
						req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(cc))
						if err != nil {
							t.Errorf("NewRequestWithContext error: %v", err)
							return
						}
						req.Header.Add("Content-Type", "application/json")
						resp, err := client.Do(req)
						if err != nil {
							if errors.Is(err, context.DeadlineExceeded) {
								n.resp = agent.State{Status: agent.StatusAborted}
								return
							}
							t.Errorf("request error: %v", err)
							return
						}
						defer resp.Body.Close()
						body, err := io.ReadAll(resp.Body)
						if err != nil {
							t.Errorf("failed to read response body: %v", err)
							return
						}
						r := agent.State{}
						err = json.Unmarshal(body, &r)
						if err != nil {
							t.Errorf("Unable to unmarshal response: %v", err)
							return
						}
						n.resp = r
					}(key, i, job)
				}
			}
			wg.Wait()
			close(ch)
			c.Shutdown()

			results := map[string]agent.State{}
			for x := range ch {
				// We are executing numIters times the same job. The results for each one must be exactly the same.
				if r, ok := results[x.check]; ok {
					diff := cmp.Diff(r, x.resp, cmpopts.IgnoreFields(report.CheckData{}, "StartTime", "EndTime"))
					if diff != "" {
						t.Errorf("Result mismatch from previous result %s. diffs %+v", tt.name, diff)
					}
				}
				results[x.check] = x.resp
			}

			// Test that the final result matches.
			diff := cmp.Diff(results, tt.want, cmpopts.IgnoreFields(report.CheckData{}, "StartTime", "EndTime"))
			if diff != "" {
				t.Errorf("Error in test %s. diffs %+v", tt.name, diff)
			}

			l.Info("waiting for go routines to tidy-up before goleak test ....")
			time.Sleep(5 * time.Second)
			goleak.VerifyNone(t)
		})
	}
}
