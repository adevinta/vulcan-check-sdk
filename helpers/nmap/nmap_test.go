/*
Copyright 2019 Adevinta
*/

package nmap

import (
	"context"
	"encoding/json"
	"flag"
	"io/ioutil"
	"net"
	"os"
	"testing"
	"time"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	gonmap "github.com/lair-framework/go-nmap"
)

const (
	NmapPath = "nmap"
)

var (
	hostComparerOpts = cmp.Options{cmpopts.IgnoreTypes(gonmap.Timestamp{}, time.Time{}, time.Location{}, gonmap.Times{})}
	update           = flag.Bool("update", false, "update golden files")
)

func listenOnTCPPort(port string) (ln net.Listener, err error) {
	ln, err = net.Listen("tcp", "localhost:"+port)
	return ln, err
}

func listenOnUDPPort(port string) (ln net.PacketConn, err error) {
	ln, err = net.ListenPacket("udp", "localhost:"+port)
	return ln, err
}

// State mock.
type stateMock struct{}

func (c stateMock) SetProgress(progress float32) {}
func (c stateMock) Result() (r *report.Report)   { return }
func (c stateMock) Shutdown() (err error)        { return }

type NmapRunnerBuilder func() (NmapRunner, tearDownIntTest, error)
type tearDownIntTest func() error
type customReportComparer func(want gonmap.NmapRun, got gonmap.NmapRun) string
type integrationTest struct {
	name                 string
	builder              NmapRunnerBuilder
	goldenPath           string
	wantReport           *gonmap.NmapRun
	customResultComparer customReportComparer
	wantErr              bool
	requiresRoot         bool
}

func initNmapPath() {
	if _, err := os.Stat(nmapFile); os.IsNotExist(err) {
		// Try to resolve from path.
		nmapFile = NmapPath
	}
}
func compareOnlyHostsSection(want gonmap.NmapRun, got gonmap.NmapRun) string {
	return cmp.Diff(want.Hosts, got.Hosts, hostComparerOpts)
}
func TestRunnerIntegrationTest(t *testing.T) {
	initNmapPath()
	tests := []integrationTest{
		{
			name:                 "HappyTCPPath",
			goldenPath:           "testdata/NmapHappyPathGolden.json",
			customResultComparer: compareOnlyHostsSection,
			builder: func() (runner NmapRunner, tearDown tearDownIntTest, err error) {
				s := state.State{
					ProgressReporter: stateMock{},
				}
				timing := 0
				port := "29070"
				ln, err := listenOnTCPPort(port)
				if err != nil {
					return nil, nil, err
				}

				runner = NewNmapTCPCheck("localhost", s, timing, []string{port})
				tearDown = func() (innerError error) {
					return (ln.Close())
				}
				return runner, tearDown, nil
			},
			wantErr: false,
		},
		{
			name:                 "HappyPath",
			goldenPath:           "testdata/NmapHappyPathGolden.json",
			customResultComparer: compareOnlyHostsSection,
			builder: func() (runner NmapRunner, tearDown tearDownIntTest, err error) {
				s := state.State{
					ProgressReporter: stateMock{},
				}
				timing := 0
				port := "29070"
				options := map[string]string{
					"-p":  port,
					"-sT": "",
				}
				ln, err := listenOnTCPPort(port)
				if err != nil {
					return nil, nil, err
				}
				runner = NewNmapCheck("localhost", s, timing, options)
				tearDown = func() (innerError error) {
					return (ln.Close())
				}
				return runner, tearDown, nil
			},
			wantErr: false,
		},
		{
			name:                 "HappyUDPPath",
			goldenPath:           "testdata/NmapHappyUDPPathGolden.json",
			customResultComparer: compareOnlyHostsSection,
			builder: func() (runner NmapRunner, tearDown tearDownIntTest, err error) {
				s := state.State{
					ProgressReporter: stateMock{},
				}
				timing := 0
				port := "29070"
				ln, err := listenOnUDPPort(port)
				if err != nil {
					return nil, nil, err
				}
				runner = NewNmapUDPCheck("localhost", s, timing, []string{port})
				tearDown = func() (innerError error) {
					return (ln.Close())
				}
				return runner, tearDown, nil
			},
			wantErr:      false,
			requiresRoot: true,
		},
	}

	for _, tt := range tests {
		if tt.requiresRoot && !root() {
			continue
		}
		t.Run(tt.name, func(t *testing.T) {
			runner, tearDown, err := tt.builder()
			if err != nil {
				t.Fatal(err)
			}
			gotReport, _, err := runner.Run(context.Background())
			// t.Logf("raw:\n%+v", gotReport)
			if (err != nil) != tt.wantErr {
				err = tearDown()
				if err != nil {
					t.Error(err)
				}
				t.Fatalf("runner.Run() error = %+v, wantErr %+v", err, tt.wantErr)
				return
			}
			if tt.goldenPath != "" {
				if *update {
					// NOTE: we should prettify the json before writting to the golden file.
					errGF := writeGoldenFile(gotReport, tt.goldenPath)
					if errGF != nil {
						errTD := tearDown()
						if errTD != nil {
							t.Error(errTD)
						}
						t.Fatalf("Error writing golden file %v", errGF)
					}
				}
				contents, errRF := ioutil.ReadFile(tt.goldenPath)
				if errRF != nil {
					t.Fatal(errRF)
				}
				tt.wantReport = &gonmap.NmapRun{}
				err = json.Unmarshal(contents, tt.wantReport)
				// r, err := gonmap.Parse(contents)
				if err != nil {
					tearDown()
					t.Fatal(err)
				}
				// tt.wantReport = r
			}
			var comparer customReportComparer
			if tt.customResultComparer != nil {
				comparer = tt.customResultComparer
			} else {
				comparer = compareOnlyHostsSection
			}
			diff := comparer(*tt.wantReport, *gotReport)
			if diff != "" {
				t.Errorf("runner.Run() gotReport != want, diffs %s ", diff)
			}
			err = tearDown()
			if err != nil {
				t.Error(err)
			}

		})
	}

}

func TestProcessOutputChunk(t *testing.T) {
	s := state.State{
		ProgressReporter: stateMock{},
	}
	timing := 0
	port := "29070"
	r := NewNmapTCPCheck("localhost", s, timing, []string{port})

	chunk := []byte(`<taskprogress percent="05" \/><taskprogress a percent="15" b\/><taskprogress c percent="25" d\/>`)
	bInfo := r.(check.ProcessChecker).ProcessOutputChunk(chunk)
	if !bInfo {
		t.Errorf("No progress information available")
	}

	chunk = []byte(`<taskprogress percent="45" \/><taskprogress a percent="NULL" b\/><taskprogress c percent="75" d\/><taskprogress c percent="100" d\/>`)
	bInfo = r.(check.ProcessChecker).ProcessOutputChunk(chunk)
	if bInfo {
		t.Errorf("Progress information available")
	}
}

func root() bool {
	return (os.Getegid() == 0)
}

func writeGoldenFile(v interface{}, filePath string) error {
	bytes, err := json.Marshal(v)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(filePath, bytes, 0644)
	return err
}
