/*
Copyright 2019 Adevinta
*/

package nmap

//Check runs nmap and proceses the output
import (
	"bufio"
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/state"
	gonmap "github.com/lair-framework/go-nmap"
)

var (
	// Path of the Nmap file.
	nmapFile = "nmap"

	// Result update time in seconds.
	updateTime = 1

	// Default timing.
	defaultTiming = 3
)

// NmapRunner executes an Nmap.
type NmapRunner interface {
	Run(ctx context.Context) (report *gonmap.NmapRun, rawOutput *[]byte, err error)
}

type runner struct {
	params []string
	state  state.State
	output []byte
}

func (r *runner) Run(ctx context.Context) (report *gonmap.NmapRun, rawOutput *[]byte, err error) {
	processRunner := check.NewProcessChecker(nmapFile, r.params, bufio.ScanLines, r)

	_, err = processRunner.Run(ctx)
	if err != nil {
		return nil, nil, err
	}

	rawOutput = &r.output
	report, err = gonmap.Parse(r.output)
	return report, rawOutput, err
}

func (r *runner) ProcessOutputChunk(chunk []byte) bool {
	// Extract progress data from Nmap XML entry.
	r.output = append(r.output, chunk...)

	re := regexp.MustCompile(`<taskprogress .*? percent="(.*?)" .*?\/>`)

	match := re.FindStringSubmatch(string(chunk))
	// If the line contains progress data.
	if len(match) >= 2 {
		progress, err := strconv.ParseFloat(match[1], 32)
		if err != nil {
			return false
		}
		r.state.SetProgress(float32(progress))
		return true
	}

	// No progress information available.
	return true
}

/* NewNmapCheck Creates a new base nmap check with some default options that are needed to parse
 * the results.
 */
func NewNmapCheck(target string, s state.State, timing int, options map[string]string) NmapRunner {
	if timing == 0 {
		timing = defaultTiming
	}
	statsPeriod := fmt.Sprintf("%vs", updateTime)
	t := fmt.Sprintf("-T%v", timing)

	// regex for -T[0-9]
	var regexT = regexp.MustCompile(`^-T[0-9]$`)

	var paramsStart = []string{"-oX", "-", t}
	var paramsEnd = []string{target, "--stats-every", statsPeriod}

	params := make([]string, 0, len(paramsStart)+len(paramsEnd)+len(options))

	params = append(params, paramsStart...)
	for k, v := range options {
		if k == "-oX" || k == "--stats-every" || regexT.MatchString(k) {
			continue
		}
		params = append(params, k)
		if v != "" {
			params = append(params, v)
		}
	}

	params = append(params, paramsEnd...)

	r := &runner{
		params: params,
		state:  s,
	}
	return r
}

// NewNmapTCPCheck Creates a new nmap check. TCP Connect()
func NewNmapTCPCheck(target string, s state.State, timing int, tcpPorts []string) NmapRunner {
	tcp := strings.Join(tcpPorts, ",")
	return NewNmapCheck(target, s, timing, map[string]string{"-p": tcp})
}

// NewNmapUDPCheck Creates a new nmap check.
func NewNmapUDPCheck(target string, s state.State, timing int, udpPorts []string) NmapRunner {
	udp := strings.Join(udpPorts, ",")
	return NewNmapCheck(target, s, timing, map[string]string{"-p": udp, "-sU": ""})
}
