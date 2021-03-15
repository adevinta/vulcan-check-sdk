/*
Copyright 2019 Adevinta
*/

package local

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	report "github.com/adevinta/vulcan-report"
)

var (
	severityNames = map[report.SeverityRank]string{
		report.SeverityLow:      "Low",
		report.SeverityMedium:   "Medium",
		report.SeverityNone:     "None",
		report.SeverityHigh:     "High",
		report.SeverityCritical: "Critical",
	}
)

type jsonFmt struct {
	Stdout *os.File
	Stderr *os.File
}

func (j *jsonFmt) progress(p float32) {
	// For the json formatter we don't write anything when a progress is
	// reported. The formatter only writes a json or a error when the check
	// finishes.
}

func (j *jsonFmt) result(err error, r *report.ResultData) {
	if err != nil {
		mustWriteError(err, j.Stderr)
		return
	}
	if r == nil {
		return
	}
	data, err := json.MarshalIndent(r, "", " ")
	// This is formatter is only used to run checks in the command line and
	// write the result as a json so if we can not marshal the result we panic.
	if err != nil {
		panic(err)
	}
	_, err = j.Stdout.Write(data)
	// Same here when trying to write to the std out.
	if err != nil {
		panic(err)
	}
}

type textFmt struct {
	Stdout *os.File
	Stderr *os.File
}

func (t *textFmt) progress(p float32) {
	progress := fmt.Sprintf("progress %.2f\n", p)
	mustWrite(progress, t.Stderr)
}

func (t *textFmt) result(err error, r *report.ResultData) {
	if err != nil {
		mustWriteError(err, t.Stderr)
		return
	}
	if r == nil || len(r.Vulnerabilities) < 1 {
		mustWrite("\nNo vulnerabilities found\n", t.Stderr)
		return
	}
	sort.SliceStable(r.Vulnerabilities, func(i, j int) bool {
		return r.Vulnerabilities[i].Score > r.Vulnerabilities[j].Score
	})
	data := [][]string{}
	for _, vuln := range r.Vulnerabilities {
		refs := ""
		for _, ref := range vuln.References {
			refs += fmt.Sprintf("%s\n", ref)
		}
		recommendations := ""
		for _, recommendation := range vuln.Recommendations {
			recommendations += fmt.Sprintf("%s\n", recommendation)
		}
		severity := severityNames[vuln.Severity()]
		row := []string{vuln.Summary, severity, recommendations}
		data = append(data, row)
	}
	w := tabwriter.NewWriter(t.Stdout, 0, 0, 1, ' ', 0)
	_, err = fmt.Fprint(w, "\nName \tSeverity \tRecommendations \t\n")
	if err != nil {
		panic(err)
	}
	for _, l := range data {
		line := formatRow(l)
		_, err = fmt.Fprint(w, line)
		if err != nil {
			panic(err)
		}
	}
	err = w.Flush()
	if err != nil {
		panic(err)
	}
}

func mustWrite(msg string, output *os.File) {
	_, err := output.WriteString(msg)
	if err != nil {
		// If we can not write we should panic because this formatter is
		// intended to be used only when running the check using the command
		// line.
		panic(err)
	}
}

func mustWriteError(err error, output *os.File) {
	msg := fmt.Sprintf("%+v", err)
	mustWrite(msg, output)
}

func formatRow(row []string) string {
	formatted := []string{}
	for _, c := range row {
		c = strings.TrimPrefix(c, "\n")
		c = strings.TrimPrefix(c, "\n")
		c = strings.TrimSpace(c)
		formatted = append(formatted, c)
	}
	line := strings.Join(formatted, "\t")
	return line + "\t\n"
}
