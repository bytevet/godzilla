package report

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/bytevet/godzilla/internal/scaninfo"
)

// diagView is the rendered form of a scaninfo.Info. Every field is a string: most
// rows always render, so a zero must read as "0"; Skipped and RulesLive are the
// two the template drops entirely when absent, and only those use optCount's
// empty-string sentinel.
type diagView struct {
	Files, Skipped, Lines         string
	Packages, Functions           string
	Rules, RulesLive              string
	SourceSites, SinkSites        string
	Wall, Speed, PeakMem, Workers string
	Engine, Toolchain             string
	Phases                        []phaseRow
}

// phaseRow is one bar in the diagnostics Time section.
type phaseRow struct {
	Label string
	Pct   int
	Time  string
}

// newDiagView renders info for the template, or returns nil when the caller
// supplied no telemetry — an absent diagnostics section beats one full of
// zeros. build is how long assembling the report's view model took, which is
// the one phase the report can measure about itself.
func newDiagView(info scaninfo.Info, build time.Duration) *diagView {
	if info == (scaninfo.Info{}) {
		return nil
	}
	return &diagView{
		Files:       count(info.Files),
		Skipped:     optCount(info.Skipped),
		Lines:       count(info.Lines),
		Packages:    count(info.Packages),
		Functions:   count(info.Functions),
		Rules:       count(info.Rules),
		RulesLive:   optCount(info.RulesLive),
		SourceSites: count(info.SourceSites),
		SinkSites:   count(info.SinkSites),
		Wall:        duration(info.Wall),
		Speed:       speed(info.Lines, info.Wall),
		PeakMem:     bytesHuman(info.PeakBytes),
		Workers:     count(runtime.GOMAXPROCS(0)),
		Engine:      Version,
		Toolchain:   runtime.Version(),
		Phases:      phases(info, build),
	}
}

// phases turns the recorded spans into bars that add up. The analysis passes
// overlap — the dangerous-call, secrets, line-counting and match-counting
// passes all run concurrently with the taint engine — so what is left of
// Analysis after its three measured sub-spans, and what is left of Wall after
// Convert and Analysis, become explicit buckets. Without them the percentages
// silently fail to reach 100 and the panel reads as broken.
func phases(info scaninfo.Info, build time.Duration) []phaseRow {
	otherAnalysis := info.Analysis - info.Index - info.RuleSel - info.Taint
	orchestration := info.Wall - info.Convert - info.Analysis
	spans := []struct {
		label string
		d     time.Duration
	}{
		{"parse & lower", info.Convert},
		{"index & call graph", info.Index},
		{"rule selection", info.RuleSel},
		{"taint propagation", info.Taint},
		{"concurrent passes", otherAnalysis},
		{"orchestration", orchestration},
		{"report build", build},
	}
	var total time.Duration
	for _, s := range spans {
		if s.d > 0 {
			total += s.d
		}
	}
	if total <= 0 {
		return nil
	}
	rows := make([]phaseRow, 0, len(spans))
	for _, s := range spans {
		if s.d <= 0 {
			continue
		}
		rows = append(rows, phaseRow{
			Label: s.label,
			Pct:   int(s.d * 100 / total),
			Time:  duration(s.d),
		})
	}
	return rows
}

// count renders n thousands-separated. Every caller passes a length or a
// counter, so there is no sign to handle.
func count(n int) string {
	s := strconv.Itoa(n)
	var b strings.Builder
	for i, r := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// optCount is count for a row the template drops when there is nothing to say.
func optCount(n int) string {
	if n == 0 {
		return ""
	}
	return count(n)
}

// duration renders d at a precision that stays readable across the four orders
// of magnitude a scan phase spans.
func duration(d time.Duration) string {
	switch {
	case d <= 0:
		return ""
	case d < time.Millisecond:
		return fmt.Sprintf("%dµs", d.Microseconds())
	case d < time.Second:
		return fmt.Sprintf("%dms", d.Milliseconds())
	case d < time.Minute:
		return fmt.Sprintf("%.2fs", d.Seconds())
	default:
		return d.Round(100 * time.Millisecond).String()
	}
}

func bytesHuman(b uint64) string {
	if b == 0 {
		return ""
	}
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit && exp < 3; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGT"[exp])
}

// speed reports lines of source per second of wall time.
func speed(lines int, wall time.Duration) string {
	if lines <= 0 || wall <= 0 {
		return ""
	}
	perSec := float64(lines) / wall.Seconds()
	if perSec >= 1000 {
		return fmt.Sprintf("%.0fk lines/s", perSec/1000)
	}
	return fmt.Sprintf("%.0f lines/s", perSec)
}
