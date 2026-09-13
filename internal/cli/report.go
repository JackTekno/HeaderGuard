package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/jacktekno/headerguard/internal/scanner"
)

var categoryLabels = map[string]string{
	"headers": "Security Headers",
	"cookies": "Cookies",
	"tls":     "TLS & HTTPS",
	"dns":     "DNS & HSTS Preload",
}

// Plain-text markers, kept ASCII so the output stays readable when piped
// or pasted anywhere.
var statusMarkers = map[string]string{
	scanner.StatusOK:      "[OK]",
	scanner.StatusWarn:    "[WARN]",
	scanner.StatusMissing: "[MISSING]",
	scanner.StatusInfo:    "[INFO]",
	scanner.StatusError:   "[FAILED]",
	scanner.StatusNA:      "[N/A]",
	scanner.StatusPartial: "[PARTIAL]",
}

func statusColor(status string, c Color) func(string) string {
	switch status {
	case scanner.StatusOK:
		return c.Green
	case scanner.StatusWarn, scanner.StatusPartial:
		return c.Yellow
	case scanner.StatusMissing, scanner.StatusError:
		return c.Red
	default:
		return c.Dim
	}
}

func gradeColor(letter string, c Color) string {
	switch letter {
	case "A+", "A":
		return c.Green(c.Bold(letter))
	case "B", "C":
		return c.Yellow(c.Bold(letter))
	case "-":
		return c.Dim(letter)
	default:
		return c.Red(c.Bold(letter))
	}
}

// PrintReport writes the full terminal report.
func PrintReport(res *scanner.Result, c Color, w io.Writer) {
	line := func(s string) { fmt.Fprintln(w, s) }

	line(c.Bold("HeaderGuard v" + scanner.Version))
	line(strings.Repeat("-", 72))
	line("Target    : " + res.Meta.Target)
	line("Final URL : " + res.Meta.FinalURL)
	line(fmt.Sprintf("Time      : %s (%d ms)", res.Meta.ScannedAt, res.Meta.DurationMs))
	for _, n := range res.Notes {
		line(c.Dim("Note      : " + n))
	}
	line("")

	if res.Meta.Status == scanner.StatusError {
		line(c.Red("FAILED: " + res.Meta.Error))
		return
	}

	// Summary.
	line(c.Bold("SUMMARY"))
	line(fmt.Sprintf("  Grade     : %s   Score %d/100", gradeColor(res.Grade.Letter, c), res.Grade.Score))
	for _, cat := range []string{"headers", "cookies", "tls", "dns"} {
		cs := res.Grade.Breakdown[cat]
		if cs.Applicable == 0 {
			continue
		}
		line(fmt.Sprintf("  %-22s %d/%d", categoryLabels[cat], cs.Earned, cs.Applicable))
	}
	for _, cap := range res.Grade.CapsApplied {
		line("  " + c.Red("CAP: "+cap))
	}
	for _, f := range res.Findings {
		line("  " + c.Red("- ") + f)
	}

	// Security headers.
	line("")
	line(c.Bold("SECURITY HEADERS"))
	for _, it := range res.Headers.Items {
		marker := statusMarkers[it.Status]
		col := statusColor(it.Status, c)
		line(fmt.Sprintf("  %s %s %s",
			col(marker), col(it.Name), col(fmt.Sprintf("%d/%d", it.Earned, it.Weight))))
		if len(it.RawValues) > 0 {
			line("      value      : " + c.Dim(strings.Join(it.RawValues, " | ")))
		}
		if it.Details != "" {
			line("      " + it.Details)
		}
		if it.Status != scanner.StatusOK && it.Status != scanner.StatusInfo && it.Fix != "" {
			line("      fix        : " + it.Fix)
		}
	}

	// Clickjacking.
	line("")
	line(c.Bold("CLICKJACKING"))
	var verdictCol func(string) string
	switch res.Clickjacking.Verdict {
	case scanner.VerdictProtected:
		verdictCol = c.Green
	case scanner.VerdictVulnerable:
		verdictCol = c.Red
	default:
		verdictCol = c.Yellow
	}
	line(fmt.Sprintf("  Verdict: %s", verdictCol(res.Clickjacking.Verdict)))
	line("  " + res.Clickjacking.Explanation)

	// Cookies.
	line("")
	line(c.Bold("COOKIES"))
	if !res.Cookies.Applicable {
		line("  No cookies set.")
	} else {
		for _, ck := range res.Cookies.Items {
			var flags []string
			if ck.Secure {
				flags = append(flags, "Secure")
			}
			if ck.HTTPOnly {
				flags = append(flags, "HttpOnly")
			}
			if ck.SameSite != "" {
				flags = append(flags, "SameSite="+ck.SameSite)
			}
			col := statusColor(ck.Status, c)
			line(fmt.Sprintf("  %s %s [%s]",
				col(statusMarkers[ck.Status]), col(ck.Name), col(strings.Join(flags, ", "))))
			for _, is := range ck.Issues {
				line("      " + is)
			}
		}
	}
	for _, f := range res.Cookies.Fatal {
		line("  " + c.Red("FATAL: "+f))
	}

	// TLS.
	line("")
	line(c.Bold("TLS & HTTPS"))
	if res.TLS.Status != scanner.StatusOK {
		line("  " + c.Red("TLS is not available: "+res.TLS.Error))
	} else {
		var supported []string
		for _, v := range []string{"TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1.0"} {
			if res.TLS.Protocols[v] {
				supported = append(supported, v)
			}
		}
		line("  Protocols  : " + strings.Join(supported, ", "))
		if cert := res.TLS.Cert; cert != nil {
			line("  Subject    : " + cert.Subject)
			line("  Issuer     : " + cert.Issuer)
			line(fmt.Sprintf("  Valid      : %s to %s (%d days left)",
				cert.NotBefore, cert.NotAfter, cert.DaysRemaining))
			line(fmt.Sprintf("  Verified   : chain=%v hostname=%v", cert.ChainValid, cert.HostnameMatch))
		}
	}

	// Redirects.
	line("")
	line(c.Bold("REDIRECTS & HTTPS"))
	if res.Redirects.HopCount == 0 {
		line("  No redirects.")
	} else {
		for _, h := range res.Redirects.Hops {
			up := ""
			if h.SchemeUpgrade {
				up = " (http->https upgrade)"
			}
			line(fmt.Sprintf("  %d. %s -> %d %s%s", h.Index, h.URL, h.StatusCode, h.Location, up))
		}
	}
	if res.Redirects.Capped {
		line("  " + c.Red("The redirect chain hit the 10-hop limit."))
	}

	// DNS.
	line("")
	line(c.Bold("DNS"))
	switch res.DNS.Status {
	case scanner.StatusNA:
		line("  N/A — the target is an IP address, so DNS checks were skipped.")
	case scanner.StatusError:
		line("  " + c.Red("Could not reach any DoH provider."))
	default:
		line("  Provider : " + res.DNS.Provider)
		for _, name := range []string{"dnssec", "caa", "spf", "dmarc"} {
			ch := res.DNS.Checks[name]
			col := statusColor(ch.Status, c)
			line(fmt.Sprintf("  %s %s", col(statusMarkers[ch.Status]), col(strings.ToUpper(name))))
			if len(ch.Records) > 0 {
				line("      " + c.Dim(strings.Join(ch.Records, " | ")))
			}
			if ch.Details != "" {
				line("      " + ch.Details)
			}
		}
	}

	// HSTS preload.
	line("")
	line(c.Bold("HSTS PRELOAD"))
	col := statusColor(res.HSTSPreload.Status, c)
	line(fmt.Sprintf("  %s %s", col(statusMarkers[res.HSTSPreload.Status]), col(res.HSTSPreload.Note)))

	line("")
	line(c.Dim("Authorized testing only — use this tool on systems you own or have permission to test."))
}

// SummaryLine builds one line of summary output (used by batch mode).
func SummaryLine(target string, res *scanner.Result, c Color) string {
	if res.Meta.Status == scanner.StatusError {
		return fmt.Sprintf("%-50s %s", target, c.Red("FAILED: "+res.Meta.Error))
	}
	return fmt.Sprintf("%-50s %s (%d/100)", target, gradeColor(res.Grade.Letter, c), res.Grade.Score)
}
