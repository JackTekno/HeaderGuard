// Package scanner berisi mesin analisis keamanan web HeaderGuard.
package scanner

import (
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// Status hasil pemeriksaan.
const (
	StatusOK      = "ok"
	StatusWarn    = "warn"
	StatusMissing = "missing"
	StatusInfo    = "info"
	StatusNA      = "n/a"
	StatusError   = "error"
	StatusPartial = "partial"
)

// Verdict clickjacking.
const (
	VerdictProtected  = "protected"
	VerdictWarning    = "warning"
	VerdictVulnerable = "vulnerable"
)

// CheckResult adalah hasil pemeriksaan satu aturan header.
type CheckResult struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Status    string   `json:"status"`
	Severity  string   `json:"severity"`
	Weight    int      `json:"weight"`
	Earned    int      `json:"earned"`
	RawValues []string `json:"raw_values"`
	Details   string   `json:"details"`
	Fix       string   `json:"fix"`
}

// HeaderSummary merangkum hasil seluruh aturan header.
type HeaderSummary struct {
	OK      int `json:"ok"`
	Warn    int `json:"warn"`
	Missing int `json:"missing"`
	Info    int `json:"info"`
	// Earned dan Applicable dipakai mesin penilaian, tidak ikut JSON.
	Earned     int `json:"-"`
	Applicable int `json:"-"`
}

// FrameCheck adalah hasil pemeriksaan satu mekanisme anti-framing.
type FrameCheck struct {
	Present bool     `json:"present"`
	Values  []string `json:"values"`
}

// ClickjackingVerdict merangkum perlindungan terhadap clickjacking.
type ClickjackingVerdict struct {
	Verdict           string     `json:"verdict"`
	XFO               FrameCheck `json:"xfo"`
	CSPFrameAncestors FrameCheck `json:"csp_frame_ancestors"`
	Explanation       string     `json:"explanation"`
}

// CookieCheck is the analysis of one cookie. Cookie values are never
// stored or displayed.
type CookieCheck struct {
	Name      string   `json:"name"`
	Domain    string   `json:"domain,omitempty"`
	Path      string   `json:"path,omitempty"`
	MaxAge    string   `json:"max_age,omitempty"`
	Expires   string   `json:"expires,omitempty"`
	Secure    bool     `json:"secure"`
	HTTPOnly  bool     `json:"httponly"`
	SameSite  string   `json:"samesite"`
	Status    string   `json:"status"`
	Issues    []string `json:"issues"`
	SourceHop int      `json:"source_hop"`
}

// Points menghitung kontribusi satu cookie terhadap penilaian (maks 3).
func (c CookieCheck) Points() int {
	p := 0
	if c.Secure {
		p++
	}
	if c.HTTPOnly {
		p++
	}
	ss := strings.ToLower(c.SameSite)
	if ss == "lax" || ss == "strict" || (ss == "none" && c.Secure) {
		p++
	}
	return p
}

// HeaderAnalysis adalah hasil lengkap modul analisis header.
type HeaderAnalysis struct {
	Items     []CheckResult       `json:"items"`
	Summary   HeaderSummary       `json:"summary"`
	Clickjack ClickjackingVerdict `json:"clickjacking"`
}

type checkOutcome struct {
	earned  int
	status  string
	raw     []string
	details string
	fix     string
}

type rule struct {
	id       string
	name     string
	severity string
	weight   int
	check    func(*ruleInput) checkOutcome
}

type ruleInput struct {
	h       http.Header
	scheme  string
	metaCSP string
}

// hvalues mengembalikan semua nilai header (nama dinormalisasi oleh net/http).
func hvalues(h http.Header, name string) []string {
	return h.Values(name)
}

func containsToken(tokens []string, target string) bool {
	for _, t := range tokens {
		if strings.EqualFold(t, target) {
			return true
		}
	}
	return false
}

func containsAnyToken(tokens []string, targets ...string) bool {
	for _, t := range tokens {
		for _, tg := range targets {
			if strings.EqualFold(t, tg) {
				return true
			}
		}
	}
	return false
}

// parseCSP menggabungkan semua header CSP menjadi peta directive → token
// (sesuai CSP3, beberapa header diperlakukan sebagai satu kebijakan).
func parseCSP(values []string) map[string][]string {
	dirs := map[string][]string{}
	for _, v := range values {
		for _, part := range strings.Split(v, ";") {
			f := strings.Fields(strings.TrimSpace(part))
			if len(f) == 0 {
				continue
			}
			name := strings.ToLower(f[0])
			dirs[name] = append(dirs[name], f[1:]...)
		}
	}
	return dirs
}

func frameAncestorsFromHeader(h http.Header) []string {
	return parseCSP(hvalues(h, "Content-Security-Policy"))["frame-ancestors"]
}

// strictFrameAncestors: frame-ancestors ketat = ada dan tanpa wildcard.
func strictFrameAncestors(fa []string) bool {
	return len(fa) > 0 && !containsToken(fa, "*")
}

// parseHSTS mengurai satu nilai Strict-Transport-Security.
func parseHSTS(v string) (maxAge int64, hasMaxAge, includeSubDomains, preload bool) {
	for _, part := range strings.Split(v, ";") {
		p := strings.TrimSpace(part)
		lp := strings.ToLower(p)
		switch {
		case strings.HasPrefix(lp, "max-age="):
			if n, err := strconv.ParseInt(strings.TrimSpace(p[len("max-age="):]), 10, 64); err == nil {
				maxAge, hasMaxAge = n, true
			}
		case lp == "includesubdomains":
			includeSubDomains = true
		case lp == "preload":
			preload = true
		}
	}
	return
}

var metaCSPRe = regexp.MustCompile(`(?is)<meta\b[^>]*\bhttp-equiv\s*=\s*["']?\s*content-security-policy\s*["']?[^>]*>`)
var metaCSPContentRe = regexp.MustCompile(`(?is)\bcontent\s*=\s*(?:"([^"]*)"|'([^']*)')`)

// findMetaCSP mencari <meta http-equiv="Content-Security-Policy"> di body.
func findMetaCSP(body []byte) string {
	tag := metaCSPRe.Find(body)
	if tag == nil {
		return ""
	}
	m := metaCSPContentRe.FindSubmatch(tag)
	for _, g := range m[1:] {
		if g != nil {
			return string(g)
		}
	}
	return ""
}

// --- Aturan bernilai (scored) ---

func checkCSP(in *ruleInput) checkOutcome {
	values := hvalues(in.h, "Content-Security-Policy")
	out := checkOutcome{raw: values}
	if len(values) == 0 {
		if in.metaCSP != "" {
			out.status = StatusWarn
			out.details = fmt.Sprintf("No CSP header, only a <meta http-equiv=\"Content-Security-Policy\"> tag in the HTML: %q. Meta CSP is weaker — the frame-ancestors directive does not work in meta tags, and it does not protect non-HTML responses.", in.metaCSP)
			out.fix = "Serve CSP through an HTTP header instead of a meta tag. Example: Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'"
			return out
		}
		out.status = StatusMissing
		out.details = "No Content-Security-Policy header — the browser will load scripts and styles from anywhere, leaving the site without XSS or clickjacking mitigation."
		out.fix = "Add a CSP header, e.g.: Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'; upgrade-insecure-requests"
		return out
	}

	dirs := parseCSP(values)
	earned := 6
	var warns []string
	if len(dirs["frame-ancestors"]) > 0 {
		earned += 2
	}
	if _, ok := dirs["upgrade-insecure-requests"]; ok {
		earned++
	}
	if _, ok := dirs["base-uri"]; ok {
		earned++
	}
	if containsToken(dirs["object-src"], "'none'") {
		earned++
	}
	src, hasSrc := dirs["script-src"]
	if !hasSrc {
		src, hasSrc = dirs["default-src"]
	}
	if hasSrc && !containsAnyToken(src, "'unsafe-inline'", "'unsafe-eval'", "'unsafe-hashes'") {
		earned++
	}
	if earned > 12 {
		earned = 12
	}

	if len(values) > 1 {
		warns = append(warns, "Multiple CSP headers are combined per CSP3 — make sure the directives do not conflict.")
	}
	if d, ok := dirs["default-src"]; ok && containsToken(d, "*") {
		warns = append(warns, "default-src contains * — every source is allowed, which defeats the purpose of CSP.")
	}
	for _, name := range []string{"script-src", "style-src", "img-src", "object-src"} {
		if d, ok := dirs[name]; ok && containsToken(d, "*") {
			warns = append(warns, name+" contains the * wildcard.")
		}
	}
	if hasSrc && containsAnyToken(src, "'unsafe-inline'", "'unsafe-eval'") {
		warns = append(warns, "'unsafe-inline'/'unsafe-eval' weakens protection against XSS.")
	}

	out.earned = earned
	if len(warns) > 0 {
		out.status = StatusWarn
		out.details = fmt.Sprintf("CSP is present (%d/12 points). %s", earned, strings.Join(warns, " "))
	} else {
		out.status = StatusOK
		out.details = fmt.Sprintf("CSP is present and strict (%d/12 points): framing, script sources, and plugins are restricted.", earned)
	}
	out.fix = "Keep CSP enabled; add any missing directives, such as object-src 'none' and base-uri 'self'."
	return out
}

func checkHSTS(in *ruleInput) checkOutcome {
	values := hvalues(in.h, "Strict-Transport-Security")
	out := checkOutcome{raw: values}
	if in.scheme != "https" {
		out.status = StatusNA
		out.details = "HSTS only applies to HTTPS responses; browsers ignore it over HTTP."
		out.fix = "Enable HTTPS and send HSTS on the HTTPS response."
		return out
	}
	if len(values) == 0 {
		out.status = StatusMissing
		out.details = "Without HSTS, the browser can still be redirected to plain HTTP (e.g. via an http:// link or an SSL-stripping attack)."
		out.fix = "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains (add ; preload once the setup is stable)."
		return out
	}

	maxAge, hasMaxAge, sub, pre := parseHSTS(values[0])
	var warns []string
	if len(values) > 1 {
		warns = append(warns, "Multiple HSTS headers found — browsers use the first one.")
	}
	if !hasMaxAge {
		out.status = StatusWarn
		out.details = "The HSTS header is present but invalid (missing max-age) — browsers will ignore it."
		out.fix = "Fix the format: Strict-Transport-Security: max-age=31536000; includeSubDomains"
		return out
	}

	earned := 0
	switch {
	case maxAge >= 15768000: // 6 months
		earned = 6
	case maxAge >= 86400: // 1 day
		earned = 3
		warns = append(warns, "max-age is below the recommended minimum of 6 months.")
	case maxAge > 0:
		earned = 1
		warns = append(warns, "max-age is very short (under 1 day).")
	default:
		warns = append(warns, "max-age=0 disables HSTS.")
	}
	if sub {
		earned++
	} else {
		warns = append(warns, "Missing includeSubDomains — subdomains are not protected.")
	}
	if pre {
		earned++
	}

	out.earned = earned
	if len(warns) > 0 {
		out.status = StatusWarn
		out.details = strings.Join(warns, " ")
	} else {
		out.status = StatusOK
		out.details = "HSTS is enabled with a long max-age, covers subdomains, and carries the preload flag."
	}
	out.fix = "Use: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
	return out
}

func checkXFO(in *ruleInput) checkOutcome {
	xfo := hvalues(in.h, "X-Frame-Options")
	out := checkOutcome{raw: xfo}
	fa := frameAncestorsFromHeader(in.h)

	if len(xfo) == 0 {
		switch {
		case strictFrameAncestors(fa):
			out.earned = 6
			out.status = StatusOK
			out.details = "No X-Frame-Options header, but CSP frame-ancestors protects against framing. XFO is still useful for older browsers."
			out.fix = "Optional: add X-Frame-Options: DENY for legacy browser support."
		case len(fa) > 0:
			out.earned = 2
			out.status = StatusWarn
			out.details = "CSP frame-ancestors is present but weak (wildcard or permissive value)."
			out.fix = "Set frame-ancestors to 'none' or an explicit list of allowed origins."
		default:
			out.status = StatusMissing
			out.details = "Neither X-Frame-Options nor CSP frame-ancestors is present — other sites can frame this page (clickjacking)."
			out.fix = "Add X-Frame-Options: DENY or Content-Security-Policy: frame-ancestors 'none'"
		}
		return out
	}

	fields := strings.Fields(xfo[0])
	if len(fields) == 0 {
		out.earned = 2
		out.status = StatusWarn
		out.details = "X-Frame-Options has an empty value."
		out.fix = "Use: X-Frame-Options: DENY"
		return out
	}
	first := strings.ToUpper(fields[0])
	earned := 0
	var warns []string
	if len(xfo) > 1 {
		same := true
		for _, v := range xfo[1:] {
			if !strings.EqualFold(strings.TrimSpace(v), xfo[0]) {
				same = false
				break
			}
		}
		if same {
			warns = append(warns, "Duplicate X-Frame-Options headers with the same value.")
		} else {
			earned = 2
			out.earned = earned
			out.status = StatusWarn
			out.details = "Conflicting X-Frame-Options values — browser behavior will be inconsistent."
			out.fix = "Use a single header: X-Frame-Options: DENY"
			return out
		}
	}
	switch first {
	case "DENY", "SAMEORIGIN":
		earned = 8
	case "ALLOW-FROM":
		earned = 3
		warns = append(warns, "ALLOW-FROM is ignored by modern browsers (Chrome/Firefox).")
	default:
		earned = 2
		warns = append(warns, "Unrecognized X-Frame-Options value.")
	}
	if len(fa) > 0 && !strictFrameAncestors(fa) {
		warns = append(warns, "CSP frame-ancestors is weak (wildcard) — it contradicts the strict XFO header.")
	}

	out.earned = earned
	if len(warns) > 0 {
		out.status = StatusWarn
		out.details = strings.Join(warns, " ")
	} else {
		out.status = StatusOK
		out.details = fmt.Sprintf("X-Frame-Options: %s — the page refuses framing.", first)
	}
	out.fix = "Keep DENY (strictest) or use SAMEORIGIN if the site embeds its own frames."
	return out
}

func checkXCTO(in *ruleInput) checkOutcome {
	values := hvalues(in.h, "X-Content-Type-Options")
	out := checkOutcome{raw: values}
	if len(values) == 0 {
		out.status = StatusMissing
		out.details = "Without nosniff, the browser may guess MIME types — opening the door to MIME sniffing."
		out.fix = "Add: X-Content-Type-Options: nosniff"
		return out
	}
	joined := strings.ToLower(strings.Join(values, " "))
	if strings.Contains(joined, "nosniff") {
		extra := []string{}
		for _, t := range strings.Fields(joined) {
			if t != "nosniff" {
				extra = append(extra, t)
			}
		}
		out.earned = 5
		if len(extra) > 0 {
			out.status = StatusWarn
			out.details = fmt.Sprintf("nosniff is set, but there are unrecognized extra tokens: %s.", strings.Join(extra, ", "))
		} else {
			out.status = StatusOK
			out.details = "nosniff is set — the browser must not guess MIME types."
		}
		out.fix = "Use the exact value: X-Content-Type-Options: nosniff"
		return out
	}
	out.earned = 1
	out.status = StatusWarn
	out.details = "The header is present but the value is not nosniff — protection is not active."
	out.fix = "Change the value to: X-Content-Type-Options: nosniff"
	return out
}

func checkReferrerPolicy(in *ruleInput) checkOutcome {
	values := hvalues(in.h, "Referrer-Policy")
	out := checkOutcome{raw: values}
	if len(values) == 0 {
		out.status = StatusMissing
		out.details = "Without Referrer-Policy, the browser sends the full URL to cross-origin sites — which can leak sensitive paths."
		out.fix = "Add: Referrer-Policy: strict-origin-when-cross-origin"
		return out
	}
	strict := map[string]bool{"no-referrer": true, "strict-origin": true, "strict-origin-when-cross-origin": true}
	moderate := map[string]bool{"same-origin": true, "origin-when-cross-origin": true}
	weak := map[string]bool{"unsafe-url": true, "no-referrer-when-downgrade": true, "origin": true}
	maxPoints := 0
	var warns []string
	seen := map[string]bool{}
	for _, v := range values {
		for _, part := range strings.Split(v, ",") {
			for _, tok := range strings.Fields(strings.ToLower(part)) {
				if seen[tok] {
					continue
				}
				seen[tok] = true
				switch {
				case strict[tok]:
					if 5 > maxPoints {
						maxPoints = 5
					}
				case moderate[tok]:
					if 3 > maxPoints {
						maxPoints = 3
					}
				case weak[tok]:
					if 1 > maxPoints {
						maxPoints = 1
					}
				default:
					warns = append(warns, fmt.Sprintf("Unrecognized token: %q.", tok))
				}
			}
		}
	}
	if len(values) > 1 {
		warns = append(warns, "Multiple Referrer-Policy headers — browsers use the last one.")
	}
	out.earned = maxPoints
	if len(warns) > 0 || maxPoints < 5 {
		out.status = StatusWarn
		out.details = strings.Join(warns, " ")
	} else {
		out.status = StatusOK
		out.details = "Strict referrer policy — full URLs are not sent to cross-origin sites."
	}
	out.fix = "Use: Referrer-Policy: strict-origin-when-cross-origin"
	return out
}

func checkPermissionsPolicy(in *ruleInput) checkOutcome {
	values := hvalues(in.h, "Permissions-Policy")
	out := checkOutcome{raw: values}
	if len(values) == 0 {
		out.status = StatusMissing
		out.details = "Without Permissions-Policy, sensitive browser features (camera, microphone, location) are available to every third-party iframe."
		out.fix = "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()"
		return out
	}
	sensitive := map[string]bool{
		"camera": true, "microphone": true, "geolocation": true,
		"payment": true, "usb": true, "hid": true, "display-capture": true,
	}
	var warns []string
	for _, v := range values {
		for _, entry := range strings.Split(v, ",") {
			entry = strings.TrimSpace(entry)
			name, rest, found := strings.Cut(entry, "=")
			if !found || rest == "" {
				continue
			}
			name = strings.ToLower(strings.TrimSpace(name))
			if sensitive[name] && strings.Contains(rest, "*") {
				warns = append(warns, fmt.Sprintf("%s is allowed for all origins (*).", name))
			}
		}
	}
	if len(warns) > 0 {
		out.earned = 2
		out.status = StatusWarn
		out.details = strings.Join(warns, " ")
	} else {
		out.earned = 5
		out.status = StatusOK
		out.details = "Permissions-Policy is set with no wildcards on sensitive features."
	}
	out.fix = "Restrict sensitive features: camera=(), microphone=(), geolocation=(self)"
	return out
}

func checkCOOP(in *ruleInput) checkOutcome {
	values := hvalues(in.h, "Cross-Origin-Opener-Policy")
	out := checkOutcome{raw: values}
	if len(values) == 0 {
		out.status = StatusMissing
		out.details = "Without COOP, a cross-origin window can obtain a reference to this window (enabling attacks such as Spectre-style side channels)."
		out.fix = "Add: Cross-Origin-Opener-Policy: same-origin"
		return out
	}
	v := strings.ToLower(strings.TrimSpace(values[0]))
	switch v {
	case "same-origin":
		out.earned = 4
		out.status = StatusOK
		out.details = "COOP same-origin — the window is isolated from cross-origin openers."
	case "same-origin-allow-popups":
		out.earned = 2
		out.status = StatusWarn
		out.details = "same-origin-allow-popups still lets popups share a reference — isolation is incomplete."
	default:
		out.earned = 1
		out.status = StatusWarn
		out.details = fmt.Sprintf("The value %q does not provide isolation (or is unrecognized).", values[0])
	}
	out.fix = "Use: Cross-Origin-Opener-Policy: same-origin"
	return out
}

func checkCORP(in *ruleInput) checkOutcome {
	values := hvalues(in.h, "Cross-Origin-Resource-Policy")
	out := checkOutcome{raw: values}
	if len(values) == 0 {
		out.status = StatusMissing
		out.details = "Without CORP, cross-origin sites can read this resource outside CORS contexts (e.g. via <script> or <img> in certain attacks)."
		out.fix = "Add: Cross-Origin-Resource-Policy: same-origin"
		return out
	}
	v := strings.ToLower(strings.TrimSpace(values[0]))
	switch v {
	case "same-origin", "same-site":
		out.earned = 3
		out.status = StatusOK
		out.details = fmt.Sprintf("CORP %s — the resource can only be read by the same origin/site.", v)
	case "cross-origin":
		out.earned = 1
		out.status = StatusWarn
		out.details = "CORP cross-origin removes the isolation benefit of the header."
	default:
		out.earned = 1
		out.status = StatusWarn
		out.details = fmt.Sprintf("Unrecognized CORP value: %q.", values[0])
	}
	out.fix = "Use: Cross-Origin-Resource-Policy: same-origin"
	return out
}

func checkCOEP(in *ruleInput) checkOutcome {
	values := hvalues(in.h, "Cross-Origin-Embedder-Policy")
	out := checkOutcome{raw: values}
	if len(values) == 0 {
		out.status = StatusMissing
		out.details = "Without COEP, the page can embed cross-origin resources without CORP — cross-origin isolation (needed for features like SharedArrayBuffer) is not satisfied."
		out.fix = "Add: Cross-Origin-Embedder-Policy: require-corp (roll out gradually — it can break third-party resources that lack CORP)"
		return out
	}
	v := strings.ToLower(strings.TrimSpace(values[0]))
	switch v {
	case "require-corp", "credentialless":
		out.earned = 2
		out.status = StatusOK
		out.details = fmt.Sprintf("COEP %s is active — cross-origin resources must carry CORP.", v)
	default:
		out.earned = 1
		out.status = StatusWarn
		out.details = fmt.Sprintf("The value %q does not enforce isolation (or is unrecognized).", values[0])
	}
	out.fix = "Use: Cross-Origin-Embedder-Policy: require-corp"
	return out
}

func checkDisclosure(in *ruleInput) checkOutcome {
	names := []string{"Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Runtime"}
	var found []string
	var raw []string
	for _, n := range names {
		for _, v := range hvalues(in.h, n) {
			found = append(found, n+": "+v)
			raw = append(raw, v)
		}
	}
	out := checkOutcome{raw: raw}
	if len(found) == 0 {
		out.earned = 3
		out.status = StatusOK
		out.details = "No headers disclose server or technology versions."
		out.fix = "Keep the current configuration."
		return out
	}
	out.earned = 1
	out.status = StatusWarn
	out.details = "These headers disclose server information: " + strings.Join(found, ", ")
	out.fix = "Hide server versions, e.g. ServerTokens Prod (Apache) or proxy_hide_header X-Powered-By (nginx)."
	return out
}

func checkCacheControl(in *ruleInput) checkOutcome {
	values := hvalues(in.h, "Cache-Control")
	out := checkOutcome{raw: values}
	joined := strings.ToLower(strings.Join(values, " "))
	if len(values) == 0 {
		out.status = StatusMissing
		out.details = "Without Cache-Control, browsers and proxies may cache the response — risky for sensitive data."
		out.fix = "For sensitive pages: Cache-Control: no-store"
		return out
	}
	switch {
	case strings.Contains(joined, "no-store"):
		out.earned = 3
		out.status = StatusOK
		out.details = "no-store is set — the response will not be stored."
	case strings.Contains(joined, "private") || strings.Contains(joined, "no-cache"):
		out.earned = 2
		out.status = StatusOK
		out.details = "private/no-cache is adequate for public content; pages with sensitive data should use no-store."
	default:
		out.earned = 1
		out.status = StatusWarn
		out.details = "The response is cacheable (public/max-age) — make sure it contains no sensitive data."
	}
	out.fix = "Sensitive pages must use: Cache-Control: no-store"
	return out
}

func checkACAO(in *ruleInput) checkOutcome {
	values := hvalues(in.h, "Access-Control-Allow-Origin")
	out := checkOutcome{raw: values}
	if len(values) == 0 {
		out.earned = 2
		out.status = StatusOK
		out.details = "No Access-Control-Allow-Origin header. Unless this is a CORS API, this is safe — browsers block cross-origin reads by default."
		out.fix = "No action needed unless this endpoint is meant to be a CORS API."
		return out
	}
	var warns []string
	earned := 2
	for _, v := range values {
		switch strings.TrimSpace(v) {
		case "*":
			earned = 1
			warns = append(warns, "The * wildcard lets any site read this response.")
		case "null":
			earned = 1
			warns = append(warns, "The 'null' value can be abused by sandboxed origins.")
		}
	}
	if len(hvalues(in.h, "Set-Cookie")) > 0 && containsToken(values, "*") {
		warns = append(warns, "The response also sets cookies — combining a wildcard with credentials is high risk.")
	}
	out.earned = earned
	if len(warns) > 0 {
		out.status = StatusWarn
		out.details = strings.Join(warns, " ")
	} else {
		out.status = StatusOK
		out.details = "CORS is restricted to a specific origin."
	}
	out.fix = "Allow only the origins you actually need, not a wildcard."
	return out
}

// --- Aturan informasional (bobot 0, tidak memengaruhi nilai) ---

func checkXSSP(in *ruleInput) checkOutcome {
	values := hvalues(in.h, "X-XSS-Protection")
	out := checkOutcome{raw: values}
	joined := strings.ToLower(strings.Join(values, " "))
	if len(values) > 0 && (strings.Contains(joined, "1") || strings.Contains(joined, "mode=block")) {
		out.details = "X-XSS-Protection: 1; mode=block can be abused in some scenarios; current guidance is to remove this header or set it to 0."
	} else {
		out.details = "Absent (or 0) — not needed in modern browsers; CSP is the primary XSS mitigation."
	}
	out.status = StatusInfo
	out.fix = "Remove this header or set: X-XSS-Protection: 0"
	return out
}

func checkExpectCT(in *ruleInput) checkOutcome {
	values := hvalues(in.h, "Expect-CT")
	out := checkOutcome{raw: values}
	if len(values) > 0 {
		out.details = "Expect-CT was removed from Chrome in 2023 — this header is obsolete and has no effect."
	} else {
		out.details = "Absent — no longer needed (Expect-CT was removed from Chrome in 2023)."
	}
	out.status = StatusInfo
	out.fix = "Remove it if still present."
	return out
}

func checkFeaturePolicy(in *ruleInput) checkOutcome {
	values := hvalues(in.h, "Feature-Policy")
	out := checkOutcome{raw: values}
	if len(values) > 0 {
		out.details = "Feature-Policy is the deprecated predecessor of Permissions-Policy."
	} else {
		out.details = "Absent — use Permissions-Policy instead."
	}
	out.status = StatusInfo
	out.fix = "Migrate to: Permissions-Policy: camera=(), microphone=(), geolocation=()"
	return out
}

func checkLegacyCSP(in *ruleInput) checkOutcome {
	var values []string
	values = append(values, hvalues(in.h, "X-WebKit-CSP")...)
	values = append(values, hvalues(in.h, "X-Content-Security-Policy")...)
	out := checkOutcome{raw: values}
	if len(values) > 0 {
		out.details = "Legacy CSP variant for very old Safari — it does not replace the standard Content-Security-Policy header."
	} else {
		out.details = "Absent — only needed if you support very old Safari."
	}
	out.status = StatusInfo
	out.fix = "Keep the standard CSP header in place; the legacy header is optional."
	return out
}

func checkP3P(in *ruleInput) checkOutcome {
	values := hvalues(in.h, "P3P")
	out := checkOutcome{raw: values}
	if len(values) > 0 {
		out.details = "P3P is obsolete (Internet Explorer era); some sites keep it for legacy cache compatibility."
	} else {
		out.details = "Absent — not needed in modern browsers."
	}
	out.status = StatusInfo
	out.fix = "Can be removed unless you target legacy IE."
	return out
}

func checkClearSiteData(in *ruleInput) checkOutcome {
	values := hvalues(in.h, "Clear-Site-Data")
	out := checkOutcome{raw: values}
	if len(values) > 0 {
		out.details = "Clear-Site-Data is set — useful on logout endpoints to clear the user's local data."
	} else {
		out.details = "Absent — relevant if the site has a logout endpoint."
	}
	out.status = StatusInfo
	out.fix = "Send Clear-Site-Data: \"cache\", \"cookies\", \"storage\" on the logout response."
	return out
}

func checkCSPReportOnly(in *ruleInput) checkOutcome {
	values := hvalues(in.h, "Content-Security-Policy-Report-Only")
	out := checkOutcome{raw: values}
	if len(values) > 0 {
		out.details = "CSP Report-Only reports violations without enforcing them — actual protection still comes from the main CSP."
	} else {
		out.details = "Absent — the enforced policy comes from the main CSP."
	}
	out.status = StatusInfo
	out.fix = "Use Report-Only to test a new CSP before enforcing it."
	return out
}

func checkContentType(in *ruleInput) checkOutcome {
	values := hvalues(in.h, "Content-Type")
	out := checkOutcome{raw: values}
	switch {
	case len(values) == 0:
		out.details = "No Content-Type header."
	case strings.Contains(strings.ToLower(values[0]), "charset"):
		out.details = "Content-Type declares the charset explicitly."
	default:
		out.details = "Content-Type has no charset=utf-8 — the browser will guess the encoding."
	}
	out.status = StatusInfo
	out.fix = "Use: Content-Type: text/html; charset=utf-8"
	return out
}

// rulesTable mengembalikan seluruh aturan dalam urutan tampilan.
func rulesTable() []rule {
	return []rule{
		{"csp", "Content-Security-Policy", "high", 12, checkCSP},
		{"hsts", "Strict-Transport-Security", "high", 8, checkHSTS},
		{"xfo", "X-Frame-Options", "high", 8, checkXFO},
		{"xcto", "X-Content-Type-Options", "medium", 5, checkXCTO},
		{"referrer-policy", "Referrer-Policy", "medium", 5, checkReferrerPolicy},
		{"permissions-policy", "Permissions-Policy", "medium", 5, checkPermissionsPolicy},
		{"coop", "Cross-Origin-Opener-Policy", "medium", 4, checkCOOP},
		{"corp", "Cross-Origin-Resource-Policy", "medium", 3, checkCORP},
		{"coep", "Cross-Origin-Embedder-Policy", "low", 2, checkCOEP},
		{"disclosure", "Pengungkapan Info Server", "low", 3, checkDisclosure},
		{"cache-control", "Cache-Control", "low", 3, checkCacheControl},
		{"acao", "Access-Control-Allow-Origin", "low", 2, checkACAO},
		{"x-xss-protection", "X-XSS-Protection", "info", 0, checkXSSP},
		{"expect-ct", "Expect-CT", "info", 0, checkExpectCT},
		{"feature-policy", "Feature-Policy", "info", 0, checkFeaturePolicy},
		{"legacy-csp", "CSP Legacy (X-WebKit-CSP)", "info", 0, checkLegacyCSP},
		{"p3p", "P3P", "info", 0, checkP3P},
		{"clear-site-data", "Clear-Site-Data", "info", 0, checkClearSiteData},
		{"csp-report-only", "CSP Report-Only", "info", 0, checkCSPReportOnly},
		{"content-type", "Content-Type (charset)", "info", 0, checkContentType},
	}
}

// computeClickjacking menentukan verdict perlindungan clickjacking.
func computeClickjacking(xfo, fa []string) ClickjackingVerdict {
	v := ClickjackingVerdict{
		XFO:               FrameCheck{Present: len(xfo) > 0, Values: xfo},
		CSPFrameAncestors: FrameCheck{Present: len(fa) > 0, Values: fa},
	}
	strongXFO := false
	for _, x := range xfo {
		u := strings.ToUpper(strings.TrimSpace(x))
		if u == "DENY" || u == "SAMEORIGIN" {
			strongXFO = true
		}
	}
	switch {
	case strongXFO:
		v.Verdict = VerdictProtected
		v.Explanation = "X-Frame-Options denies framing — the page is protected against clickjacking."
	case strictFrameAncestors(fa):
		v.Verdict = VerdictProtected
		v.Explanation = "CSP frame-ancestors restricts framing — the page is protected against clickjacking."
	case len(xfo) > 0 || len(fa) > 0:
		v.Verdict = VerdictWarning
		v.Explanation = "Some anti-framing mechanism is present but weak or inconsistent — verify manually."
	default:
		v.Verdict = VerdictVulnerable
		v.Explanation = "No anti-framing protection — the page is vulnerable to clickjacking."
	}
	return v
}

// AnalyzeHeaders menganalisis header respons final (murni, tanpa I/O).
func AnalyzeHeaders(h http.Header, body []byte, scheme string) *HeaderAnalysis {
	meta := findMetaCSP(body)
	in := &ruleInput{h: h, scheme: scheme, metaCSP: meta}
	an := &HeaderAnalysis{}
	for _, r := range rulesTable() {
		oc := r.check(in)
		item := CheckResult{
			ID:        r.id,
			Name:      r.name,
			Severity:  r.severity,
			Weight:    r.weight,
			Status:    oc.status,
			Earned:    oc.earned,
			RawValues: oc.raw,
			Details:   oc.details,
			Fix:       oc.fix,
		}
		an.Items = append(an.Items, item)
		switch oc.status {
		case StatusOK:
			an.Summary.OK++
		case StatusWarn:
			an.Summary.Warn++
		case StatusMissing:
			an.Summary.Missing++
		case StatusInfo:
			an.Summary.Info++
		}
		if oc.status != StatusNA {
			an.Summary.Earned += oc.earned
			an.Summary.Applicable += r.weight
		}
	}
	an.Clickjack = computeClickjacking(
		hvalues(h, "X-Frame-Options"),
		frameAncestorsFromHeader(h),
	)
	return an
}

// parseSetCookie parses one Set-Cookie value. net/http is intentionally not
// used because http.Cookie cannot round-trip the SameSite attribute.
func parseSetCookie(raw string, hop int, scheme string) CookieCheck {
	c := CookieCheck{SourceHop: hop}
	sawSameSite := false
	for i, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		if i == 0 {
			if eq := strings.Index(part, "="); eq >= 0 {
				c.Name = part[:eq]
			} else {
				c.Name = part
			}
			continue
		}
		key, val, _ := strings.Cut(part, "=")
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "secure":
			c.Secure = true
		case "httponly":
			c.HTTPOnly = true
		case "samesite":
			c.SameSite = strings.TrimSpace(val)
			sawSameSite = true
		case "path":
			c.Path = strings.TrimSpace(val)
		case "domain":
			c.Domain = strings.TrimSpace(val)
		case "max-age":
			c.MaxAge = strings.TrimSpace(val)
		case "expires":
			c.Expires = strings.TrimSpace(val)
		}
	}

	ss := strings.ToLower(c.SameSite)
	switch {
	case !sawSameSite:
		c.Issues = append(c.Issues, "Missing SameSite attribute (CSRF risk; modern browsers default to Lax, but explicit is better).")
	case c.SameSite == "" || (ss != "lax" && ss != "strict" && ss != "none"):
		c.Issues = append(c.Issues, fmt.Sprintf("Invalid SameSite value %q.", c.SameSite))
	}
	if ss == "none" && !c.Secure {
		c.Issues = append(c.Issues, "SameSite=None without Secure — browsers reject this cookie (and it is risky if accepted).")
	}
	if !c.HTTPOnly {
		c.Issues = append(c.Issues, "Missing HttpOnly flag — accessible to JavaScript (risk in XSS attacks).")
	}
	if !c.Secure && scheme == "https" {
		c.Issues = append(c.Issues, "Missing Secure flag although the site uses HTTPS.")
	}

	if len(c.Issues) > 0 {
		c.Status = StatusWarn
	} else {
		c.Status = StatusOK
	}
	return c
}

// ParseCookies mengurai seluruh header Set-Cookie pada satu hop.
func ParseCookies(raw []string, hop int, scheme string) []CookieCheck {
	out := make([]CookieCheck, 0, len(raw))
	for _, r := range raw {
		out = append(out, parseSetCookie(r, hop, scheme))
	}
	return out
}
