package scanner

import "math"

// CategoryScore is the score of one grading category.
type CategoryScore struct {
	Earned     int `json:"earned"`
	Applicable int `json:"applicable"`
}

// GradeInput is the pure input to the grading engine.
type GradeInput struct {
	Headers     CategoryScore
	Cookies     CategoryScore
	TLS         CategoryScore
	DNS         CategoryScore
	CookieFatal bool // a SameSite=None cookie without Secure is present
}

// Grade is the final grading result.
type Grade struct {
	Letter      string                   `json:"letter"`
	Score       int                      `json:"score"`
	Breakdown   map[string]CategoryScore `json:"breakdown"`
	CapsApplied []string                 `json:"caps_applied,omitempty"`
}

// ComputeGrade computes a 0-100 score with renormalization: categories that
// do not apply (n/a) are excluded from both the numerator and denominator.
func ComputeGrade(in GradeInput) Grade {
	g := Grade{
		Breakdown: map[string]CategoryScore{
			"headers": in.Headers,
			"cookies": in.Cookies,
			"tls":     in.TLS,
			"dns":     in.DNS,
		},
	}
	totalEarned := in.Headers.Earned + in.Cookies.Earned + in.TLS.Earned + in.DNS.Earned
	totalApplicable := in.Headers.Applicable + in.Cookies.Applicable + in.TLS.Applicable + in.DNS.Applicable

	if totalApplicable == 0 {
		g.Letter = "-"
		return g
	}
	score := int(math.Round(100 * float64(totalEarned) / float64(totalApplicable)))

	// Satu-satunya cap: cookie SameSite=None tanpa Secure membatasi nilai
	// maksimal B (70) — kesalahan fatal yang tidak bisa ditutup poin lain.
	if in.CookieFatal && score > 70 {
		score = 70
		g.CapsApplied = append(g.CapsApplied,
			"SameSite=None without Secure caps the grade at B")
	}

	g.Score = score
	g.Letter = letterFor(score)
	return g
}

// letterFor maps a score to a grade letter.
func letterFor(score int) string {
	switch {
	case score >= 95:
		return "A+"
	case score >= 85:
		return "A"
	case score >= 70:
		return "B"
	case score >= 55:
		return "C"
	case score >= 40:
		return "D"
	case score >= 25:
		return "E"
	default:
		return "F"
	}
}
