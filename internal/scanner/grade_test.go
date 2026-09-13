package scanner

import "testing"

func TestLetterFor(t *testing.T) {
	tests := []struct {
		score int
		want  string
	}{
		{100, "A+"}, {95, "A+"}, {94, "A"}, {85, "A"}, {84, "B"},
		{70, "B"}, {69, "C"}, {55, "C"}, {54, "D"}, {40, "D"},
		{39, "E"}, {25, "E"}, {24, "F"}, {0, "F"},
	}
	for _, tt := range tests {
		if got := letterFor(tt.score); got != tt.want {
			t.Errorf("letterFor(%d) = %s, want %s", tt.score, got, tt.want)
		}
	}
}

func TestComputeGradePerfect(t *testing.T) {
	g := ComputeGrade(GradeInput{
		Headers: CategoryScore{Earned: 60, Applicable: 60},
		Cookies: CategoryScore{Earned: 15, Applicable: 15},
		TLS:     CategoryScore{Earned: 15, Applicable: 15},
		DNS:     CategoryScore{Earned: 10, Applicable: 10},
	})
	if g.Letter != "A+" || g.Score != 100 {
		t.Errorf("grade = %s (%d), want A+ (100)", g.Letter, g.Score)
	}
	if len(g.CapsApplied) != 0 {
		t.Errorf("caps = %v, want kosong", g.CapsApplied)
	}
}

func TestComputeGradeAllZero(t *testing.T) {
	g := ComputeGrade(GradeInput{
		Headers: CategoryScore{Earned: 0, Applicable: 60},
		TLS:     CategoryScore{Earned: 0, Applicable: 15},
	})
	if g.Letter != "F" || g.Score != 0 {
		t.Errorf("grade = %s (%d), want F (0)", g.Letter, g.Score)
	}
}

func TestComputeGradeNothingApplicable(t *testing.T) {
	g := ComputeGrade(GradeInput{})
	if g.Letter != "-" {
		t.Errorf("letter = %s, want '-'", g.Letter)
	}
}

func TestComputeGradeCookieFatalCap(t *testing.T) {
	g := ComputeGrade(GradeInput{
		Headers:     CategoryScore{Earned: 60, Applicable: 60},
		Cookies:     CategoryScore{Earned: 15, Applicable: 15},
		TLS:         CategoryScore{Earned: 15, Applicable: 15},
		DNS:         CategoryScore{Earned: 10, Applicable: 10},
		CookieFatal: true,
	})
	if g.Letter != "B" || g.Score != 70 {
		t.Errorf("grade = %s (%d), want B (70)", g.Letter, g.Score)
	}
	if len(g.CapsApplied) != 1 {
		t.Errorf("caps = %v, want 1 cap", g.CapsApplied)
	}
}

func TestComputeGradeRenormalize(t *testing.T) {
	// Hanya headers yang berlaku (cookies/tls/dns n/a): 30/60 → 50 → D.
	g := ComputeGrade(GradeInput{
		Headers: CategoryScore{Earned: 30, Applicable: 60},
	})
	if g.Letter != "D" || g.Score != 50 {
		t.Errorf("grade = %s (%d), want D (50)", g.Letter, g.Score)
	}
}
