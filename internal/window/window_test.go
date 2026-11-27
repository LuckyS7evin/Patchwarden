package window

import (
	"testing"
	"time"
)

func TestNextAndOpen(t *testing.T) {
	w, err := New("nuit", []string{"dim", "mer"}, "03:00", 2*time.Hour, []string{"media"})
	if err != nil {
		t.Fatal(err)
	}
	// Jeudi 26/11/2026 10:00 → prochaine : dimanche 29/11 03:00.
	now := time.Date(2026, 11, 26, 10, 0, 0, 0, time.Local)
	s, e := w.Next(now)
	if s.Weekday() != time.Sunday || s.Day() != 29 || s.Hour() != 3 || e.Sub(s) != 2*time.Hour || w.Open(now) {
		t.Errorf("prochaine : %v → %v", s, e)
	}
	// Dimanche 04:00 : fenêtre ouverte, encore en cours.
	in := time.Date(2026, 11, 29, 4, 0, 0, 0, time.Local)
	if s, _ := w.Next(in); s.Day() != 29 || !w.Open(in) {
		t.Errorf("fenêtre en cours : %v", s)
	}
	if !w.Applies([]string{"Media"}) || w.Applies([]string{"web"}) {
		t.Error("tags")
	}
	if w.Label() != "mer, dim 03:00, 2h" {
		t.Errorf("libellé : %q", w.Label())
	}
	if _, err := New("x", []string{"lundi"}, "03:00", time.Hour, nil); err == nil {
		t.Error("jour invalide accepté")
	}
	daily, _ := New("x", nil, "23:30", time.Hour, nil)
	if s, e := daily.Next(time.Date(2026, 11, 27, 0, 10, 0, 0, time.Local)); s.Day() != 26 || e.Day() != 27 {
		t.Errorf("fenêtre à cheval sur minuit : %v → %v", s, e)
	}
}
