// Package window décrit les fenêtres de maintenance : créneaux hebdomadaires
// (jours, heure de début, durée) pendant lesquels les lots programmés et la
// sécurité automatique peuvent s'exécuter.
package window

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Window est une fenêtre de maintenance.
type Window struct {
	Name     string
	Days     []time.Weekday // vide : tous les jours
	Hour     int
	Minute   int
	Duration time.Duration
	Tags     []string // vide : tous les invités
}

var dayNames = map[string]time.Weekday{
	"lun": time.Monday, "mar": time.Tuesday, "mer": time.Wednesday, "jeu": time.Thursday,
	"ven": time.Friday, "sam": time.Saturday, "dim": time.Sunday,
}

var dayLabels = map[time.Weekday]string{
	time.Monday: "lun", time.Tuesday: "mar", time.Wednesday: "mer", time.Thursday: "jeu",
	time.Friday: "ven", time.Saturday: "sam", time.Sunday: "dim",
}

// New construit une fenêtre à partir de la configuration (jours « lun »…
// « dim », début « HH:MM », durée de 5 min à 24 h).
func New(name string, days []string, start string, d time.Duration, tags []string) (Window, error) {
	w := Window{Name: name, Duration: d, Tags: tags}
	t, err := time.Parse("15:04", start)
	if err != nil {
		return w, fmt.Errorf("début « HH:MM » attendu, obtenu %q", start)
	}
	w.Hour, w.Minute = t.Hour(), t.Minute()
	for _, s := range days {
		wd, ok := dayNames[strings.ToLower(strings.TrimSpace(s))]
		if !ok {
			return w, fmt.Errorf("jour inconnu %q (lun, mar, mer, jeu, ven, sam, dim)", s)
		}
		w.Days = append(w.Days, wd)
	}
	if d < 5*time.Minute || d > 24*time.Hour {
		return w, fmt.Errorf("durée de 5 min à 24 h attendue, obtenu %s", d)
	}
	return w, nil
}

func (w Window) onDay(d time.Weekday) bool {
	if len(w.Days) == 0 {
		return true
	}
	for _, x := range w.Days {
		if x == d {
			return true
		}
	}
	return false
}

// Next renvoie la fenêtre en cours ou la prochaine : début et fin, en heure locale.
func (w Window) Next(now time.Time) (start, end time.Time) {
	now = now.Local()
	for day := -1; day <= 8; day++ {
		s := time.Date(now.Year(), now.Month(), now.Day()+day, w.Hour, w.Minute, 0, 0, now.Location())
		if !w.onDay(s.Weekday()) {
			continue
		}
		e := s.Add(w.Duration)
		if e.After(now) {
			return s, e
		}
	}
	return time.Time{}, time.Time{}
}

// Open dit si la fenêtre est ouverte à cet instant.
func (w Window) Open(now time.Time) bool {
	s, _ := w.Next(now)
	return !s.IsZero() && !s.After(now)
}

// Applies dit si la fenêtre concerne un invité portant ces tags.
func (w Window) Applies(tags []string) bool {
	if len(w.Tags) == 0 {
		return true
	}
	for _, t := range tags {
		for _, x := range w.Tags {
			if strings.EqualFold(t, x) {
				return true
			}
		}
	}
	return false
}

// Label décrit la fenêtre (« dim 03:00, 2h »).
func (w Window) Label() string {
	days := "tous les jours"
	if len(w.Days) > 0 {
		ds := append([]time.Weekday(nil), w.Days...)
		sort.Slice(ds, func(i, j int) bool { return (ds[i]+6)%7 < (ds[j]+6)%7 })
		parts := make([]string, len(ds))
		for i, d := range ds {
			parts[i] = dayLabels[d]
		}
		days = strings.Join(parts, ", ")
	}
	return fmt.Sprintf("%s %02d:%02d, %s", days, w.Hour, w.Minute, strings.TrimSuffix(strings.TrimSuffix(w.Duration.String(), "0s"), "0m"))
}

// FormatTime : « dim. 30/11 03:00 ».
func FormatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	t = t.Local()
	return dayLabels[t.Weekday()] + " " + t.Format("02/01 15:04")
}
