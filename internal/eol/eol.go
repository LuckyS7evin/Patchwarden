// Package eol indique si le système d'un invité reçoit encore des correctifs
// de sécurité. Les dates viennent d'une table intégrée, rafraîchie en arrière-
// plan depuis endoflife.date si c'est autorisé : une page n'attend jamais le
// réseau.
package eol

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Cycle est une version majeure d'un système.
type Cycle struct {
	Cycle    string
	EOL      time.Time // fin du support standard (correctifs de sécurité)
	Extended time.Time // fin du support étendu (Debian LTS, Ubuntu Pro), zéro si aucun
}

// Status est l'état du support d'un système.
type Status struct {
	Level string // "ok", "warn", "crit" ; vide si inconnu
	Text  string
	Name  string // « Debian 12 »
}

func d(s string) time.Time {
	t, _ := time.Parse("2006-01-02", s)
	return t
}

// table : dates publiées (endoflife.date, novembre 2026). Rafraîchies en ligne
// quand c'est autorisé ; sinon mises à jour avec PatchWarden.
var table = map[string][]Cycle{
	"debian": {
		{"9", d("2020-07-06"), d("2022-06-30")},
		{"10", d("2022-09-10"), d("2024-06-30")},
		{"11", d("2024-08-14"), d("2026-08-31")},
		{"12", d("2026-06-10"), d("2028-06-30")},
		{"13", d("2028-08-09"), d("2030-06-30")},
	},
	"ubuntu": {
		{"18.04", d("2023-05-31"), d("2028-04-01")},
		{"20.04", d("2025-05-29"), d("2030-04-02")},
		{"22.04", d("2027-06-01"), d("2032-04-09")},
		{"24.04", d("2029-05-31"), d("2034-04-25")},
		{"24.10", d("2025-07-10"), time.Time{}},
		{"25.04", d("2026-01-15"), time.Time{}},
		{"25.10", d("2026-07-09"), time.Time{}},
	},
	"alpine": {
		{"3.17", d("2024-11-22"), time.Time{}},
		{"3.18", d("2025-05-09"), time.Time{}},
		{"3.19", d("2025-11-01"), time.Time{}},
		{"3.20", d("2026-04-01"), time.Time{}},
		{"3.21", d("2026-11-01"), time.Time{}},
		{"3.22", d("2027-05-01"), time.Time{}},
	},
}

var names = map[string]string{"debian": "Debian", "ubuntu": "Ubuntu", "alpine": "Alpine"}
var extName = map[string]string{"debian": "Debian LTS", "ubuntu": "Ubuntu Pro (ESM)"}

// Normalize renvoie le produit et la version majeure suivis (vide si inconnus).
func Normalize(osID, version string) (product, cycle string) {
	product = strings.ToLower(osID)
	if _, ok := table[product]; !ok {
		return "", ""
	}
	parts := strings.Split(version, ".")
	switch product {
	case "debian":
		return product, parts[0]
	default: // ubuntu 22.04, alpine 3.19(.1)
		if len(parts) >= 2 {
			return product, parts[0] + "." + parts[1]
		}
		return product, version
	}
}

// Warn : fin du support signalée à l'avance.
const Warn = 180 * 24 * time.Hour

func frDate(t time.Time) string { return t.Format("02/01/2006") }

// Evaluate calcule l'état d'un cycle à la date now.
func Evaluate(product string, c Cycle, now time.Time) Status {
	st := Status{Name: names[product] + " " + c.Cycle}
	switch {
	case c.EOL.IsZero():
		st.Level, st.Text = "ok", "supporté"
	case !c.Extended.IsZero() && now.After(c.Extended):
		st.Level, st.Text = "crit", "plus aucun correctif de sécurité depuis le "+frDate(c.Extended)
	case !c.Extended.IsZero() && now.After(c.EOL):
		st.Level = "warn"
		st.Text = fmt.Sprintf("support standard terminé le %s ; correctifs %s jusqu'au %s", frDate(c.EOL), extName[product], frDate(c.Extended))
	case c.Extended.IsZero() && now.After(c.EOL):
		st.Level, st.Text = "crit", "plus aucun correctif de sécurité depuis le "+frDate(c.EOL)
	case c.EOL.Sub(now) < Warn:
		st.Level = "warn"
		st.Text = fmt.Sprintf("fin du support le %s (dans %d jours)", frDate(c.EOL), int(c.EOL.Sub(now).Hours()/24)+1)
	default:
		st.Level, st.Text = "ok", "supporté jusqu'au "+frDate(c.EOL)
	}
	return st
}

// Checker fournit l'état du support, avec rafraîchissement en ligne facultatif.
type Checker struct {
	base string // ex. https://endoflife.date/api ; vide : table intégrée seule
	http *http.Client
	ttl  time.Duration

	mu       sync.Mutex
	online   map[string][]Cycle
	fetched  map[string]time.Time
	inflight map[string]bool
}

// New crée un vérificateur. base vide : table intégrée seule.
func New(base string, hc *http.Client) *Checker {
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	return &Checker{base: strings.TrimRight(base, "/"), http: hc, ttl: 24 * time.Hour,
		online: map[string][]Cycle{}, fetched: map[string]time.Time{}, inflight: map[string]bool{}}
}

// Status renvoie l'état du support d'un système (vide si inconnu).
func (c *Checker) Status(osID, version string, now time.Time) Status {
	product, cycle := Normalize(osID, version)
	if product == "" || cycle == "" {
		return Status{}
	}
	for _, cy := range c.cycles(product, now) {
		if cy.Cycle == cycle {
			return Evaluate(product, cy, now)
		}
	}
	return Status{Name: names[product] + " " + cycle, Text: "version absente de la table de fin de support"}
}

func (c *Checker) cycles(product string, now time.Time) []Cycle {
	if c == nil {
		return table[product]
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.base != "" && now.Sub(c.fetched[product]) > c.ttl && !c.inflight[product] {
		c.inflight[product] = true
		go c.refresh(product)
	}
	if l, ok := c.online[product]; ok && len(l) > 0 {
		return l
	}
	return table[product]
}

// Refresh lit endoflife.date de façon synchrone (tests, démarrage).
func (c *Checker) Refresh(product string) error {
	c.mu.Lock()
	c.inflight[product] = true
	c.mu.Unlock()
	return c.refresh(product)
}

func (c *Checker) refresh(product string) error {
	defer func() {
		c.mu.Lock()
		c.inflight[product] = false
		c.fetched[product] = time.Now()
		c.mu.Unlock()
	}()
	resp, err := c.http.Get(c.base + "/" + product + ".json")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("endoflife.date : HTTP %d", resp.StatusCode)
	}
	var raw []struct {
		Cycle    json.RawMessage `json:"cycle"`
		Support  json.RawMessage `json:"support"`
		EOL      json.RawMessage `json:"eol"`
		Extended json.RawMessage `json:"extendedSupport"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return err
	}
	var out []Cycle
	for _, r := range raw {
		cy := strings.Trim(string(r.Cycle), `"`)
		if cy == "" {
			continue
		}
		c := Cycle{Cycle: cy, EOL: rawDate(r.EOL), Extended: rawDate(r.Extended)}
		if product == "debian" {
			// endoflife.date : pour Debian, « eol » est la fin de Debian LTS
			// (correctifs gratuits) et « extendedSupport » celle d'ELTS, une
			// offre payante (Freexian) : ignorée. La fin du support standard
			// (équipe sécurité) est « support » quand il est publié.
			c.Extended = time.Time{}
			if std := rawDate(r.Support); !std.IsZero() && std.Before(c.EOL) {
				c.EOL, c.Extended = std, c.EOL
			}
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return fmt.Errorf("endoflife.date : réponse vide pour %s", product)
	}
	c.mu.Lock()
	c.online[product] = out
	c.mu.Unlock()
	return nil
}

// rawDate lit une date (« 2026-06-10 ») ; un booléen ou une absence donnent zéro.
func rawDate(b json.RawMessage) time.Time {
	var s string
	if json.Unmarshal(b, &s) != nil {
		return time.Time{}
	}
	return d(s)
}
