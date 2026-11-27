// Package notify envoie les notifications de PatchWarden vers ntfy, Gotify ou
// un webhook générique. Un échec d'envoi est journalisé, jamais bloquant.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/LuckyS7evin/patchwarden/internal/config"
)

// Event est la nature d'une notification.
type Event string

// Événements.
const (
	// EvSecurity : nouveaux correctifs de sécurité détectés.
	EvSecurity Event = "securite"
	// EvApps : nouvelles versions d'applications community-scripts.
	EvApps Event = "applis"
	// EvFailure : échec d'une mise à jour ou d'une détection planifiée.
	EvFailure Event = "echec"
	// EvSuccess : mise à jour réussie.
	EvSuccess Event = "succes"
	// EvTest : message de test (envoyé à toutes les cibles).
	EvTest Event = "test"
)

// AllEvents liste les événements configurables.
var AllEvents = []Event{EvSecurity, EvApps, EvFailure, EvSuccess}

// Message est une notification.
type Message struct {
	Event    Event
	Title    string
	Body     string
	Priority int    // 1 (min) à 5 (urgent)
	URL      string // lien vers PatchWarden, facultatif
	// Always : envoyé à toutes les cibles, quel que soit leur filtre
	// d'événements (actions automatiques).
	Always bool
}

// Target est une destination configurée.
type Target struct {
	cfg    config.Notify
	events map[Event]bool
	http   *http.Client
}

// Name décrit la cible (sans secret).
func (t *Target) Name() string {
	u, err := url.Parse(t.cfg.URL)
	if err != nil {
		return t.cfg.Type
	}
	return t.cfg.Type + " " + u.Host + u.Path
}

// Hub distribue les messages aux cibles abonnées à l'événement.
type Hub struct {
	targets []*Target
	log     *slog.Logger
}

// New construit le distributeur à partir de la configuration (déjà validée).
func New(cfgs []config.Notify, hc *http.Client, log *slog.Logger) *Hub {
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	h := &Hub{log: log}
	for _, c := range cfgs {
		t := &Target{cfg: c, events: map[Event]bool{}, http: hc}
		evs := c.Events
		if len(evs) == 0 {
			evs = []string{string(EvSecurity), string(EvApps), string(EvFailure)}
		}
		for _, e := range evs {
			t.events[Event(e)] = true
		}
		h.targets = append(h.targets, t)
	}
	return h
}

// Enabled indique si au moins une cible est configurée.
func (h *Hub) Enabled() bool { return h != nil && len(h.targets) > 0 }

// Notify envoie le message aux cibles concernées, en arrière-plan.
func (h *Hub) Notify(m Message) {
	if !h.Enabled() {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		for _, err := range h.Send(ctx, m) {
			h.log.Warn("notification non envoyée", "erreur", err)
		}
	}()
}

// Send envoie le message de façon synchrone et renvoie une erreur par cible en échec.
func (h *Hub) Send(ctx context.Context, m Message) []error {
	var errs []error
	for _, t := range h.targets {
		if m.Event != EvTest && !m.Always && !t.events[m.Event] {
			continue
		}
		if err := t.send(ctx, m); err != nil {
			errs = append(errs, fmt.Errorf("%s : %w", t.Name(), err))
		}
	}
	return errs
}

// Targets renvoie les noms des cibles (pour notify-test).
func (h *Hub) Targets() []string {
	var out []string
	for _, t := range h.targets {
		out = append(out, t.Name())
	}
	return out
}

func clampPriority(p int) int {
	if p < 1 {
		return 3
	}
	if p > 5 {
		return 5
	}
	return p
}

func (t *Target) send(ctx context.Context, m Message) error {
	prio := clampPriority(m.Priority)
	body := m.Body
	if m.URL != "" {
		body += "\n" + m.URL
	}
	var (
		target  = t.cfg.URL
		payload any
		headers = map[string]string{}
	)
	switch t.cfg.Type {
	case "ntfy":
		// Publication JSON (UTF-8 sûr) : POST à la racine du serveur, sujet dans le corps.
		u, err := url.Parse(t.cfg.URL)
		if err != nil {
			return err
		}
		topic := strings.Trim(u.Path, "/")
		u.Path = "/"
		target = u.String()
		msg := map[string]any{"topic": topic, "title": m.Title, "message": body, "priority": prio, "tags": []string{tagFor(m.Event)}}
		if m.URL != "" {
			msg["click"] = m.URL
		}
		payload = msg
		if t.cfg.Token != "" {
			headers["Authorization"] = "Bearer " + t.cfg.Token
		}
	case "gotify":
		target = strings.TrimRight(t.cfg.URL, "/") + "/message"
		// Gotify : priorités 0 à 10.
		payload = map[string]any{"title": m.Title, "message": body, "priority": prio * 2}
		headers["X-Gotify-Key"] = t.cfg.Token
	default: // webhook
		payload = map[string]any{
			"event": m.Event, "title": m.Title, "message": m.Body, "priority": prio,
			"url": m.URL, "time": time.Now().UTC().Format(time.RFC3339), "source": "patchwarden",
		}
		if t.cfg.Token != "" {
			headers["Authorization"] = "Bearer " + t.cfg.Token
		}
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "PatchWarden")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := t.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		snip, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		return fmt.Errorf("HTTP %d : %s", resp.StatusCode, strings.TrimSpace(string(snip)))
	}
	return nil
}

func tagFor(e Event) string {
	switch e {
	case EvSecurity:
		return "shield"
	case EvApps:
		return "package"
	case EvFailure:
		return "x"
	case EvSuccess:
		return "white_check_mark"
	default:
		return "bell"
	}
}
