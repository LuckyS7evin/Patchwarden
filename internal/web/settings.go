package web

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/LuckyS7evin/patchwarden/internal/window"
)

type setting struct{ Key, Value, Note string }

type settingsSection struct {
	Title string
	Items []setting
}

type settingsData struct {
	base
	Sections []settingsSection
}

func yes(b bool) string {
	if b {
		return "oui"
	}
	return "non"
}

func secret(name, env string) string {
	switch {
	case env != "":
		return "variable d'environnement " + env
	case name != "":
		return "défini (masqué)"
	}
	return "—"
}

// settingsPage affiche la configuration en vigueur, en lecture seule et sans
// aucun secret. Elle se modifie dans le fichier de configuration.
func (s *Server) settingsPage(w http.ResponseWriter, r *http.Request, se *session) {
	c := s.cfg
	d := settingsData{base: s.base("Réglages", "reglages", se)}
	add := func(title string, items ...setting) {
		d.Sections = append(d.Sections, settingsSection{Title: title, Items: items})
	}
	add("Interface",
		setting{"server.listen", c.Server.Listen, ""},
		setting{"server.public_url", c.Server.PublicURL, "liens dans les notifications"},
		setting{"auth.username", c.Auth.Username, "mot de passe haché, jamais affiché"},
		setting{"ui.icons", yes(c.UI.Icons == nil || *c.UI.Icons), "selfh.st/icons, mises en cache"},
	)
	var eps []setting
	for _, e := range c.Proxmox {
		v := e.URL + " · jeton " + e.TokenID + " · secret " + secret(e.TokenSecret, e.TokenSecretEnv)
		eps = append(eps, setting{"[[proxmox]] " + e.Name, v, "lecture seule (PVEAuditor)"})
	}
	add("Points d'accès Proxmox", eps...)
	var nodes []setting
	names := make([]string, 0, len(c.SSH.Nodes))
	for n := range c.SSH.Nodes {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		nodes = append(nodes, setting{"ssh.nodes." + n, c.SSH.Nodes[n], ""})
	}
	if len(nodes) == 0 {
		nodes = append(nodes, setting{"ssh", "non configuré", "PatchWarden est en lecture seule"})
	} else {
		nodes = append([]setting{{"ssh.user", c.SSH.User, "clé dédiée, commande forcée (wrapper)"}}, nodes...)
	}
	add("Accès aux nœuds", nodes...)
	if len(c.Hosts) > 0 {
		var hosts []setting
		for _, h := range c.Hosts {
			note := "compte dédié, sudo limité au wrapper ; pas de snapshot, confirmation renforcée"
			if len(h.Tags) > 0 {
				note += " · tags : " + strings.Join(h.Tags, ", ")
			}
			hosts = append(hosts, setting{"[[host]] " + h.Name, h.User + "@" + h.Address, note})
		}
		add("Hôtes autonomes", hosts...)
	}
	keep, maxPct := c.Snapshots.Keep, c.Snapshots.MaxStoragePct
	add("Snapshots",
		setting{"snapshots.default", yes(c.Snapshots.Default), "case cochée d'office pour tous les invités"},
		setting{"snapshots.keep", itoa(keep), "snapshots PatchWarden gardés par invité"},
		setting{"snapshots.max_storage_pct", itoa(maxPct) + " %", "snapshot refusé au-delà"},
	)
	dock := []setting{
		{"docker.registry_check", yes(c.Docker.RegistryCheck == nil || *c.Docker.RegistryCheck), "comparaison des images aux registres (empreinte du tag, versions plus récentes)"},
		{"docker.registries", strings.Join(c.Docker.Registries, ", "), "seuls registres interrogés ; une image d'un autre registre reste « inconnu »"},
	}
	for _, p := range c.Portainer {
		tok := "absent"
		if p.Token != "" {
			tok = "défini"
			if p.TokenEnv != "" {
				tok = "lu dans " + p.TokenEnv
			}
		}
		dock = append(dock, setting{"portainer." + p.Name, redactURL(p.URL), "jeton : " + tok})
	}
	if len(c.Portainer) == 0 {
		dock = append(dock, setting{"portainer", "aucune instance", "stacks Portainer : détection seulement"})
	}
	add("Docker", dock...)
	var maint []setting
	for _, w := range s.deps.Engine.MaintenanceWindows() {
		start, _ := w.Next(s.now())
		note := "prochaine ouverture : " + window.FormatTime(start)
		if w.Open(s.now()) {
			note = "ouverte maintenant"
		}
		if len(w.Tags) > 0 {
			note += " · invités des tags " + strings.Join(w.Tags, ", ")
		} else {
			note += " · tous les invités"
		}
		maint = append(maint, setting{"[[maintenance]] " + w.Name, w.Label(), note})
	}
	if len(maint) == 0 {
		maint = append(maint, setting{"maintenance", "aucune fenêtre", "pas de lot programmé ni de sécurité automatique possible"})
	}
	a := c.AutoSecurity
	if a.Enabled {
		n := len(s.deps.Engine.AutoCandidates())
		maint = append(maint, setting{"auto_security", "activée : fenêtre « " + a.Window + " », tag « " + a.Tag + " », snapshot " + yes(a.Snapshot == nil || *a.Snapshot),
			fmt.Sprintf("%d invité(s) portent le tag · prochaine exécution : %s · « Sécurité uniquement » seulement, jamais les invités critiques, OMV, PBS ni celui de PatchWarden", n, window.FormatTime(s.deps.Engine.NextAuto(s.now())))})
	} else {
		maint = append(maint, setting{"auto_security", "désactivée", "rien n'est jamais appliqué sans confirmation"})
	}
	add("Maintenance", maint...)
	met := setting{"metrics", "désactivée", "aucun jeton : /metrics répond 404"}
	if c.Metrics.Token != "" {
		met = setting{"metrics", "/metrics", "Prometheus ; jeton " + secret(c.Metrics.Token, c.Metrics.TokenEnv) + ", en-tête Authorization: Bearer"}
	}
	add("Métriques", met)
	sched := strings.Join(c.Schedule.DetectAt, ", ")
	if sched == "" {
		sched = "aucune"
	}
	add("Détection",
		setting{"schedule.detect_at", sched, "détection seule, jamais de mise à jour automatique"},
		setting{"detection.apt_refresh", yes(c.Detection.AptRefresh == nil || *c.Detection.AptRefresh), "apt-get update avant la simulation"},
		setting{"detection.timeout", c.Detection.Timeout.Duration.String(), ""},
	)
	var notif []setting
	for _, n := range c.Notify {
		notif = append(notif, setting{n.Type, redactURL(n.URL), "événements : " + strings.Join(n.Events, ", ")})
	}
	if len(notif) == 0 {
		notif = append(notif, setting{"notify", "aucune", ""})
	}
	add("Notifications", notif...)
	add("Tâches",
		setting{"jobs.data_dir", c.Jobs.DataDir, ""},
		setting{"jobs.max_parallel", itoa(c.Jobs.MaxParallel), "une seule tâche à la fois par invité"},
	)
	s.render(w, "reglages", http.StatusOK, d)
}

func itoa(n int) string { return strconv.Itoa(n) }

// redactURL ne garde que le schéma et l'hôte : le chemin (sujet ntfy) ou la
// requête peuvent valoir un secret.
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "(masquée)"
	}
	out := u.Scheme + "://" + u.Host
	if u.Path != "" && u.Path != "/" {
		out += "/…"
	}
	return out
}
