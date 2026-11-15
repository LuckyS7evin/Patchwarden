package web

import (
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
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
	keep, maxPct := c.Snapshots.Keep, c.Snapshots.MaxStoragePct
	add("Snapshots",
		setting{"snapshots.default", yes(c.Snapshots.Default), "case cochée d'office pour tous les invités"},
		setting{"snapshots.keep", itoa(keep), "snapshots PatchWarden gardés par invité"},
		setting{"snapshots.max_storage_pct", itoa(maxPct) + " %", "snapshot refusé au-delà"},
	)
	dock := []setting{{"docker.registry_check", yes(c.Docker.RegistryCheck == nil || *c.Docker.RegistryCheck), "comparaison des images aux registres (empreinte du tag, versions plus récentes)"}}
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
