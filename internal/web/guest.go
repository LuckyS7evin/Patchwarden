package web

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/LuckyS7evin/patchwarden/internal/detect"
	"github.com/LuckyS7evin/patchwarden/internal/engine"
	"github.com/LuckyS7evin/patchwarden/internal/inventory"
	"github.com/LuckyS7evin/patchwarden/internal/jobs"
)

type tabLink struct {
	Key, Label, URL, Badge, BadgeClass string
	Current                            bool
}

type guestData struct {
	base
	Row    row
	Error  string
	Notice string
	Tab    string
	Tabs   []tabLink
	Jobs   []jobs.Job
	// Plans : « sécurité uniquement » puis « tout mettre à jour ».
	Plans     []engine.Plan
	Sec, Full *engine.Plan
	Answers   []engine.PromptAnswer
	Missing   int // questions sans réponse enregistrée
	// Paquets séparés pour l'affichage.
	SecurityPkgs, OtherPkgs []detect.Package
	StrictMissing           int
	// Snapshots : réglage de l'invité, réglage global, actions possibles.
	SnapPref     string
	SnapDefaults engine.SnapConfig
	SnapWhy      string // retour arrière / suppression impossibles : pourquoi
	// Preview : rendu dans le tiroir de l'inventaire.
	TopSec []detect.Package
	// Restart : redémarrages utiles (services, CT).
	Restart *engine.RestartPlan
	// CheckURL : adresse vérifiée après chaque opération (vide : aucune).
	CheckURL string
	// Invité arrêté : démarrer, mettre à jour, arrêter.
	CanCycle      bool
	CycleNeedName bool
	// Docker : mise à jour des conteneurs (tous les groupes à jour possibles) et
	// conteneurs par groupe pour l'onglet Docker.
	Docker       *engine.DockerPlan
	DockerGroups []dockerGroupView
}

var guestTabs = []struct{ key, label string }{
	{"", "Aperçu"}, {"paquets", "Paquets"}, {"docker", "Docker"}, {"snapshots", "Snapshots"}, {"questions", "Questions du script"}, {"historique", "Historique"},
}

// guestInfo rassemble ce que la fiche et l'aperçu affichent.
func (s *Server) guestInfo(r *http.Request, se *session) (guestData, bool) {
	g, ok := s.findGuest(r)
	if !ok {
		return guestData{}, false
	}
	s.deps.Engine.SyncSnapshots([]inventory.Guest{g})
	d := guestData{
		base:   s.base(fmt.Sprintf("%s (%d)", g.Name, g.VMID), "inventaire", se),
		Row:    s.rowFor(g),
		Error:  r.URL.Query().Get("erreur"),
		Notice: r.URL.Query().Get("info"),
		Jobs:   s.deps.Jobs.List(g.Key(), 20),
		Tab:    r.URL.Query().Get("onglet"),
	}
	if s.deps.Engine.CanDetect(g) == nil {
		for _, a := range []engine.Action{engine.ActSecurity, engine.ActFull} {
			p := s.deps.Engine.PlanFor(g, a)
			d.Plans = append(d.Plans, p)
		}
		d.Sec, d.Full = &d.Plans[0], &d.Plans[1]
		d.Answers = d.Full.Answers
		for _, a := range d.Answers {
			if !a.Set {
				d.Missing++
			}
		}
	}
	if det := d.Row.Det; det != nil {
		for _, p := range det.Apt.Packages {
			if p.Security {
				d.SecurityPkgs = append(d.SecurityPkgs, p)
			} else {
				d.OtherPkgs = append(d.OtherPkgs, p)
			}
		}
		d.StrictMissing = det.Apt.SecurityNotStrict()
		d.TopSec = d.SecurityPkgs[:min(5, len(d.SecurityPkgs))]
	}
	rp := s.deps.Engine.PlanRestart(g)
	d.Restart = &rp
	if det := d.Row.Det; det != nil && det.Docker && len(det.DockerInfo.List) > 0 {
		dp := s.deps.Engine.PlanDocker(g, nil)
		d.Docker = &dp
		d.DockerGroups = dockerView(det.DockerInfo)
	}
	d.SnapPref = s.deps.Engine.SnapPref(g.Key())
	d.CheckURL = s.deps.Engine.CheckURL(g.Key())
	if s.deps.Engine.CanCycle(g) == nil {
		d.CanCycle, d.CycleNeedName = true, s.deps.Engine.CycleNeedName(g)
	}
	d.SnapDefaults = s.deps.Engine.SnapDefaults()
	if err := s.deps.Engine.CanSnapAction(g); err != nil {
		d.SnapWhy = err.Error()
	}
	known := false
	for _, t := range guestTabs {
		if t.key == d.Tab {
			known = true
		}
	}
	if !known || (d.Tab == "docker" && d.DockerGroups == nil) || (d.Tab == "snapshots" && g.IsHost()) {
		d.Tab = ""
	}
	for _, t := range guestTabs {
		tl := tabLink{Key: t.key, Label: t.label, URL: guestLink(g, t.key), Current: t.key == d.Tab}
		switch t.key {
		case "paquets":
			if d.Row.Det != nil && d.Row.Det.Apt.Total > 0 {
				tl.Badge = fmt.Sprint(d.Row.Det.Apt.Total)
				if d.Row.Det.Apt.Security > 0 {
					tl.BadgeClass = "c"
				}
			}
		case "docker":
			if d.DockerGroups == nil {
				continue
			}
			if n := d.Row.Det.DockerInfo.Updates(); n > 0 {
				tl.Badge, tl.BadgeClass = fmt.Sprint(n), "w"
			}
		case "snapshots":
			if g.IsHost() {
				continue
			}
			if d.Row.Det != nil && len(d.Row.Det.Snap.PW) > 0 {
				tl.Badge, tl.BadgeClass = fmt.Sprint(len(d.Row.Det.Snap.PW)), "v"
			}
		case "questions":
			if len(d.Answers) == 0 {
				continue
			}
			if d.Missing > 0 {
				tl.Badge, tl.BadgeClass = "à renseigner", "w"
			}
		case "historique":
			if len(d.Jobs) > 0 {
				tl.Badge = fmt.Sprint(len(d.Jobs))
			}
		}
		d.Tabs = append(d.Tabs, tl)
	}
	return d, true
}

func (s *Server) guestPage(w http.ResponseWriter, r *http.Request, se *session) {
	d, ok := s.guestInfo(r, se)
	if !ok {
		http.Error(w, "Invité inconnu (rafraîchissez l'inventaire)", http.StatusNotFound)
		return
	}
	s.render(w, "invite", http.StatusOK, d)
}

// previewFragment renvoie l'aperçu d'un invité (tiroir de l'inventaire), sans le cadre.
func (s *Server) previewFragment(w http.ResponseWriter, r *http.Request, se *session) {
	g, ok := s.findGuest(r)
	if !ok {
		http.Error(w, "Invité inconnu", http.StatusNotFound)
		return
	}
	d := guestData{
		base: base{User: se.user, CSRF: se.csrf, Version: s.version},
		Row:  s.rowFor(g),
	}
	if s.deps.Engine.CanDetect(g) == nil {
		for _, a := range []engine.Action{engine.ActSecurity, engine.ActFull} {
			d.Plans = append(d.Plans, s.deps.Engine.PlanFor(g, a))
		}
		d.Sec, d.Full = &d.Plans[0], &d.Plans[1]
	}
	if det := d.Row.Det; det != nil {
		for _, p := range det.Apt.Packages {
			if p.Security {
				d.SecurityPkgs = append(d.SecurityPkgs, p)
			}
		}
		d.TopSec = d.SecurityPkgs[:min(5, len(d.SecurityPkgs))]
	}
	var buf []byte
	out := &byteWriter{b: buf}
	if err := s.pages["apercu"].ExecuteTemplate(out, "apercu", d); err != nil {
		s.log.Error("rendu de l'aperçu", "erreur", err)
		http.Error(w, "Erreur interne", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(out.b)
}

type byteWriter struct{ b []byte }

func (w *byteWriter) Write(p []byte) (int, error) { w.b = append(w.b, p...); return len(p), nil }

// saveCheckURL enregistre l'adresse vérifiée après chaque opération sur l'invité.
func (s *Server) saveCheckURL(w http.ResponseWriter, r *http.Request, se *session) {
	g, ok := s.findGuest(r)
	if !ok {
		http.Error(w, "Invité inconnu (rafraîchissez l'inventaire)", http.StatusNotFound)
		return
	}
	if err := s.deps.Engine.SetCheckURL(g.Key(), r.PostFormValue("url")); err != nil {
		http.Redirect(w, r, guestURL(g)+"?erreur="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	s.log.Info("adresse de vérification enregistrée", "invité", g.Key(), "par", se.user)
	http.Redirect(w, r, guestURL(g)+"?info="+url.QueryEscape("Vérification enregistrée."), http.StatusSeeOther)
}

// cycleSubmit : démarrer un invité arrêté, le mettre à jour (ou simuler), l'arrêter.
func (s *Server) cycleSubmit(w http.ResponseWriter, r *http.Request, se *session) {
	g, ok := s.findGuest(r)
	if !ok {
		http.Error(w, "Invité inconnu (rafraîchissez l'inventaire)", http.StatusNotFound)
		return
	}
	a, err := engine.ParseAction(r.PostFormValue("action"))
	if err == nil {
		var j jobs.Job
		j, err = s.deps.Engine.Cycle(g, a, r.PostFormValue("simulation") == "1", se.user, r.PostFormValue("confirme") == "1", r.PostFormValue("nom"), r.PostFormValue("snapshot") == "1")
		if err == nil {
			s.log.Info("démarrer, mettre à jour, arrêter", "invité", g.Key(), "action", a, "tâche", j.ID, "par", se.user)
			http.Redirect(w, r, "/taches/"+j.ID, http.StatusSeeOther)
			return
		}
	}
	http.Redirect(w, r, guestURL(g)+"?erreur="+url.QueryEscape(err.Error()), http.StatusSeeOther)
}

// pruneSubmit : supprimer (ou lister) les images Docker sans nom de l'invité.
func (s *Server) pruneSubmit(w http.ResponseWriter, r *http.Request, se *session) {
	g, ok := s.findGuest(r)
	if !ok {
		http.Error(w, "Invité inconnu (rafraîchissez l'inventaire)", http.StatusNotFound)
		return
	}
	j, err := s.deps.Engine.DockerPrune(g, r.PostFormValue("simulation") == "1", se.user, r.PostFormValue("confirme") == "1")
	if err != nil {
		http.Redirect(w, r, guestURL(g)+"?onglet=docker&erreur="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	s.log.Info("nettoyage Docker demandé", "invité", g.Key(), "tâche", j.ID, "par", se.user)
	http.Redirect(w, r, "/taches/"+j.ID, http.StatusSeeOther)
}
