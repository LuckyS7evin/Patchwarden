package web

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/LuckyS7evin/patchwarden/internal/detect"
	"github.com/LuckyS7evin/patchwarden/internal/engine"
	"github.com/LuckyS7evin/patchwarden/internal/jobs"
)

type dockerData struct {
	base
	Plan    engine.DockerPlan
	Keys    []string // groupes demandés (vide : tous ceux à mettre à jour)
	Choices []dockerChoice
	Error   string
}

// dockerChoice : une stack ou un projet que la mise à jour peut traiter,
// coché s'il fait partie de la demande.
type dockerChoice struct {
	Group   detect.DockerGroup
	Checked bool
	Images  string // conteneurs qui ont une nouvelle image
}

func dockerChoices(p engine.DockerPlan) []dockerChoice {
	if p.Det == nil {
		return nil
	}
	sel := map[string]bool{}
	for _, k := range p.Keys() {
		sel[k] = true
	}
	var out []dockerChoice
	for _, g := range p.Det.DockerInfo.UpdatableGroups() {
		var imgs []string
		for _, n := range g.Containers {
			if c, ok := p.Det.DockerInfo.Container(n); ok && c.Running() && c.UpdateAvailable() {
				imgs = append(imgs, c.Name+" ("+c.Image+")")
			}
		}
		out = append(out, dockerChoice{Group: g, Checked: sel[g.Key], Images: strings.Join(imgs, ", ")})
	}
	return out
}

// dockerPage : confirmation de la mise à jour des conteneurs d'un invité.
func (s *Server) dockerPage(w http.ResponseWriter, r *http.Request, se *session) {
	g, ok := s.findGuest(r)
	if !ok {
		http.Error(w, "Invité inconnu (rafraîchissez l'inventaire)", http.StatusNotFound)
		return
	}
	keys := r.URL.Query()["groupe"]
	p := s.deps.Engine.PlanDocker(g, keys)
	s.render(w, "docker", http.StatusOK, dockerData{
		base: s.base("Conteneurs Docker · "+g.Name, "inventaire", se),
		Plan: p, Keys: keys, Choices: dockerChoices(p), Error: r.URL.Query().Get("erreur"),
	})
}

func (s *Server) dockerSubmit(w http.ResponseWriter, r *http.Request, se *session) {
	g, ok := s.findGuest(r)
	if !ok {
		http.Error(w, "Invité inconnu (rafraîchissez l'inventaire)", http.StatusNotFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Formulaire invalide", http.StatusBadRequest)
		return
	}
	keys := r.PostForm["groupe"]
	if r.PostFormValue("choix") == "1" && len(keys) == 0 {
		// Aucune case cochée ne veut pas dire « tout ».
		http.Redirect(w, r, guestURL(g)+"/docker?erreur="+url.QueryEscape("cochez au moins une stack ou un projet"), http.StatusSeeOther)
		return
	}
	dry := r.PostFormValue("simulation") == "1"
	snap := r.PostFormValue("snapshot") == "1"
	j, err := s.deps.Engine.ExecuteDocker(g, keys, dry, se.user, r.PostFormValue("confirme") == "1", r.PostFormValue("nom"), snap)
	if err != nil {
		if errors.Is(err, jobs.ErrBusy) {
			if act, ok := s.deps.Jobs.ActiveFor(jobs.Target{Node: g.Node, VMID: g.VMID}); ok {
				http.Redirect(w, r, "/taches/"+act.ID, http.StatusSeeOther)
				return
			}
		}
		v := url.Values{"groupe": keys, "erreur": {err.Error()}}
		http.Redirect(w, r, guestURL(g)+"/docker?"+v.Encode(), http.StatusSeeOther)
		return
	}
	s.log.Info("mise à jour Docker demandée", "invité", g.Key(), "groupes", keys, "simulation", dry, "snapshot", snap, "tâche", j.ID, "par", se.user)
	http.Redirect(w, r, "/taches/"+j.ID, http.StatusSeeOther)
}

// dockerRows : conteneurs d'un groupe, pour l'onglet Docker de la fiche.
type dockerGroupView struct {
	detect.DockerGroup
	Items []detect.Container
}

func dockerView(d detect.Docker) []dockerGroupView {
	out := make([]dockerGroupView, 0, len(d.Groups))
	for _, g := range d.Groups {
		v := dockerGroupView{DockerGroup: g}
		for _, n := range g.Containers {
			if c, ok := d.Container(n); ok {
				v.Items = append(v.Items, c)
			}
		}
		out = append(out, v)
	}
	return out
}
