package web

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/LuckyS7evin/patchwarden/internal/detect"
	"github.com/LuckyS7evin/patchwarden/internal/engine"
	"github.com/LuckyS7evin/patchwarden/internal/jobs"
)

type dockerData struct {
	base
	Plan  engine.DockerPlan
	Keys  []string // groupes demandés (vide : tous ceux à mettre à jour)
	Error string
}

// dockerPage : confirmation de la mise à jour des conteneurs d'un invité.
func (s *Server) dockerPage(w http.ResponseWriter, r *http.Request, se *session) {
	g, ok := s.findGuest(r)
	if !ok {
		http.Error(w, "Invité inconnu (rafraîchissez l'inventaire)", http.StatusNotFound)
		return
	}
	keys := r.URL.Query()["groupe"]
	s.render(w, "docker", http.StatusOK, dockerData{
		base: s.base("Conteneurs Docker · "+g.Name, "inventaire", se),
		Plan: s.deps.Engine.PlanDocker(g, keys), Keys: keys, Error: r.URL.Query().Get("erreur"),
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
