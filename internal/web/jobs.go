package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/LuckyS7evin/patchwarden/internal/engine"
	"github.com/LuckyS7evin/patchwarden/internal/inventory"
	"github.com/LuckyS7evin/patchwarden/internal/jobs"
)

// findGuest retrouve un invité de l'inventaire courant à partir de l'URL.
func (s *Server) findGuest(r *http.Request) (inventory.Guest, bool) {
	vmid, err := strconv.Atoi(r.PathValue("vmid"))
	if err != nil {
		return inventory.Guest{}, false
	}
	node := r.PathValue("node")
	snap, _ := s.inv.Current()
	for _, g := range snap.Guests {
		if g.Node == node && g.VMID == vmid {
			return g, true
		}
	}
	return inventory.Guest{}, false
}

func (s *Server) detectOne(w http.ResponseWriter, r *http.Request, se *session) {
	g, ok := s.findGuest(r)
	if !ok {
		http.Error(w, "Invité inconnu (rafraîchissez l'inventaire)", http.StatusNotFound)
		return
	}
	j, err := s.deps.Engine.Detect(g, se.user)
	if err != nil {
		if errors.Is(err, jobs.ErrBusy) {
			if a, ok := s.deps.Jobs.ActiveFor(jobs.Target{Node: g.Node, VMID: g.VMID}); ok {
				http.Redirect(w, r, "/taches/"+a.ID, http.StatusSeeOther)
				return
			}
		}
		http.Redirect(w, r, fmt.Sprintf("/invites/%s/%d?erreur=%s", g.Node, g.VMID, url.QueryEscape(err.Error())), http.StatusSeeOther)
		return
	}
	s.log.Info("détection demandée", "invité", g.Key(), "tâche", j.ID, "par", se.user)
	http.Redirect(w, r, "/taches/"+j.ID, http.StatusSeeOther)
}

func (s *Server) detectAll(w http.ResponseWriter, r *http.Request, se *session) {
	snap, _ := s.inv.Current()
	started, skipped := s.deps.Engine.DetectAll(snap.Guests, se.user)
	s.log.Info("détection de tous les invités demandée", "lancées", started, "ignorés", skipped, "par", se.user)
	http.Redirect(w, r, fmt.Sprintf("/taches?lancees=%d&ignores=%d", started, skipped), http.StatusSeeOther)
}

type jobsData struct {
	base
	Batches                       []engine.Batch
	Jobs                          []jobs.Job
	Started, Skipped, Simulations string
	RunningOrQueued               int
}

func (s *Server) jobsPage(w http.ResponseWriter, r *http.Request, se *session) {
	d := jobsData{base: s.base("Tâches", "taches", se), Jobs: s.deps.Jobs.List("", 200)}
	if s.deps.Batches != nil {
		d.Batches = s.deps.Batches.List(5)
	}
	q := r.URL.Query()
	d.Started, d.Skipped, d.Simulations = q.Get("lancees"), q.Get("ignores"), q.Get("simulations")
	for _, j := range d.Jobs {
		if !j.Status.Finished() {
			d.RunningOrQueued++
		}
	}
	s.render(w, "taches", http.StatusOK, d)
}

type jobData struct {
	base
	Job      jobs.Job
	Lines    []jobs.Line
	Live     bool
	Steps    []stepView
	NodeLog  string
	SnapName string
	// Apply : simulation réussie d'une mise à jour apt, à appliquer depuis
	// la même page ; DockerNext : simulation Docker réussie.
	Apply      *engine.Plan
	DockerNext bool
	Back       string // page de l'invité
}

func (s *Server) jobPage(w http.ResponseWriter, r *http.Request, se *session) {
	j, ok := s.deps.Jobs.Get(r.PathValue("id"))
	if !ok {
		http.Error(w, "Tâche inconnue", http.StatusNotFound)
		return
	}
	lines, err := s.deps.Jobs.Log(j.ID)
	if err != nil {
		s.log.Error("lecture du journal", "tâche", j.ID, "erreur", err)
	}
	d := jobData{
		base: s.base(string(j.Kind)+" · "+j.Target.Name, "taches", se), Job: j, Lines: lines, Live: !j.Status.Finished(),
		Steps: stepsFor(j, lines), NodeLog: nodeLog(j, lines), SnapName: takenSnapshot(j, lines),
		Back: fmt.Sprintf("/invites/%s/%d", url.PathEscape(j.Target.Node), j.Target.VMID),
	}
	if j.DryRun && j.Status == jobs.Success {
		switch j.Kind {
		case jobs.KindSecurity, jobs.KindFull:
			if g, ok := s.guestByKey(j.Target.Key()); ok {
				a := engine.ActFull
				if j.Kind == jobs.KindSecurity {
					a = engine.ActSecurity
				}
				p := s.deps.Engine.PlanFor(g, a)
				d.Apply = &p
			}
		case jobs.KindDocker:
			d.DockerNext = true
		}
	}
	s.render(w, "tache", http.StatusOK, d)
}

type sseLine struct {
	H string `json:"h"`
	E bool   `json:"e,omitempty"`
	X string `json:"x"`
}

// jobStream diffuse le journal d'une tâche en Server-Sent Events : tout le
// passé (précédé de « debut », pour qu'une reconnexion reparte de zéro), puis
// la suite en direct, puis « fin ».
func (s *Server) jobStream(w http.ResponseWriter, r *http.Request, _ *session) {
	id := r.PathValue("id")
	past, ch, cancel, err := s.deps.Jobs.Subscribe(id)
	if err != nil {
		http.Error(w, "Tâche inconnue", http.StatusNotFound)
		return
	}
	defer cancel()
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Flux non pris en charge", http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no") // pas de mise en tampon par un reverse proxy nginx
	fmt.Fprint(w, "retry: 2000\nevent: debut\ndata: {}\n\n")
	send := func(l jobs.Line) {
		b, _ := json.Marshal(sseLine{H: l.T.Local().Format("15:04:05"), E: l.Stderr, X: l.Text})
		fmt.Fprintf(w, "event: ligne\ndata: %s\n\n", b)
	}
	end := func() {
		j, _ := s.deps.Jobs.Get(id)
		b, _ := json.Marshal(map[string]string{"statut": string(j.Status)})
		fmt.Fprintf(w, "event: fin\ndata: %s\n\n", b)
		fl.Flush()
	}
	for _, l := range past {
		send(l)
	}
	fl.Flush()
	if ch == nil {
		end()
		return
	}
	tick := time.NewTicker(20 * time.Second)
	defer tick.Stop()
	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				if j, _ := s.deps.Jobs.Get(id); j.Status.Finished() {
					end()
				}
				return // sinon : déconnecté car trop lent, le navigateur se reconnecte
			}
			if ev.Line != nil {
				send(*ev.Line)
				fl.Flush()
			}
			if ev.Done != nil {
				end()
				return
			}
		case <-tick.C:
			fmt.Fprint(w, ": maintien\n\n")
			fl.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

// guestByKey retrouve un invité de l'inventaire courant (« nœud/vmid »).
func (s *Server) guestByKey(key string) (inventory.Guest, bool) {
	snap, _ := s.inv.Current()
	for _, g := range snap.Guests {
		if g.Key() == key {
			return g, true
		}
	}
	return inventory.Guest{}, false
}

func guestURL(g inventory.Guest) string { return fmt.Sprintf("/invites/%s/%d", g.Node, g.VMID) }

type actionData struct {
	base
	Plan  engine.Plan
	Error string
}

func (s *Server) actionPage(w http.ResponseWriter, r *http.Request, se *session) {
	g, ok := s.findGuest(r)
	if !ok {
		http.Error(w, "Invité inconnu (rafraîchissez l'inventaire)", http.StatusNotFound)
		return
	}
	a, err := engine.ParseAction(r.PathValue("action"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	p := s.deps.Engine.PlanFor(g, a)
	s.render(w, "action", http.StatusOK, actionData{
		base: s.base(a.Label()+" · "+g.Name, "inventaire", se), Plan: p, Error: r.URL.Query().Get("erreur"),
	})
}

func (s *Server) actionSubmit(w http.ResponseWriter, r *http.Request, se *session) {
	g, ok := s.findGuest(r)
	if !ok {
		http.Error(w, "Invité inconnu (rafraîchissez l'inventaire)", http.StatusNotFound)
		return
	}
	a, err := engine.ParseAction(r.PathValue("action"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	dry := r.PostFormValue("simulation") == "1"
	snap := r.PostFormValue("snapshot") == "1"
	j, err := s.deps.Engine.Execute(g, a, dry, se.user, r.PostFormValue("confirme") == "1", r.PostFormValue("nom"), snap)
	if err != nil {
		if errors.Is(err, jobs.ErrBusy) {
			if act, ok := s.deps.Jobs.ActiveFor(jobs.Target{Node: g.Node, VMID: g.VMID}); ok {
				http.Redirect(w, r, "/taches/"+act.ID, http.StatusSeeOther)
				return
			}
		}
		http.Redirect(w, r, guestURL(g)+"/action/"+string(a)+"?erreur="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	s.log.Info("mise à jour demandée", "invité", g.Key(), "action", a, "simulation", dry, "snapshot", snap, "tâche", j.ID, "par", se.user)
	http.Redirect(w, r, "/taches/"+j.ID, http.StatusSeeOther)
}

// saveAnswers enregistre les réponses aux questions du script de l'invité,
// dans l'ordre des questions de la dernière détection.
func (s *Server) saveAnswers(w http.ResponseWriter, r *http.Request, se *session) {
	g, ok := s.findGuest(r)
	if !ok {
		http.Error(w, "Invité inconnu (rafraîchissez l'inventaire)", http.StatusNotFound)
		return
	}
	det, ok := s.deps.Detections.Get(g.Key())
	if !ok || len(det.CS.Prompts) == 0 {
		http.Redirect(w, r, guestURL(g)+"?erreur="+url.QueryEscape("aucune question à laquelle répondre"), http.StatusSeeOther)
		return
	}
	ans := map[string]string{}
	for i, q := range det.CS.Prompts {
		switch v := r.PostFormValue(fmt.Sprintf("r%d", i)); v {
		case "y", "n":
			ans[q] = v
		case "defaut":
			ans[q] = ""
		default:
			http.Redirect(w, r, guestURL(g)+"?erreur="+url.QueryEscape("répondez à chaque question"), http.StatusSeeOther)
			return
		}
	}
	if err := s.deps.Engine.SetAnswers(g.Key(), ans); err != nil {
		http.Redirect(w, r, guestURL(g)+"?erreur="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	s.log.Info("réponses enregistrées", "invité", g.Key(), "par", se.user)
	http.Redirect(w, r, guestURL(g)+"?info="+url.QueryEscape("Réponses enregistrées."), http.StatusSeeOther)
}
