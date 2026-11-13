package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/LuckyS7evin/patchwarden/internal/detect"
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

type guestData struct {
	base
	Row   row
	Error string
	Jobs  []jobs.Job
	// Paquets séparés pour l'affichage.
	SecurityPkgs, OtherPkgs []detect.Package
	StrictMissing           int
}

func (s *Server) guestPage(w http.ResponseWriter, r *http.Request, se *session) {
	g, ok := s.findGuest(r)
	if !ok {
		http.Error(w, "Invité inconnu (rafraîchissez l'inventaire)", http.StatusNotFound)
		return
	}
	d := guestData{
		base:  s.base(fmt.Sprintf("%s (%d)", g.Name, g.VMID), "inventaire", se),
		Row:   s.rowFor(g),
		Error: r.URL.Query().Get("erreur"),
		Jobs:  s.deps.Jobs.List(g.Key(), 20),
	}
	if det := d.Row.Det; det != nil {
		for _, p := range det.Apt.Packages {
			if p.Security {
				d.SecurityPkgs = append(d.SecurityPkgs, p)
			} else {
				d.OtherPkgs = append(d.OtherPkgs, p)
			}
		}
		d.StrictMissing = det.Apt.Security - det.Apt.SecurityStrict
	}
	s.render(w, "invite", http.StatusOK, d)
}

type jobsData struct {
	base
	Jobs             []jobs.Job
	Started, Skipped string
	RunningOrQueued  int
}

func (s *Server) jobsPage(w http.ResponseWriter, r *http.Request, se *session) {
	d := jobsData{base: s.base("Tâches", "taches", se), Jobs: s.deps.Jobs.List("", 200)}
	q := r.URL.Query()
	d.Started, d.Skipped = q.Get("lancees"), q.Get("ignores")
	for _, j := range d.Jobs {
		if !j.Status.Finished() {
			d.RunningOrQueued++
		}
	}
	s.render(w, "taches", http.StatusOK, d)
}

type jobData struct {
	base
	Job   jobs.Job
	Lines []jobs.Line
	Live  bool
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
	s.render(w, "tache", http.StatusOK, jobData{
		base: s.base("Tâche "+j.ID, "taches", se), Job: j, Lines: lines, Live: !j.Status.Finished(),
	})
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
