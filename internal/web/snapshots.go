package web

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/LuckyS7evin/patchwarden/internal/detect"
	"github.com/LuckyS7evin/patchwarden/internal/engine"
	"github.com/LuckyS7evin/patchwarden/internal/jobs"
)

func (s *Server) saveSnapPref(w http.ResponseWriter, r *http.Request, se *session) {
	g, ok := s.findGuest(r)
	if !ok {
		http.Error(w, "Invité inconnu (rafraîchissez l'inventaire)", http.StatusNotFound)
		return
	}
	v := r.PostFormValue("reglage")
	if err := s.deps.Engine.SetSnapPref(g.Key(), v); err != nil {
		http.Redirect(w, r, guestURL(g)+"?erreur="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	s.log.Info("réglage de snapshot enregistré", "invité", g.Key(), "réglage", v, "par", se.user)
	http.Redirect(w, r, guestURL(g)+"?info="+url.QueryEscape("Réglage de snapshot enregistré."), http.StatusSeeOther)
}

type rollbackData struct {
	base
	Row   row
	Snap  detect.Snapshot
	Binds int
	Why   string
	Error string
}

// snapshotFor retrouve l'invité et le snapshot PatchWarden désignés par l'URL.
func (s *Server) snapshotFor(r *http.Request) (row, detect.Snapshot, int, string, bool) {
	g, ok := s.findGuest(r)
	if !ok {
		return row{}, detect.Snapshot{}, 0, "", false
	}
	rw := s.rowFor(g)
	name := r.PathValue("name")
	if !engine.ValidSnapName(name) || rw.Det == nil {
		return rw, detect.Snapshot{}, 0, "", false
	}
	sn, ok := rw.Det.Snap.Has(name)
	return rw, sn, rw.Det.Snap.Binds, name, ok
}

func (s *Server) rollbackPage(w http.ResponseWriter, r *http.Request, se *session) {
	rw, sn, binds, _, ok := s.snapshotFor(r)
	if !ok {
		http.Error(w, "Snapshot PatchWarden inconnu (relancez une détection)", http.StatusNotFound)
		return
	}
	d := rollbackData{
		base: s.base("Retour arrière · "+rw.Name, "inventaire", se),
		Row:  rw, Snap: sn, Binds: binds, Error: r.URL.Query().Get("erreur"),
	}
	if err := s.deps.Engine.CanSnapAction(rw.Guest); err != nil {
		d.Why = err.Error()
	}
	s.render(w, "restaurer", http.StatusOK, d)
}

func (s *Server) rollbackSubmit(w http.ResponseWriter, r *http.Request, se *session) {
	rw, _, _, name, ok := s.snapshotFor(r)
	if !ok {
		http.Error(w, "Snapshot PatchWarden inconnu (relancez une détection)", http.StatusNotFound)
		return
	}
	g := rw.Guest
	j, err := s.deps.Engine.Rollback(g, name, se.user, r.PostFormValue("nom"))
	if err != nil {
		if errors.Is(err, jobs.ErrBusy) {
			if act, ok := s.deps.Jobs.ActiveFor(jobs.Target{Node: g.Node, VMID: g.VMID}); ok {
				http.Redirect(w, r, "/taches/"+act.ID, http.StatusSeeOther)
				return
			}
		}
		http.Redirect(w, r, guestURL(g)+"/snapshots/"+name+"/restaurer?erreur="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	s.log.Info("retour arrière demandé", "invité", g.Key(), "snapshot", name, "tâche", j.ID, "par", se.user)
	http.Redirect(w, r, "/taches/"+j.ID, http.StatusSeeOther)
}

func (s *Server) deleteSnapshot(w http.ResponseWriter, r *http.Request, se *session) {
	rw, _, _, name, ok := s.snapshotFor(r)
	if !ok {
		http.Error(w, "Snapshot PatchWarden inconnu (relancez une détection)", http.StatusNotFound)
		return
	}
	g := rw.Guest
	j, err := s.deps.Engine.DeleteSnapshot(g, name, se.user, r.PostFormValue("confirme") == "1")
	if err != nil {
		http.Redirect(w, r, guestURL(g)+"?erreur="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	s.log.Info("suppression de snapshot demandée", "invité", g.Key(), "snapshot", name, "tâche", j.ID, "par", se.user)
	http.Redirect(w, r, "/taches/"+j.ID, http.StatusSeeOther)
}

type snapRow struct {
	Row  row
	Snap detect.Snapshot
}

type snapshotsData struct {
	base
	Rows     []snapRow
	Manual   int // snapshots manuels (jamais touchés)
	Defaults engine.SnapConfig
	Storages []string
}

// snapshotsPage liste tous les snapshots PatchWarden, du plus ancien au plus récent.
func (s *Server) snapshotsPage(w http.ResponseWriter, r *http.Request, se *session) {
	snap, _ := s.inv.Current()
	d := snapshotsData{base: s.base("Snapshots", "snapshots", se), Defaults: s.deps.Engine.SnapDefaults()}
	for _, g := range snap.Guests {
		rw := s.rowFor(g)
		if rw.Det == nil {
			continue
		}
		d.Manual += rw.Det.Snap.Other
		for _, sn := range rw.Det.Snap.PW {
			d.Rows = append(d.Rows, snapRow{Row: rw, Snap: sn})
		}
	}
	sort.SliceStable(d.Rows, func(i, j int) bool { return d.Rows[i].Snap.Time.Before(d.Rows[j].Snap.Time) })
	for _, n := range snap.Nodes() {
		if st, ok := snap.NodeStats[n]; ok && st.Storage != "" {
			d.Storages = append(d.Storages, fmt.Sprintf("%s : %s (%s) %d %%", strings.ToUpper(n), st.Storage, st.StorageType, st.StoragePct()))
		}
	}
	s.render(w, "snapshots", http.StatusOK, d)
}
