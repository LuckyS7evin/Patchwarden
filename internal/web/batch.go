package web

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/LuckyS7evin/patchwarden/internal/engine"
	"github.com/LuckyS7evin/patchwarden/internal/inventory"
	"github.com/LuckyS7evin/patchwarden/internal/jobs"
	"github.com/LuckyS7evin/patchwarden/internal/window"
)

// maxBatch : nombre maximal d'opérations dans un lot.
const maxBatch = 100

// lotRow est une ligne de la page de préparation d'un lot.
type lotRow struct {
	Index        int
	Row          row
	Op           engine.Op
	Ops          []engine.Op // opérations proposées pour cet invité
	Snapshot     bool
	SnapPossible bool
	SnapWhy      string
	Why          string // raison pour laquelle l'opération sera ignorée
	Detail       string
	Removed      bool   // décochée par l'utilisateur (retour après une erreur)
	OutWindow    string // hors de sa fenêtre de maintenance : prochaine ouverture
}

// windowChoice : fenêtre proposée pour programmer un lot.
type windowChoice struct {
	Name, Label, Next string
	Open              bool
}

type lotData struct {
	base
	Rows     []lotRow
	Runnable int
	Source   string
	Error    string
	Back     string // page d'où vient le lot (bouton « Annuler »)
	Stop     bool   // « arrêter au premier échec »
	Windows  []windowChoice
}

func opChoices(op engine.Op) []engine.Op {
	if op.Update() {
		return []engine.Op{engine.OpSecurity, engine.OpFull}
	}
	if op == engine.OpDocker {
		return []engine.Op{engine.OpDocker}
	}
	return []engine.Op{engine.OpServices, engine.OpReboot}
}

func (s *Server) guestsByKey() map[string]inventory.Guest {
	snap, _ := s.inv.Current()
	out := make(map[string]inventory.Guest, len(snap.Guests))
	for _, g := range snap.Guests {
		out[g.Key()] = g
	}
	return out
}

// opDetail résume ce qu'une opération ferait sur un invité.
func (s *Server) opDetail(rw row, op engine.Op) string {
	d := rw.Det
	if d == nil {
		return ""
	}
	var parts []string
	switch op {
	case engine.OpSecurity:
		parts = append(parts, plural(d.Apt.SecurityStrict, "paquet de sécurité", "paquets de sécurité"))
	case engine.OpFull:
		if d.Apt.Total > 0 {
			parts = append(parts, plural(d.Apt.Total, "paquet", "paquets"))
		}
		for _, a := range d.Apps {
			if a.UpdateAvailable() {
				p := a.Name + " " + a.Installed + " → " + a.Latest
				if a.MajorChange() {
					p += " (majeure)"
				}
				parts = append(parts, p)
			}
		}
	case engine.OpServices:
		parts = append(parts, strings.Join(d.RestartableUnits(), ", "))
	case engine.OpDocker:
		for _, g := range d.DockerInfo.UpdatableGroups() {
			parts = append(parts, fmt.Sprintf("%s (%d)", g.Name, g.Updates))
		}
	case engine.OpReboot:
		if d.RebootRequired {
			parts = append(parts, "redémarrage requis")
		} else {
			parts = append(parts, "CT redémarré (pct reboot)")
		}
	}
	return strings.Join(parts, " · ")
}

// batchPrepare affiche le lot à confirmer : invités sélectionnés dans « À
// traiter » (sel=nœud/vmid:op), ou tous les invités d'un tag (tag, op).
func (s *Server) batchPrepare(w http.ResponseWriter, r *http.Request, se *session) {
	q := r.URL.Query()
	byKey := s.guestsByKey()
	var reqs []engine.BatchRequest
	d := lotData{base: s.base("Préparer un lot", "traiter", se), Error: q.Get("erreur"), Back: "/", Stop: q.Get("choix") == "" || q.Get("arret") == "1"}
	// Retour après une erreur : les choix faits sur la page sont rendus tels quels.
	choice := q.Get("choix") == "1"
	snapSet, removed := map[string]bool{}, map[string]bool{}
	for _, v := range q["snap"] {
		snapSet[v] = true
	}
	for _, v := range q["retire"] {
		removed[v] = true
	}
	if tag := q.Get("tag"); tag != "" {
		op, err := engine.ParseOp(q.Get("op"))
		if err != nil || !op.Update() {
			op = engine.OpSecurity
		}
		d.Source = "tag « " + tag + " » · " + op.Label()
		d.Back = "/inventaire?grouper=tag"
		snap, _ := s.inv.Current()
		for _, g := range snap.Guests {
			if (g.Type != "lxc" && g.Type != "qemu") || !hasTag(g.Tags, tag) {
				continue
			}
			rw := s.rowFor(g)
			if rw.Det == nil || (op == engine.OpSecurity && rw.Det.Apt.Security == 0) || (op == engine.OpFull && rw.Det.Apt.Total == 0 && rw.Det.AppUpdates() == 0) {
				continue
			}
			reqs = append(reqs, engine.BatchRequest{Guest: g, Op: op})
		}
	} else {
		d.Source = "sélection de « À traiter »"
		// Par invité : une mise à jour (« tout » l'emporte sur « sécurité »),
		// puis les redémarrages demandés, dans l'ordre de la page.
		upd := map[string]int{}
		seen := map[string]bool{}
		for _, v := range q["sel"] {
			key, op, ok := strings.Cut(v, ":")
			o, err := engine.ParseOp(op)
			g, found := byKey[key]
			if !ok || err != nil || !found || seen[key+":"+op] {
				continue
			}
			seen[key+":"+op] = true
			if o.Update() {
				if i, dup := upd[key]; dup {
					if o == engine.OpFull {
						reqs[i].Op = o
					}
					continue
				}
				upd[key] = len(reqs)
			}
			reqs = append(reqs, engine.BatchRequest{Guest: g, Op: o})
		}
	}
	if len(reqs) > maxBatch {
		reqs = reqs[:maxBatch]
	}
	// Snapshot pré-coché comme sur la page de confirmation d'une mise à jour
	// (ou tel que choisi, au retour d'une erreur).
	for i := range reqs {
		if choice {
			reqs[i].Snapshot = snapSet[reqs[i].Guest.Key()+":"+string(reqs[i].Op)]
			continue
		}
		if reqs[i].Op.Update() {
			p := s.deps.Engine.PlanFor(reqs[i].Guest, engine.Action(reqs[i].Op))
			reqs[i].Snapshot = p.Snap.Checked && p.Snap.Possible
		} else if reqs[i].Op == engine.OpDocker {
			p := s.deps.Engine.PlanDocker(reqs[i].Guest, nil)
			reqs[i].Snapshot = p.Snap.Checked && p.Snap.Possible
		}
	}
	why := s.deps.Engine.PreviewBatch(reqs)
	for i, rq := range reqs {
		rw := s.rowFor(rq.Guest)
		lr := lotRow{Index: i, Row: rw, Op: rq.Op, Ops: opChoices(rq.Op), Snapshot: rq.Snapshot, Why: why[i], Detail: s.opDetail(rw, rq.Op), Removed: removed[rq.Guest.Key()+":"+string(rq.Op)]}
		if rq.Op.Update() {
			p := s.deps.Engine.PlanFor(rq.Guest, engine.Action(rq.Op))
			lr.SnapPossible, lr.SnapWhy = p.Snap.Possible, p.Snap.Why
		} else if rq.Op == engine.OpDocker {
			p := s.deps.Engine.PlanDocker(rq.Guest, nil)
			lr.SnapPossible, lr.SnapWhy = p.Snap.Possible, p.Snap.Why
		}
		if st := s.deps.Engine.WindowFor(rq.Guest, s.now()); st.Covered && !st.Open {
			lr.OutWindow = "« " + st.Next.Name + " » " + window.FormatTime(st.NextAt)
		}
		if lr.Why == "" {
			d.Runnable++
		}
		d.Rows = append(d.Rows, lr)
	}
	for _, w := range s.deps.Engine.MaintenanceWindows() {
		start, _ := w.Next(s.now())
		d.Windows = append(d.Windows, windowChoice{Name: w.Name, Label: w.Label(), Next: window.FormatTime(start), Open: w.Open(s.now())})
	}
	s.render(w, "lot", http.StatusOK, d)
}

// batchSubmit lance le lot confirmé (ou sa simulation).
func (s *Server) batchSubmit(w http.ResponseWriter, r *http.Request, se *session) {
	byKey := s.guestsByKey()
	var reqs []engine.BatchRequest
	var keep url.Values = url.Values{}
	for i := 0; i < maxBatch; i++ {
		key := r.PostFormValue("cle_" + strconv.Itoa(i))
		if key == "" {
			break
		}
		g, ok := byKey[key]
		op, err := engine.ParseOp(r.PostFormValue("op_" + strconv.Itoa(i)))
		if !ok || err != nil {
			continue
		}
		keep.Add("sel", key+":"+string(op))
		snap := r.PostFormValue("snap_"+strconv.Itoa(i)) == "1"
		if snap {
			keep.Add("snap", key+":"+string(op))
		}
		if r.PostFormValue("garder_"+strconv.Itoa(i)) != "1" {
			keep.Add("retire", key+":"+string(op))
			continue // retiré du lot
		}
		reqs = append(reqs, engine.BatchRequest{Guest: g, Op: op, Snapshot: snap})
	}
	back := func(msg string) {
		keep.Set("choix", "1")
		if r.PostFormValue("arret") == "1" {
			keep.Set("arret", "1")
		}
		keep.Set("erreur", msg)
		http.Redirect(w, r, "/lot?"+keep.Encode(), http.StatusSeeOther)
	}
	mode := r.PostFormValue("mode")
	dry := mode != "appliquer" && mode != "programmer"
	if !dry && r.PostFormValue("confirme") != "1" {
		back("cochez la case de confirmation pour appliquer le lot")
		return
	}
	var b engine.Batch
	var err error
	if mode == "programmer" {
		b, err = s.deps.Engine.ScheduleBatch(reqs, r.PostFormValue("arret") == "1", se.user, r.PostFormValue("fenetre"))
	} else {
		b, err = s.deps.Engine.StartBatch(reqs, dry, r.PostFormValue("arret") == "1", se.user)
	}
	if err != nil {
		back(err.Error())
		return
	}
	s.log.Info("lot lancé", "lot", b.ID, "opérations", len(b.Items), "simulation", dry, "par", se.user)
	http.Redirect(w, r, "/lots/"+b.ID, http.StatusSeeOther)
}

type lotsData struct {
	base
	Batch engine.Batch
	Live  bool
	Error string
}

func (s *Server) batchPage(w http.ResponseWriter, r *http.Request, se *session) {
	if s.deps.Batches == nil {
		http.NotFound(w, r)
		return
	}
	b, ok := s.deps.Batches.Get(r.PathValue("id"))
	if !ok {
		http.Error(w, "Lot inconnu", http.StatusNotFound)
		return
	}
	title := "Lot"
	if b.DryRun {
		title = "Lot simulé"
	}
	s.render(w, "lots", http.StatusOK, lotsData{base: s.base(title, "taches", se), Batch: b, Live: b.Running(), Error: r.URL.Query().Get("erreur")})
}

// batchCancel annule un lot programmé.
func (s *Server) batchCancel(w http.ResponseWriter, r *http.Request, se *session) {
	id := r.PathValue("id")
	if err := s.deps.Engine.CancelBatch(id, se.user); err != nil {
		http.Redirect(w, r, "/lots/"+url.PathEscape(id)+"?erreur="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	s.log.Info("lot programmé annulé", "lot", id, "par", se.user)
	http.Redirect(w, r, "/lots/"+url.PathEscape(id), http.StatusSeeOther)
}

type restartData struct {
	base
	Row   row
	Plan  engine.RestartPlan
	What  string // "services" ou "ct"
	Error string
}

func (s *Server) restartPage(w http.ResponseWriter, r *http.Request, se *session) {
	g, ok := s.findGuest(r)
	if !ok {
		http.Error(w, "Invité inconnu (rafraîchissez l'inventaire)", http.StatusNotFound)
		return
	}
	what := r.URL.Query().Get("quoi")
	if what != "services" {
		what = "ct"
	}
	title := "Redémarrer le CT"
	if what == "services" {
		title = "Redémarrer les services"
	}
	s.render(w, "redemarrage", http.StatusOK, restartData{
		base: s.base(title+" · "+g.Name, "inventaire", se), Row: s.rowFor(g),
		Plan: s.deps.Engine.PlanRestart(g), What: what, Error: r.URL.Query().Get("erreur"),
	})
}

func (s *Server) restartSubmit(w http.ResponseWriter, r *http.Request, se *session) {
	g, ok := s.findGuest(r)
	if !ok {
		http.Error(w, "Invité inconnu (rafraîchissez l'inventaire)", http.StatusNotFound)
		return
	}
	what := r.URL.Query().Get("quoi")
	confirmed := r.PostFormValue("confirme") == "1"
	var j jobs.Job
	var err error
	if what == "services" {
		j, err = s.deps.Engine.RestartServices(g, se.user, confirmed)
	} else {
		what = "ct"
		j, err = s.deps.Engine.Reboot(g, se.user, confirmed, r.PostFormValue("nom"))
	}
	if err != nil {
		if errors.Is(err, jobs.ErrBusy) {
			if act, ok := s.deps.Jobs.ActiveFor(jobs.Target{Node: g.Node, VMID: g.VMID}); ok {
				http.Redirect(w, r, "/taches/"+act.ID, http.StatusSeeOther)
				return
			}
		}
		http.Redirect(w, r, fmt.Sprintf("%s/redemarrage?quoi=%s&erreur=%s", guestURL(g), what, url.QueryEscape(err.Error())), http.StatusSeeOther)
		return
	}
	s.log.Info("redémarrage demandé", "invité", g.Key(), "quoi", what, "tâche", j.ID, "par", se.user)
	http.Redirect(w, r, "/taches/"+j.ID, http.StatusSeeOther)
}
