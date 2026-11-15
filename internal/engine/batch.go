package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/LuckyS7evin/patchwarden/internal/inventory"
	"github.com/LuckyS7evin/patchwarden/internal/jobs"
	"github.com/LuckyS7evin/patchwarden/internal/notify"
)

// Op est une opération d'un lot.
type Op string

// Opérations possibles dans un lot.
const (
	OpSecurity Op = "securite"
	OpFull     Op = "complet"
	OpServices Op = "services"
	OpReboot   Op = "redemarrage"
	// OpDocker : mise à jour des stacks et projets compose qui ont une nouvelle image.
	OpDocker Op = "docker"
)

// ParseOp valide une opération venue de l'interface.
func ParseOp(s string) (Op, error) {
	switch Op(s) {
	case OpSecurity, OpFull, OpServices, OpReboot, OpDocker:
		return Op(s), nil
	}
	return "", fmt.Errorf("opération inconnue : %q", s)
}

// Label renvoie le libellé affiché.
func (o Op) Label() string {
	switch o {
	case OpSecurity:
		return "sécurité uniquement"
	case OpFull:
		return "tout mettre à jour"
	case OpServices:
		return "redémarrer les services"
	case OpReboot:
		return "redémarrer l'invité"
	case OpDocker:
		return "conteneurs Docker"
	}
	return string(o)
}

// Update dit si l'opération est une mise à jour (snapshot possible).
func (o Op) Update() bool { return o == OpSecurity || o == OpFull }

// Snapshotable dit si l'opération accepte un snapshot avant (et une simulation).
func (o Op) Snapshotable() bool { return o.Update() || o == OpDocker }

// États d'un élément de lot.
const (
	ItemPending   = "en attente"
	ItemRunning   = "en cours"
	ItemSuccess   = "réussie"
	ItemFailed    = "échouée"
	ItemCancelled = "annulée"
	ItemSkipped   = "ignorée"
)

// États d'un lot.
const (
	BatchRunning     = "en cours"
	BatchDone        = "terminé"
	BatchStopped     = "arrêté après un échec"
	BatchInterrupted = "interrompu"
)

// BatchItem est une opération sur un invité.
type BatchItem struct {
	Node     string `json:"node"`
	VMID     int    `json:"vmid"`
	Name     string `json:"name"`
	Op       Op     `json:"op"`
	Snapshot bool   `json:"snapshot,omitempty"`
	JobID    string `json:"job_id,omitempty"`
	Status   string `json:"status"`
	Error    string `json:"error,omitempty"`
	Summary  string `json:"summary,omitempty"`
}

// Key renvoie la clé de l'invité.
func (it BatchItem) Key() string { return VMIDKey(it.Node, it.VMID) }

// Batch est un lot d'opérations exécutées l'une après l'autre.
type Batch struct {
	ID         string      `json:"id"`
	CreatedAt  time.Time   `json:"created_at"`
	EndedAt    time.Time   `json:"ended_at,omitempty"`
	By         string      `json:"by"`
	DryRun     bool        `json:"dry_run"`
	StopOnFail bool        `json:"stop_on_fail"`
	Status     string      `json:"status"`
	Items      []BatchItem `json:"items"`
}

// Running dit si le lot n'est pas terminé.
func (b Batch) Running() bool { return b.Status == BatchRunning }

// Count compte les éléments dans un état.
func (b Batch) Count(status string) int {
	n := 0
	for _, it := range b.Items {
		if it.Status == status {
			n++
		}
	}
	return n
}

// BatchRequest est une opération demandée pour un lot.
type BatchRequest struct {
	Guest    inventory.Guest
	Op       Op
	Snapshot bool
}

// BatchStore conserve les lots sur disque (un fichier JSON par lot).
type BatchStore struct {
	dir  string
	mu   sync.Mutex
	m    map[string]*Batch
	jobs map[string]bool // tâches lancées par un lot (notification résumée)
	keep int
}

// OpenBatches charge les lots ; un lot resté « en cours » (PatchWarden arrêté
// pendant son exécution) est marqué interrompu.
func OpenBatches(dataDir string) (*BatchStore, error) {
	s := &BatchStore{dir: filepath.Join(dataDir, "lots"), m: map[string]*Batch{}, jobs: map[string]bool{}, keep: 50}
	if err := os.MkdirAll(s.dir, 0o750); err != nil {
		return nil, err
	}
	ents, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	for _, e := range ents {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(s.dir, e.Name()))
		if err != nil {
			continue
		}
		var bt Batch
		if json.Unmarshal(b, &bt) != nil || bt.ID == "" {
			continue
		}
		if bt.Status == BatchRunning {
			bt.Status = BatchInterrupted
			for i := range bt.Items {
				if bt.Items[i].Status == ItemPending || bt.Items[i].Status == ItemRunning {
					bt.Items[i].Status = ItemCancelled
					bt.Items[i].Error = "PatchWarden a redémarré pendant le lot"
				}
			}
			_ = s.saveLocked(&bt)
		}
		s.m[bt.ID] = &bt
	}
	return s, nil
}

func (s *BatchStore) saveLocked(b *Batch) error {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	p := filepath.Join(s.dir, b.ID+".json")
	if err := os.WriteFile(p+".tmp", data, 0o640); err != nil {
		return err
	}
	return os.Rename(p+".tmp", p)
}

// Get renvoie une copie d'un lot.
func (s *BatchStore) Get(id string) (Batch, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.m[id]
	if !ok {
		return Batch{}, false
	}
	c := *b
	c.Items = append([]BatchItem(nil), b.Items...)
	return c, true
}

// List renvoie les lots, les plus récents d'abord.
func (s *BatchStore) List(limit int) []Batch {
	s.mu.Lock()
	out := make([]Batch, 0, len(s.m))
	for _, b := range s.m {
		c := *b
		c.Items = append([]BatchItem(nil), b.Items...)
		out = append(out, c)
	}
	s.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func (s *BatchStore) update(id string, fn func(*Batch)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if b, ok := s.m[id]; ok {
		fn(b)
		_ = s.saveLocked(b)
	}
}

func (s *BatchStore) prune() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.m) <= s.keep {
		return
	}
	all := make([]*Batch, 0, len(s.m))
	for _, b := range s.m {
		all = append(all, b)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].CreatedAt.After(all[j].CreatedAt) })
	for _, b := range all[s.keep:] {
		if b.Running() {
			continue
		}
		delete(s.m, b.ID)
		_ = os.Remove(filepath.Join(s.dir, b.ID+".json"))
	}
}

// FromBatch dit si une tâche a été lancée par un lot.
func (s *BatchStore) FromBatch(jobID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.jobs[jobID]
}

// ErrEmptyBatch : aucune opération possible dans la demande.
var ErrEmptyBatch = errors.New("aucune opération possible dans ce lot")

// checkOp vérifie qu'une opération est possible maintenant (sinon : pourquoi).
func (e *Engine) checkOp(r BatchRequest) string {
	g := r.Guest
	if g.Critical {
		return "invité à confirmation renforcée (" + g.CriticalReason + ") : à lancer depuis sa fiche"
	}
	if det, ok := e.Store.Get(target(g).Key()); ok && det.Special != "" {
		return det.SpecialLabel() + " : à lancer depuis sa fiche (confirmation renforcée)"
	}
	switch r.Op {
	case OpSecurity, OpFull:
		p := e.PlanFor(g, Action(r.Op))
		if !p.OK() {
			return p.Blockers[0]
		}
		if r.Snapshot && !p.Snap.Possible {
			return "snapshot impossible : " + p.Snap.Why
		}
	case OpServices:
		p := e.PlanRestart(g)
		if !p.CanServices() {
			if p.Why != "" {
				return p.Why
			}
			return "aucun service à redémarrer"
		}
	case OpReboot:
		if p := e.PlanRestart(g); !p.CanReboot() {
			return p.Why
		}
	case OpDocker:
		p := e.PlanDocker(g, nil)
		if !p.OK() {
			return p.Blockers[0]
		}
		if r.Snapshot && !p.Snap.Possible {
			return "snapshot impossible : " + p.Snap.Why
		}
	}
	return ""
}

// PreviewBatch indique, pour chaque demande, pourquoi elle serait ignorée.
func (e *Engine) PreviewBatch(reqs []BatchRequest) []string {
	out := make([]string, len(reqs))
	for i, r := range reqs {
		out[i] = e.checkOp(r)
	}
	return out
}

func newBatchID(now time.Time) string {
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	return "lot-" + now.Format("20060102-150405") + "-" + hex.EncodeToString(b)
}

// StartBatch lance un lot : les opérations s'enchaînent une par une, dans
// l'ordre ; avec stopOnFail, un échec annule la suite. Un invité peut avoir
// une mise à jour puis un redémarrage, mais pas deux fois la même sorte
// d'opération. Les opérations impossibles sont ignorées (avec la raison).
func (e *Engine) StartBatch(reqs []BatchRequest, dryRun, stopOnFail bool, user string) (Batch, error) {
	if e.Batches == nil {
		return Batch{}, errors.New("lots indisponibles")
	}
	now := time.Now()
	b := &Batch{ID: newBatchID(now), CreatedAt: now, By: user, DryRun: dryRun, StopOnFail: stopOnFail, Status: BatchRunning}
	seen := map[string]bool{}
	guests := map[int]inventory.Guest{}
	runnable := 0
	for _, r := range reqs {
		it := BatchItem{Node: r.Guest.Node, VMID: r.Guest.VMID, Name: r.Guest.Name, Op: r.Op, Snapshot: r.Snapshot && r.Op.Snapshotable(), Status: ItemPending}
		switch {
		case seen[opKind(it)]:
			it.Status, it.Error = ItemSkipped, "invité déjà présent dans ce lot pour ce type d'opération"
		case dryRun && !r.Op.Snapshotable():
			it.Status, it.Error = ItemSkipped, "les redémarrages n'ont pas de simulation"
		default:
			if why := e.checkOp(r); why != "" {
				it.Status, it.Error = ItemSkipped, why
			}
		}
		seen[opKind(it)] = true
		if it.Status == ItemPending {
			runnable++
		}
		guests[len(b.Items)] = r.Guest
		b.Items = append(b.Items, it)
	}
	if runnable == 0 {
		return Batch{}, ErrEmptyBatch
	}
	e.Batches.mu.Lock()
	e.Batches.m[b.ID] = b
	_ = e.Batches.saveLocked(b)
	e.Batches.mu.Unlock()
	e.Batches.prune()
	go e.runBatch(b.ID, guests)
	c, _ := e.Batches.Get(b.ID)
	return c, nil
}

// opKind : clé d'unicité dans un lot (une mise à jour, un redémarrage des
// services, un redémarrage du CT par invité).
func opKind(it BatchItem) string {
	k := string(it.Op)
	if it.Op.Update() {
		k = "maj"
	}
	return it.Key() + ":" + k
}

func (e *Engine) submitOp(g inventory.Guest, it BatchItem, dryRun bool, user string) (jobs.Job, error) {
	switch it.Op {
	case OpSecurity, OpFull:
		// La confirmation du lot vaut confirmation de chaque élément ; les
		// invités critiques (nom à saisir) sont exclus des lots.
		return e.Execute(g, Action(it.Op), dryRun, user, true, g.Name, it.Snapshot)
	case OpServices:
		return e.RestartServices(g, user, true)
	case OpReboot:
		return e.Reboot(g, user, true, g.Name)
	case OpDocker:
		return e.ExecuteDocker(g, nil, dryRun, user, true, g.Name, it.Snapshot)
	}
	return jobs.Job{}, fmt.Errorf("opération inconnue : %s", it.Op)
}

func (e *Engine) runBatch(id string, guests map[int]inventory.Guest) {
	b, _ := e.Batches.Get(id)
	stop := false
	for i, it := range b.Items {
		if it.Status != ItemPending {
			continue
		}
		if stop {
			e.Batches.update(id, func(bt *Batch) {
				bt.Items[i].Status, bt.Items[i].Error = ItemCancelled, "lot arrêté après un échec"
			})
			continue
		}
		j, err := e.submitOp(guests[i], it, b.DryRun, b.By)
		if err != nil {
			e.Batches.update(id, func(bt *Batch) { bt.Items[i].Status, bt.Items[i].Error = ItemFailed, err.Error() })
			stop = b.StopOnFail && !b.DryRun
			continue
		}
		e.Batches.mu.Lock()
		e.Batches.jobs[j.ID] = true
		e.Batches.mu.Unlock()
		e.Batches.update(id, func(bt *Batch) { bt.Items[i].Status, bt.Items[i].JobID = ItemRunning, j.ID })
		done := e.waitJob(context.Background(), j.ID)
		e.Batches.update(id, func(bt *Batch) {
			it := &bt.Items[i]
			it.Summary = done.Summary
			if done.Status == jobs.Success {
				it.Status = ItemSuccess
			} else {
				it.Status, it.Error = ItemFailed, done.Error
				if it.Error == "" {
					it.Error = string(done.Status)
				}
			}
		})
		if done.Status != jobs.Success && b.StopOnFail && !b.DryRun {
			stop = true
		}
	}
	e.Batches.update(id, func(bt *Batch) {
		bt.EndedAt = time.Now()
		bt.Status = BatchDone
		if stop {
			bt.Status = BatchStopped
		}
	})
	e.notifyBatch(id)
}

// notifyBatch envoie un seul message pour un lot réel (les tâches du lot ne
// notifient pas une à une).
func (e *Engine) notifyBatch(id string) {
	b, ok := e.Batches.Get(id)
	if !ok || b.DryRun || e.Notify == nil {
		return
	}
	ok2, failed := b.Count(ItemSuccess), b.Count(ItemFailed)
	m := notify.Message{URL: e.link("/lots/" + b.ID)}
	var lines []string
	for _, it := range b.Items {
		line := fmt.Sprintf("%s (%s/%d) : %s — %s", it.Name, it.Node, it.VMID, it.Op.Label(), it.Status)
		if it.Error != "" && it.Status != ItemSuccess {
			line += " : " + it.Error
		}
		lines = append(lines, line)
	}
	m.Body = strings.Join(lines, "\n")
	if failed == 0 && b.Status == BatchDone {
		m.Event, m.Priority = notify.EvSuccess, 2
		m.Title = fmt.Sprintf("PatchWarden : lot terminé, %d opération(s) réussie(s)", ok2)
	} else {
		m.Event, m.Priority = notify.EvFailure, 4
		m.Title = fmt.Sprintf("PatchWarden : lot %s, %d réussie(s), %d échec(s)", b.Status, ok2, failed)
	}
	e.Notify.Notify(m)
}
