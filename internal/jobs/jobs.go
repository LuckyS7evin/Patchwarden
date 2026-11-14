// Package jobs exécute les tâches (détection, mises à jour) en arrière-plan :
// jamais deux tâches à la fois sur un même invité, un nombre limité de tâches
// simultanées, un journal conservé sur disque et diffusé en direct.
package jobs

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"
)

// Status est l'état d'une tâche.
type Status string

// États possibles.
const (
	Queued      Status = "en attente"
	Running     Status = "en cours"
	Success     Status = "réussie"
	Failed      Status = "échouée"
	Interrupted Status = "interrompue"
)

// Finished indique si la tâche est terminée.
func (s Status) Finished() bool { return s == Success || s == Failed || s == Interrupted }

// Kind est le type de tâche.
type Kind string

// Types de tâches.
const (
	KindDetect   Kind = "détection"
	KindSecurity Kind = "sécurité uniquement"
	KindFull     Kind = "tout mettre à jour"
)

// Target est l'invité visé.
type Target struct {
	Node string `json:"node"`
	VMID int    `json:"vmid"`
	Type string `json:"type"`
	Name string `json:"name"`
}

// Key identifie l'invité.
func (t Target) Key() string { return t.Node + "/" + strconv.Itoa(t.VMID) }

// Job décrit une tâche.
type Job struct {
	ID          string    `json:"id"`
	Kind        Kind      `json:"kind"`
	Target      Target    `json:"target"`
	DryRun      bool      `json:"dry_run"`
	Status      Status    `json:"status"`
	RequestedBy string    `json:"requested_by"`
	CreatedAt   time.Time `json:"created_at"`
	StartedAt   time.Time `json:"started_at,omitempty"`
	EndedAt     time.Time `json:"ended_at,omitempty"`
	Summary     string    `json:"summary,omitempty"`
	Error       string    `json:"error,omitempty"`
}

// Duration renvoie la durée d'exécution (ou écoulée si en cours).
func (j Job) Duration() time.Duration {
	if j.StartedAt.IsZero() {
		return 0
	}
	end := j.EndedAt
	if end.IsZero() {
		end = time.Now()
	}
	return end.Sub(j.StartedAt).Round(time.Second)
}

// Line est une ligne du journal d'une tâche.
type Line struct {
	T      time.Time `json:"t"`
	Stderr bool      `json:"e,omitempty"`
	Text   string    `json:"x"`
}

// Event est diffusé aux abonnés : une ligne, ou la fin de la tâche.
type Event struct {
	Line *Line
	Done *Job
}

// Logger écrit dans le journal de la tâche.
type Logger func(stderr bool, text string)

// Func est le travail d'une tâche. Le résumé est affiché dans l'historique ;
// une erreur fait échouer la tâche.
type Func func(ctx context.Context, job Job, log Logger) (summary string, err error)

// ErrBusy : une tâche est déjà en attente ou en cours pour cet invité.
var ErrBusy = errors.New("une tâche est déjà en attente ou en cours pour cet invité")

type entry struct {
	job   Job
	lines []Line // gardées en mémoire tant que la tâche n'est pas terminée
	file  *os.File
	subs  map[chan Event]struct{}
}

// Manager orchestre les tâches.
type Manager struct {
	dir       string
	retention int
	sem       chan struct{}
	log       *slog.Logger
	now       func() time.Time

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu     sync.Mutex
	jobs   map[string]*entry
	active map[string]string // clé d'invité -> ID de tâche
}

// New ouvre (ou crée) le répertoire des tâches et recharge l'historique. Les
// tâches restées « en cours » lors d'un arrêt brutal sont marquées interrompues.
func New(dir string, maxParallel, retention int, log *slog.Logger) (*Manager, error) {
	if err := os.MkdirAll(filepath.Join(dir, "jobs"), 0o750); err != nil {
		return nil, fmt.Errorf("répertoire des tâches : %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	m := &Manager{
		dir: dir, retention: retention, sem: make(chan struct{}, maxParallel), log: log, now: time.Now,
		ctx: ctx, cancel: cancel, jobs: map[string]*entry{}, active: map[string]string{},
	}
	ents, err := os.ReadDir(filepath.Join(dir, "jobs"))
	if err != nil {
		return nil, err
	}
	for _, de := range ents {
		if !de.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, "jobs", de.Name(), "meta.json"))
		if err != nil {
			continue
		}
		var j Job
		if json.Unmarshal(b, &j) != nil || j.ID != de.Name() {
			continue
		}
		if !j.Status.Finished() {
			j.Status = Interrupted
			j.Error = "PatchWarden s'est arrêté pendant l'exécution ; l'état réel de l'invité est à vérifier"
			if j.EndedAt.IsZero() {
				j.EndedAt = m.now()
			}
			_ = m.writeMeta(j)
		}
		m.jobs[j.ID] = &entry{job: j}
	}
	m.prune()
	return m, nil
}

// Close interrompt les tâches en cours et attend leur fin.
func (m *Manager) Close() {
	m.cancel()
	m.wg.Wait()
}

func newID(t time.Time) string {
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	return t.Format("20060102-150405") + "-" + hex.EncodeToString(b)
}

// Submit met une tâche en file. Elle est refusée si l'invité a déjà une tâche active.
func (m *Manager) Submit(kind Kind, target Target, dryRun bool, requestedBy string, fn Func) (Job, error) {
	m.mu.Lock()
	if id, busy := m.active[target.Key()]; busy {
		m.mu.Unlock()
		return Job{}, fmt.Errorf("%w (tâche %s)", ErrBusy, id)
	}
	now := m.now()
	j := Job{ID: newID(now), Kind: kind, Target: target, DryRun: dryRun, Status: Queued, RequestedBy: requestedBy, CreatedAt: now}
	jdir := filepath.Join(m.dir, "jobs", j.ID)
	if err := os.MkdirAll(jdir, 0o750); err != nil {
		m.mu.Unlock()
		return Job{}, err
	}
	f, err := os.OpenFile(filepath.Join(jdir, "output.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		m.mu.Unlock()
		return Job{}, err
	}
	e := &entry{job: j, file: f, subs: map[chan Event]struct{}{}}
	m.jobs[j.ID] = e
	m.active[target.Key()] = j.ID
	m.mu.Unlock()
	if err := m.writeMeta(j); err != nil {
		m.log.Error("écriture de la tâche", "id", j.ID, "erreur", err)
	}

	m.wg.Add(1)
	go m.run(e, fn)
	return j, nil
}

func (m *Manager) run(e *entry, fn Func) {
	defer m.wg.Done()
	select {
	case m.sem <- struct{}{}:
	case <-m.ctx.Done():
		m.finish(e, Interrupted, "", "arrêt de PatchWarden avant le démarrage")
		return
	}
	defer func() { <-m.sem }()

	m.mu.Lock()
	e.job.Status = Running
	e.job.StartedAt = m.now()
	j := e.job
	m.mu.Unlock()
	_ = m.writeMeta(j)
	m.log.Info("tâche démarrée", "id", j.ID, "type", j.Kind, "invité", j.Target.Key())

	logf := func(stderr bool, text string) { m.append(e, stderr, text) }
	summary, err := func() (s string, err error) {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("erreur interne : %v", r)
			}
		}()
		return fn(m.ctx, j, logf)
	}()
	switch {
	case err == nil:
		m.finish(e, Success, summary, "")
	case m.ctx.Err() != nil:
		m.finish(e, Interrupted, summary, err.Error())
	default:
		m.finish(e, Failed, summary, err.Error())
	}
}

func (m *Manager) append(e *entry, stderr bool, text string) {
	l := Line{T: m.now(), Stderr: stderr, Text: text}
	b, _ := json.Marshal(l)
	m.mu.Lock()
	defer m.mu.Unlock()
	e.lines = append(e.lines, l)
	if e.file != nil {
		_, _ = e.file.Write(append(b, '\n'))
	}
	for ch := range e.subs {
		select {
		case ch <- Event{Line: &l}:
		default:
			// Abonné trop lent : on le déconnecte plutôt que de bloquer la
			// tâche. Le navigateur se reconnecte et relit le journal complet.
			delete(e.subs, ch)
			close(ch)
		}
	}
}

func (m *Manager) finish(e *entry, st Status, summary, errText string) {
	m.mu.Lock()
	e.job.Status = st
	e.job.EndedAt = m.now()
	e.job.Summary = summary
	e.job.Error = errText
	j := e.job
	if e.file != nil {
		_ = e.file.Close()
		e.file = nil
	}
	for ch := range e.subs {
		select {
		case ch <- Event{Done: &j}:
		default:
		}
		close(ch)
	}
	e.subs = nil
	e.lines = nil
	delete(m.active, j.Target.Key())
	m.mu.Unlock()
	if err := m.writeMeta(j); err != nil {
		m.log.Error("écriture de la tâche", "id", j.ID, "erreur", err)
	}
	m.log.Info("tâche terminée", "id", j.ID, "statut", j.Status, "erreur", errText)
	m.prune()
}

func (m *Manager) writeMeta(j Job) error {
	b, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return err
	}
	p := filepath.Join(m.dir, "jobs", j.ID, "meta.json")
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// prune supprime les tâches terminées les plus anciennes au-delà de la rétention.
func (m *Manager) prune() {
	m.mu.Lock()
	ids := make([]string, 0, len(m.jobs))
	for id := range m.jobs {
		ids = append(ids, id)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(ids)))
	var drop []string
	for i, id := range ids {
		if i >= m.retention && m.jobs[id].job.Status.Finished() {
			drop = append(drop, id)
			delete(m.jobs, id)
		}
	}
	m.mu.Unlock()
	for _, id := range drop {
		_ = os.RemoveAll(filepath.Join(m.dir, "jobs", id))
	}
}

// Get renvoie une tâche.
func (m *Manager) Get(id string) (Job, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.jobs[id]
	if !ok {
		return Job{}, false
	}
	return e.job, true
}

// ActiveFor renvoie la tâche active d'un invité, s'il y en a une.
func (m *Manager) ActiveFor(t Target) (Job, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.active[t.Key()]
	if !ok {
		return Job{}, false
	}
	return m.jobs[id].job, true
}

// List renvoie les tâches, les plus récentes d'abord. targetKey vide = toutes.
func (m *Manager) List(targetKey string, limit int) []Job {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Job, 0, len(m.jobs))
	for _, e := range m.jobs {
		if targetKey == "" || e.job.Target.Key() == targetKey {
			out = append(out, e.job)
		}
	}
	sort.Slice(out, func(i, k int) bool { return out[i].ID > out[k].ID })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// Subscribe renvoie le journal déjà écrit et, si la tâche n'est pas terminée,
// un canal qui recevra la suite puis l'événement de fin.
func (m *Manager) Subscribe(id string) (past []Line, ch <-chan Event, cancel func(), err error) {
	m.mu.Lock()
	e, ok := m.jobs[id]
	if !ok {
		m.mu.Unlock()
		return nil, nil, nil, os.ErrNotExist
	}
	if e.job.Status.Finished() {
		m.mu.Unlock()
		lines, err := m.readLog(id)
		return lines, nil, func() {}, err
	}
	past = append([]Line(nil), e.lines...)
	c := make(chan Event, 256)
	e.subs[c] = struct{}{}
	m.mu.Unlock()
	cancel = func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		if e.subs != nil {
			if _, ok := e.subs[c]; ok {
				delete(e.subs, c)
				close(c)
			}
		}
	}
	return past, c, cancel, nil
}

// Log renvoie le journal complet d'une tâche.
func (m *Manager) Log(id string) ([]Line, error) {
	m.mu.Lock()
	e, ok := m.jobs[id]
	if ok && !e.job.Status.Finished() {
		lines := append([]Line(nil), e.lines...)
		m.mu.Unlock()
		return lines, nil
	}
	m.mu.Unlock()
	if !ok {
		return nil, os.ErrNotExist
	}
	return m.readLog(id)
}

func (m *Manager) readLog(id string) ([]Line, error) {
	f, err := os.Open(filepath.Join(m.dir, "jobs", id, "output.jsonl"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var out []Line
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var l Line
		if json.Unmarshal(sc.Bytes(), &l) == nil {
			out = append(out, l)
		}
	}
	return out, sc.Err()
}
