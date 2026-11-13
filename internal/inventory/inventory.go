// Package inventory construit la liste des invités (LXC et VM) à partir d'un
// ou plusieurs points d'accès Proxmox, en cluster comme en nœuds autonomes.
package inventory

import (
	"context"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/LuckyS7evin/patchwarden/internal/config"
	"github.com/LuckyS7evin/patchwarden/internal/proxmox"
)

// Source fournit les invités vus par un point d'accès.
type Source interface {
	Name() string
	Guests(ctx context.Context) ([]proxmox.Resource, error)
}

// Guest est un invité tel que l'affiche PatchWarden.
type Guest struct {
	Node     string
	Type     string // "lxc" ou "qemu"
	VMID     int
	Name     string
	Status   string
	Tags     []string
	Template bool
	Lock     string

	// CommunityScript : LXC portant le tag community-scripts.
	CommunityScript bool
	// Critical : confirmation renforcée exigée ; CriticalReason dit pourquoi.
	Critical       bool
	CriticalReason string
	// Stale : le nœud n'a pas répondu au dernier rafraîchissement ; données
	// issues de la lecture précédente.
	Stale bool
}

// Key identifie un invité de façon unique.
func (g Guest) Key() string { return g.Node + "/" + strconv.Itoa(g.VMID) }

// TypeLabel renvoie « LXC » ou « VM ».
func (g Guest) TypeLabel() string {
	if g.Type == "lxc" {
		return "LXC"
	}
	return "VM"
}

// Snapshot est l'état de l'inventaire à un instant donné.
type Snapshot struct {
	Guests    []Guest
	FetchedAt time.Time
	// Errors : erreur par point d'accès lors du dernier rafraîchissement.
	Errors map[string]string
}

// Nodes renvoie les nœuds présents, triés.
func (s Snapshot) Nodes() []string {
	set := map[string]bool{}
	for _, g := range s.Guests {
		set[g.Node] = true
	}
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Service tient l'inventaire à jour sans jamais bloquer l'interface.
type Service struct {
	sources []Source
	policy  config.Policy
	timeout time.Duration
	log     *slog.Logger

	mu         sync.RWMutex
	snap       Snapshot
	refreshing bool
	trigger    chan struct{}
}

// New crée le service.
func New(sources []Source, policy config.Policy, timeout time.Duration, log *slog.Logger) *Service {
	return &Service{
		sources: sources,
		policy:  policy,
		timeout: timeout,
		log:     log,
		trigger: make(chan struct{}, 1),
	}
}

// Current renvoie le dernier inventaire connu.
func (s *Service) Current() (Snapshot, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.snap, s.refreshing
}

// TriggerRefresh demande un rafraîchissement asynchrone. Les demandes
// multiples sont fusionnées.
func (s *Service) TriggerRefresh() {
	select {
	case s.trigger <- struct{}{}:
	default:
	}
}

// Run rafraîchit au démarrage, puis à intervalle régulier ou sur demande.
func (s *Service) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	s.Refresh(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-s.trigger:
		}
		s.Refresh(ctx)
	}
}

// Refresh interroge tous les points d'accès en parallèle et fusionne.
func (s *Service) Refresh(ctx context.Context) {
	s.mu.Lock()
	s.refreshing = true
	prev := s.snap
	s.mu.Unlock()

	type result struct {
		name string
		res  []proxmox.Resource
		err  error
	}
	results := make([]result, len(s.sources))
	var wg sync.WaitGroup
	for i, src := range s.sources {
		wg.Add(1)
		go func(i int, src Source) {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, s.timeout)
			defer cancel()
			r, err := src.Guests(cctx)
			results[i] = result{src.Name(), r, err}
		}(i, src)
	}
	wg.Wait()

	next := Snapshot{FetchedAt: time.Now(), Errors: map[string]string{}}
	byKey := map[string]Guest{}
	covered := map[string]bool{} // nœuds présents dans au moins une réponse
	for _, r := range results {
		if r.err != nil {
			next.Errors[r.name] = r.err.Error()
			s.log.Warn("inventaire : point d'accès en erreur", "point", r.name, "erreur", r.err)
			continue
		}
		for _, res := range r.res {
			if res.Type != "lxc" && res.Type != "qemu" {
				continue
			}
			g := s.classify(res)
			covered[g.Node] = true
			if _, dup := byKey[g.Key()]; !dup {
				byKey[g.Key()] = g
			}
		}
	}
	// Un nœud qui n'a répondu par aucun point d'accès garde ses invités de la
	// lecture précédente, marqués comme périmés, plutôt que de disparaître.
	for _, g := range prev.Guests {
		if !covered[g.Node] {
			g.Stale = true
			byKey[g.Key()] = g
		}
	}
	for _, g := range byKey {
		next.Guests = append(next.Guests, g)
	}
	sort.Slice(next.Guests, func(i, j int) bool {
		a, b := next.Guests[i], next.Guests[j]
		if a.Node != b.Node {
			return a.Node < b.Node
		}
		return a.VMID < b.VMID
	})

	s.mu.Lock()
	s.snap = next
	s.refreshing = false
	s.mu.Unlock()
	s.log.Info("inventaire rafraîchi", "invités", len(next.Guests), "erreurs", len(next.Errors))
}

func (s *Service) classify(r proxmox.Resource) Guest {
	g := Guest{
		Node:     r.Node,
		Type:     r.Type,
		VMID:     r.VMID,
		Name:     r.Name,
		Status:   r.Status,
		Template: r.Template == 1,
		Lock:     r.Lock,
	}
	for _, t := range strings.FieldsFunc(r.Tags, func(c rune) bool { return c == ';' || c == ',' || c == ' ' }) {
		g.Tags = append(g.Tags, strings.ToLower(t))
	}
	g.CommunityScript = g.Type == "lxc" && hasTag(g.Tags, s.policy.CommunityScriptTag)
	for _, t := range s.policy.CriticalTags {
		if hasTag(g.Tags, t) {
			g.Critical, g.CriticalReason = true, "tag « "+strings.ToLower(t)+" »"
			break
		}
	}
	if !g.Critical {
		lname := strings.ToLower(g.Name)
		for _, n := range s.policy.SpecialNames {
			if n != "" && strings.Contains(lname, strings.ToLower(n)) {
				g.Critical, g.CriticalReason = true, "nom contenant « "+strings.ToLower(n)+" »"
				break
			}
		}
	}
	return g
}

func hasTag(tags []string, want string) bool {
	want = strings.ToLower(want)
	for _, t := range tags {
		if t == want {
			return true
		}
	}
	return false
}
