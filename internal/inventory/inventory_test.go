package inventory

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/LuckyS7evin/patchwarden/internal/config"
	"github.com/LuckyS7evin/patchwarden/internal/proxmox"
)

type fake struct {
	name string
	res  []proxmox.Resource
	err  error
}

func (f *fake) Name() string { return f.name }
func (f *fake) Guests(context.Context) ([]proxmox.Resource, error) {
	return f.res, f.err
}

var policy = config.Policy{
	CommunityScriptTag: "community-script",
	CriticalTags:       []string{"critique"},
	SpecialNames:       []string{"omv", "pbs"},
}

func newSvc(src ...Source) *Service {
	return New(src, policy, time.Second, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func cluster() []proxmox.Resource {
	return []proxmox.Resource{
		{Type: "lxc", VMID: 104, Node: "loki", Name: "termix", Status: "running", Tags: "community-script;ssh"},
		{Type: "qemu", VMID: 403, Node: "tyr", Name: "OMV6", Status: "running"},
		{Type: "qemu", VMID: 203, Node: "loki", Name: "PBS", Status: "running", Tags: "Critique"},
		{Type: "lxc", VMID: 117, Node: "odin", Name: "claude-ops", Status: "running", Tags: "community-script;os"},
		{Type: "storage", Node: "loki"},
	}
}

func TestClusterFromTwoEndpointsIsDeduplicated(t *testing.T) {
	s := newSvc(&fake{name: "loki", res: cluster()}, &fake{name: "tyr", res: cluster()})
	s.Refresh(context.Background())
	snap, _ := s.Current()
	if len(snap.Guests) != 4 {
		t.Fatalf("4 invités attendus (doublons et stockage exclus), obtenu %d", len(snap.Guests))
	}
	if snap.Guests[0].Key() != "loki/104" || snap.Guests[3].Key() != "tyr/403" {
		t.Errorf("tri nœud puis VMID incorrect : %v", snap.Guests)
	}
	if got := snap.Nodes(); len(got) != 3 {
		t.Errorf("nœuds : %v", got)
	}
}

func TestClassification(t *testing.T) {
	s := newSvc(&fake{name: "loki", res: cluster()})
	s.Refresh(context.Background())
	snap, _ := s.Current()
	by := map[int]Guest{}
	for _, g := range snap.Guests {
		by[g.VMID] = g
	}
	if !by[104].CommunityScript || by[104].Critical {
		t.Errorf("termix : %+v", by[104])
	}
	if !by[203].Critical || by[203].CriticalReason != "tag « critique »" {
		t.Errorf("PBS (tag en majuscules) : %+v", by[203])
	}
	if !by[403].Critical || by[403].CriticalReason != "nom contenant « omv »" {
		t.Errorf("OMV (par le nom) : %+v", by[403])
	}
	if by[403].CommunityScript {
		t.Error("une VM ne peut pas être community-script")
	}
}

func TestStandaloneNodeDownKeepsStaleGuests(t *testing.T) {
	loki := &fake{name: "loki", res: []proxmox.Resource{{Type: "lxc", VMID: 104, Node: "loki", Name: "termix"}}}
	tyr := &fake{name: "tyr", res: []proxmox.Resource{{Type: "qemu", VMID: 403, Node: "tyr", Name: "OMV6"}}}
	s := newSvc(loki, tyr)
	s.Refresh(context.Background())

	tyr.err = errors.New("délai dépassé")
	s.Refresh(context.Background())
	snap, _ := s.Current()
	if len(snap.Guests) != 2 {
		t.Fatalf("les invités de tyr doivent rester affichés : %+v", snap.Guests)
	}
	for _, g := range snap.Guests {
		if (g.Node == "tyr") != g.Stale {
			t.Errorf("marquage périmé incorrect : %+v", g)
		}
	}
	if snap.Errors["tyr"] == "" || snap.Errors["loki"] != "" {
		t.Errorf("erreurs par point d'accès : %v", snap.Errors)
	}
}

func TestTriggerRefreshCoalesces(t *testing.T) {
	s := newSvc(&fake{name: "loki"})
	for i := 0; i < 5; i++ {
		s.TriggerRefresh() // ne doit jamais bloquer
	}
	if len(s.trigger) != 1 {
		t.Errorf("demandes non fusionnées : %d", len(s.trigger))
	}
}

func TestNodeStats(t *testing.T) {
	src := &fake{name: "loki", res: []proxmox.Resource{
		{Type: "node", Node: "loki", Status: "online", CPU: 0.234, Mem: 6 << 30, MaxMem: 10 << 30},
		{Type: "storage", Node: "loki", Storage: "local", PluginType: "dir", Content: "iso,vztmpl,backup", Status: "available", Disk: 90, MaxDisk: 100},
		{Type: "storage", Node: "loki", Storage: "local-lvm", PluginType: "lvmthin", Content: "rootdir,images", Status: "available", Disk: 82, MaxDisk: 100},
		{Type: "storage", Node: "loki", Storage: "nas", PluginType: "nfs", Content: "images", Shared: 1, Status: "available", Disk: 99, MaxDisk: 100},
		{Type: "lxc", VMID: 104, Node: "loki", Name: "termix", Status: "running"},
	}}
	s := New([]Source{src}, config.Policy{}, time.Second, slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.Refresh(context.Background())
	snap, _ := s.Current()
	st := snap.NodeStats["loki"]
	if !st.Online || st.CPUPct() != 23 || st.MemPct() != 60 || st.Storage != "local-lvm" || st.StoragePct() != 82 || st.StorageType != "lvmthin" {
		t.Errorf("état du nœud : %+v", st)
	}
	if s, ok := st.PickStorage(map[string]bool{"local-lvm": true}); !ok || s.Name != "local-lvm" {
		t.Errorf("stockage choisi : %+v", s)
	}
	st.Storages = append(st.Storages, StorageStat{Name: "omv-data", Type: "lvm", Used: 99, Total: 100})
	if s, _ := st.PickStorage(map[string]bool{"local-lvm": true}); s.Name != "local-lvm" {
		t.Errorf("un stockage réservé à une VM ne doit pas l'emporter : %+v", s)
	}
	if s, _ := st.PickStorage(nil); s.Name != "local-lvm" {
		t.Errorf("repli : %+v", s)
	}
	if len(snap.Guests) != 1 {
		t.Errorf("les nœuds et stockages ne sont pas des invités : %+v", snap.Guests)
	}
	src.err = errors.New("délai dépassé")
	s.Refresh(context.Background())
	snap, _ = s.Current()
	if st := snap.NodeStats["loki"]; !st.Stale || st.Online || st.StoragePct() != 82 {
		t.Errorf("nœud injoignable : %+v", st)
	}
}

func TestHostsGroupedAndCritical(t *testing.T) {
	host := &fake{name: "hôte vps", res: []proxmox.Resource{{Type: TypeHost, Node: "vps", Name: "vps", Status: "running", Tags: "cloud"}}}
	s := newSvc(&fake{name: "loki", res: cluster()}, host)
	s.Refresh(context.Background())
	snap, _ := s.Current()
	var h *Guest
	for i := range snap.Guests {
		if snap.Guests[i].IsHost() {
			h = &snap.Guests[i]
		}
	}
	if h == nil || !h.Critical || !h.Managed() || h.TypeLabel() != "Hôte" || h.Where() != "hôte autonome" || h.Key() != "vps/0" || h.Tags[0] != "cloud" {
		t.Fatalf("hôte : %+v", h)
	}
	for _, n := range snap.Nodes() {
		if n == "vps" {
			t.Errorf("un hôte autonome n'est pas un nœud : %v", snap.Nodes())
		}
	}
	// Injoignable : reste affiché, état inconnu, erreur publiée.
	host.res[0].Status, host.err = "unknown", errors.New("connexion refusée")
	s.Refresh(context.Background())
	snap, _ = s.Current()
	found := false
	for _, g := range snap.Guests {
		if g.IsHost() && g.Status == "unknown" {
			found = true
		}
	}
	if !found || snap.Errors["hôte vps"] == "" {
		t.Errorf("hôte injoignable : %+v %v", snap.Guests, snap.Errors)
	}
}
