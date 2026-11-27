package engine

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/LuckyS7evin/patchwarden/internal/detect"
	"github.com/LuckyS7evin/patchwarden/internal/inventory"
	"github.com/LuckyS7evin/patchwarden/internal/proxmox"
)

// SnapLister lit les snapshots d'un invité par l'API Proxmox (lecture seule).
type SnapLister func(ctx context.Context, node, typ string, vmid int) ([]proxmox.Snapshot, error)

var snapSync struct {
	mu   sync.Mutex
	last map[string]time.Time // par invité
}

// SyncSnapshots rapproche les snapshots PatchWarden connus (relevés à la
// dernière détection) de ceux qui existent vraiment, par l'API Proxmox : un
// snapshot supprimé ou restauré hors de PatchWarden disparaît des pages sans
// attendre la détection suivante. Au plus une fois par minute et par invité ; les invités
// injoignables par l'API gardent leurs informations.
func (e *Engine) SyncSnapshots(guests []inventory.Guest) {
	if e.ListSnapshots == nil || e.Store == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	all := e.Store.All()
	for _, g := range guests {
		det, ok := all[g.Key()]
		if !ok || !det.Snap.Known || (g.Type != "lxc" && g.Type != "qemu") {
			continue
		}
		snapSync.mu.Lock()
		if snapSync.last == nil {
			snapSync.last = map[string]time.Time{}
		}
		recent := time.Since(snapSync.last[g.Key()]) < time.Minute
		if !recent {
			snapSync.last[g.Key()] = time.Now()
		}
		snapSync.mu.Unlock()
		if recent {
			continue
		}
		list, err := e.ListSnapshots(ctx, g.Node, g.Type, g.VMID)
		if err != nil {
			continue
		}
		info := reconcileSnaps(det.Snap, list)
		if !sameSnaps(info, det.Snap) {
			if err := e.Store.UpdateSnap(g.Key(), info); err != nil {
				e.Log.Warn("rapprochement des snapshots", "invité", g.Key(), "erreur", err)
			} else {
				e.Log.Info("snapshots rapprochés avec Proxmox", "invité", g.Key(), "pw", len(info.PW), "manuels", info.Other)
			}
		}
	}
}

// reconcileSnaps remplace la liste des snapshots par celle de l'API, en
// gardant le reste (possibilité, stockages).
func reconcileSnaps(old detect.SnapInfo, list []proxmox.Snapshot) detect.SnapInfo {
	info := old
	info.PW, info.Other = nil, 0
	for _, s := range list {
		if !ValidSnapName(s.Name) {
			info.Other++
			continue
		}
		sn := detect.Snapshot{Name: s.Name, Description: s.Description}
		if s.SnapTime > 0 {
			sn.Time = time.Unix(s.SnapTime, 0)
		}
		info.PW = append(info.PW, sn)
	}
	sort.Slice(info.PW, func(i, j int) bool { return info.PW[i].Time.Before(info.PW[j].Time) })
	return info
}

func sameSnaps(a, b detect.SnapInfo) bool {
	if a.Other != b.Other || len(a.PW) != len(b.PW) {
		return false
	}
	names := map[string]bool{}
	for _, s := range a.PW {
		names[s.Name] = true
	}
	for _, s := range b.PW {
		if !names[s.Name] {
			return false
		}
	}
	return true
}
