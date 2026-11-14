package web

import (
	"net/http"
	"sort"
	"time"

	"github.com/LuckyS7evin/patchwarden/internal/detect"
	"github.com/LuckyS7evin/patchwarden/internal/inventory"
)

// StaleDetection : au-delà, une détection est signalée comme trop ancienne.
const StaleDetection = 48 * time.Hour

type secRow struct {
	Guest    inventory.Guest
	Det      detect.Result
	Packages []detect.Package // correctifs de sécurité, plus anciens d'abord
	Oldest   time.Time
	Old      bool // détection trop ancienne
}

type securityData struct {
	base
	Rows            []secRow
	Total, Guests   int
	Oldest          time.Time
	Missing         []inventory.Guest // LXC démarrés sans détection récente
	VMs             int
	StaleAfter      string
	LoadedInventory bool
}

// securityPage liste les correctifs de sécurité en attente, invité par invité,
// les plus anciens d'abord.
func (s *Server) securityPage(w http.ResponseWriter, r *http.Request, se *session) {
	snap, _ := s.inv.Current()
	all := s.deps.Detections.All()
	d := securityData{base: s.base("Sécurité", "securite", se), StaleAfter: "48 h", LoadedInventory: !snap.FetchedAt.IsZero()}
	now := s.now()
	for _, g := range snap.Guests {
		if g.Template {
			continue
		}
		if g.Type != "lxc" {
			d.VMs++
			continue
		}
		det, ok := all[g.Key()]
		old := ok && now.Sub(det.At) > StaleDetection
		if g.Status == "running" && (!ok || old) {
			d.Missing = append(d.Missing, g)
		}
		if !ok || det.Apt.Security == 0 {
			continue
		}
		row := secRow{Guest: g, Det: det, Oldest: det.OldestSecurity(), Old: old}
		for _, p := range det.Apt.Packages {
			if p.Security {
				row.Packages = append(row.Packages, p)
			}
		}
		sort.SliceStable(row.Packages, func(i, j int) bool { return row.Packages[i].Since.Before(row.Packages[j].Since) })
		d.Rows = append(d.Rows, row)
		d.Total += det.Apt.Security
		d.Guests++
		if !row.Oldest.IsZero() && (d.Oldest.IsZero() || row.Oldest.Before(d.Oldest)) {
			d.Oldest = row.Oldest
		}
	}
	sort.SliceStable(d.Rows, func(i, j int) bool {
		a, b := d.Rows[i].Oldest, d.Rows[j].Oldest
		if a.Equal(b) {
			return d.Rows[i].Det.Apt.Security > d.Rows[j].Det.Apt.Security
		}
		return a.Before(b)
	})
	s.render(w, "securite", http.StatusOK, d)
}
