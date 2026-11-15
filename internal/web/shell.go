package web

import (
	"fmt"
	"html/template"
	"net"
	"sort"
	"strings"

	"github.com/LuckyS7evin/patchwarden/internal/detect"
	"github.com/LuckyS7evin/patchwarden/internal/inventory"
)

// navCounts : pastilles du menu.
type navCounts struct {
	Todo      int  // éléments « À traiter »
	TodoCrit  bool // dont des correctifs de sécurité
	Guests    int
	Snapshots int // snapshots PatchWarden
	Running   int // tâches en cours ou en attente
}

// nodeView : un nœud dans le menu.
type nodeView struct {
	Name    string
	Addr    string // adresse SSH, sans le port 22
	Stat    inventory.NodeStat
	HasStat bool
	Storage inventory.StorageStat // stockage des disques des invités
	HasStor bool
}

// storagesInUse : par nœud, les stockages qui portent des disques de LXC
// détectés (lus par le wrapper à chaque détection).
func storagesInUse(all map[string]detect.Result) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	for key, d := range all {
		node, _, ok := strings.Cut(key, "/")
		if !ok {
			continue
		}
		for _, st := range d.Snap.Storages {
			if out[node] == nil {
				out[node] = map[string]bool{}
			}
			out[node][st.Name] = true
		}
	}
	return out
}

// shell : ce que le cadre commun affiche sur chaque page connectée.
type shell struct {
	Nav           navCounts
	Nodes         []nodeView
	Detectable    int
	NextDetection string
}

// shellFor calcule le cadre à partir de l'inventaire, des détections et des tâches.
func (s *Server) shellFor() shell {
	var sh shell
	snap, _ := s.inv.Current()
	sh.Nav.Guests = len(snap.Guests)
	all := s.allDetections()
	t := buildTodo(snap, all, s.now(), s.isSelf)
	sh.Nav.Todo = t.Count
	sh.Nav.TodoCrit = len(t.Groups) > 0 && t.Groups[0].Key == "securite"
	for _, d := range all {
		sh.Nav.Snapshots += len(d.Snap.PW)
	}
	if s.deps.Jobs != nil {
		for _, j := range s.deps.Jobs.List("", 100) {
			if !j.Status.Finished() {
				sh.Nav.Running++
			}
		}
	}
	if s.deps.Engine != nil {
		for _, g := range snap.Guests {
			if s.deps.Engine.CanDetect(g) == nil {
				sh.Detectable++
			}
		}
	}
	inUse := storagesInUse(all)
	for _, n := range snap.Nodes() {
		st, ok := snap.NodeStats[n]
		stor, hasStor := st.PickStorage(inUse[n])
		addr := s.cfg.SSH.Nodes[n]
		if h, p, err := net.SplitHostPort(addr); err == nil && p == "22" {
			addr = h
		}
		sh.Nodes = append(sh.Nodes, nodeView{Name: n, Addr: addr, Stat: st, HasStat: ok && (st.MemTotal > 0 || hasStor), Storage: stor, HasStor: hasStor})
	}
	sort.Slice(sh.Nodes, func(i, j int) bool { return sh.Nodes[i].Name < sh.Nodes[j].Name })
	if s.deps.NextDetection != nil {
		if t := s.deps.NextDetection(); !t.IsZero() {
			sh.NextDetection = t.Local().Format("02/01 à 15:04")
		}
	}
	return sh
}

// level : classe de couleur d'un pourcentage (orange à 80 %, rouge à 90 %).
func level(p int) string {
	switch {
	case p >= 90:
		return "c"
	case p >= 80:
		return "w"
	}
	return ""
}

// barSVG dessine une jauge en SVG : la politique CSP interdit les styles en ligne.
func barSVG(p int) template.HTML {
	p = max(0, min(p, 100))
	return template.HTML(fmt.Sprintf(`<svg class="bar" viewBox="0 0 100 4" preserveAspectRatio="none" aria-hidden="true"><rect class="bg" width="100" height="4"/><rect class="fg %s" width="%d" height="4"/></svg>`, level(p), p)) // #nosec G203 : uniquement des nombres
}

func initials(user string) string {
	r := []rune(strings.TrimSpace(user))
	if len(r) >= 2 {
		return string(r[:2])
	}
	return string(r)
}
