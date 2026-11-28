package inventory

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/LuckyS7evin/patchwarden/internal/config"
	"github.com/LuckyS7evin/patchwarden/internal/proxmox"
	"github.com/LuckyS7evin/patchwarden/internal/sshx"
)

// TypeHost est le type des hôtes autonomes ([[host]]) : machines hors Proxmox
// (VPS…), jointes directement par SSH. Leur identifiant (VMID) vaut 0.
const TypeHost = "host"

// HostSource publie un hôte autonome dans l'inventaire. Chaque rafraîchissement
// interroge le wrapper de l'hôte (verbe ping) : l'hôte apparaît démarré s'il
// répond, en état inconnu sinon (avec l'erreur).
type HostSource struct {
	Host   config.Host
	Runner sshx.Runner
}

// Name identifie la source dans les erreurs d'inventaire.
func (h HostSource) Name() string { return "hôte " + h.Host.Name }

// ErrHostIsPVE : l'hôte déclaré en [[host]] est un nœud Proxmox.
var ErrHostIsPVE = errors.New("c'est un nœud Proxmox : un hôte Proxmox n'est jamais mis à jour par PatchWarden, retirez-le de [[host]]")

// Guests renvoie l'hôte lui-même et, avec le wrapper v15, son état (CPU,
// mémoire, disque /) sous la forme d'un nœud et d'un stockage, comme l'API
// Proxmox pour les nœuds : le menu l'affiche de la même façon.
func (h HostSource) Guests(ctx context.Context) ([]proxmox.Resource, error) {
	r := proxmox.Resource{Type: TypeHost, Node: h.Host.Name, VMID: 0, Name: h.Host.Name, Status: "unknown", Tags: strings.Join(h.Host.Tags, ";")}
	if h.Runner == nil {
		return []proxmox.Resource{r}, errors.New("accès SSH non configuré")
	}
	var out []string
	code, err := h.Runner.Run(ctx, h.Host.Name, "ping", func(l sshx.Line) {
		if !l.Stderr {
			out = append(out, l.Text)
		}
	})
	switch {
	case err != nil:
		return []proxmox.Resource{r}, err
	case code != 0:
		return []proxmox.Resource{r}, fmt.Errorf("wrapper : code %d", code)
	}
	kv := map[string]string{}
	for _, l := range out {
		if k, v, ok := strings.Cut(l, "="); ok {
			kv[k] = strings.TrimSpace(v)
		}
	}
	if kv["pw.pve"] != "" {
		return nil, ErrHostIsPVE
	}
	r.Status = "running"
	res := []proxmox.Resource{r}
	num := func(k string) int64 { n, _ := strconv.ParseInt(kv[k], 10, 64); return n }
	if memTotal := num("pw.mem_total"); memTotal > 0 {
		cpu, _ := strconv.ParseFloat(kv["pw.cpu"], 64)
		res = append(res, proxmox.Resource{Type: "node", Node: h.Host.Name, Status: "online", CPU: cpu, Mem: num("pw.mem_used"), MaxMem: memTotal})
	}
	if diskTotal := num("pw.disk_total"); diskTotal > 0 {
		res = append(res, proxmox.Resource{Type: "storage", Node: h.Host.Name, Storage: "/", PluginType: kv["pw.disk_type"], Status: "available", Content: "rootdir", Disk: num("pw.disk_used"), MaxDisk: diskTotal})
	}
	return res, nil
}
