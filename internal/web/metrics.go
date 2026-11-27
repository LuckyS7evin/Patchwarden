package web

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

// metrics expose l'état du homelab au format texte de Prometheus. Désactivée
// sans jeton ([metrics] token_env) ; le jeton est attendu en
// « Authorization: Bearer … ».
func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	tok := s.cfg.Metrics.Token
	if tok == "" {
		http.NotFound(w, r)
		return
	}
	got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || subtle.ConstantTimeCompare([]byte(got), []byte(tok)) != 1 {
		w.Header().Set("WWW-Authenticate", `Bearer realm="patchwarden"`)
		http.Error(w, "Jeton requis", http.StatusUnauthorized)
		return
	}
	var b strings.Builder
	gauge := func(name, help string) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s gauge\n", name, help, name)
	}
	now := s.now()
	snap, _ := s.inv.Current()
	all := s.allDetections()

	gauge("patchwarden_info", "Version de PatchWarden.")
	fmt.Fprintf(&b, "patchwarden_info{version=%q} 1\n", esc(s.version))
	gauge("patchwarden_inventory_age_seconds", "Âge de la dernière lecture de l'inventaire Proxmox.")
	if !snap.FetchedAt.IsZero() {
		fmt.Fprintf(&b, "patchwarden_inventory_age_seconds %d\n", int(now.Sub(snap.FetchedAt).Seconds()))
	}

	type serie struct{ name, help string }
	series := []serie{
		{"patchwarden_guest_running", "1 si l'invité est démarré."},
		{"patchwarden_detection_age_seconds", "Âge de la dernière détection."},
		{"patchwarden_apt_updates", "Paquets apt à mettre à jour."},
		{"patchwarden_apt_security_updates", "Correctifs de sécurité apt en attente."},
		{"patchwarden_app_updates", "Applications community-scripts avec une version plus récente."},
		{"patchwarden_docker_image_updates", "Conteneurs démarrés avec une nouvelle image pour leur tag."},
		{"patchwarden_reboot_required", "1 si un redémarrage est requis ou conseillé."},
		{"patchwarden_failed_units", "Services systemd en échec."},
		{"patchwarden_os_support", "Support de l'OS : 0 supporté, 1 fin proche ou support étendu, 2 sans correctif."},
		{"patchwarden_snapshots", "Snapshots PatchWarden de l'invité."},
	}
	lines := map[string][]string{}
	guests := append(snap.Guests[:0:0], snap.Guests...)
	sort.Slice(guests, func(i, j int) bool { return guests[i].Key() < guests[j].Key() })
	for _, g := range guests {
		if g.Template || !g.Managed() {
			continue
		}
		l := fmt.Sprintf(`{node=%q,vmid="%d",name=%q,type=%q}`, esc(g.Node), g.VMID, esc(g.Name), esc(g.Type))
		run := 0
		if g.Status == "running" {
			run = 1
		}
		lines["patchwarden_guest_running"] = append(lines["patchwarden_guest_running"], l+" "+strconv.Itoa(run))
		det, ok := all[g.Key()]
		if !ok {
			continue
		}
		add := func(name string, v int) { lines[name] = append(lines[name], l+" "+strconv.Itoa(v)) }
		add("patchwarden_detection_age_seconds", int(now.Sub(det.At).Seconds()))
		add("patchwarden_apt_updates", det.Apt.Total)
		add("patchwarden_apt_security_updates", det.Apt.Security)
		add("patchwarden_app_updates", det.AppUpdates())
		add("patchwarden_docker_image_updates", det.DockerInfo.Updates())
		reboot := 0
		if det.RebootAdvised() {
			reboot = 1
		}
		add("patchwarden_reboot_required", reboot)
		add("patchwarden_failed_units", len(det.FailedUnits))
		add("patchwarden_snapshots", len(det.Snap.PW))
		switch s.osSupport(det).Level {
		case "ok":
			add("patchwarden_os_support", 0)
		case "warn":
			add("patchwarden_os_support", 1)
		case "crit":
			add("patchwarden_os_support", 2)
		}
	}
	for _, se := range series {
		gauge(se.name, se.help)
		for _, l := range lines[se.name] {
			b.WriteString(se.name + l + "\n")
		}
	}

	// Tâches de l'historique, par type et par résultat.
	counts := map[[2]string]int{}
	running := 0
	if s.deps.Jobs != nil {
		for _, j := range s.deps.Jobs.List("", 0) {
			if !j.Status.Finished() {
				running++
				continue
			}
			if j.DryRun {
				continue
			}
			counts[[2]string{string(j.Kind), string(j.Status)}]++
		}
	}
	gauge("patchwarden_jobs_running", "Tâches en cours ou en attente.")
	fmt.Fprintf(&b, "patchwarden_jobs_running %d\n", running)
	gauge("patchwarden_jobs", "Tâches réelles conservées dans l'historique, par type et résultat.")
	keys := make([][2]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i][0]+keys[i][1] < keys[j][0]+keys[j][1] })
	for _, k := range keys {
		fmt.Fprintf(&b, "patchwarden_jobs{kind=%q,status=%q} %d\n", esc(k[0]), esc(k[1]), counts[k])
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(b.String()))
}

// esc prépare une valeur d'étiquette (les guillemets sont ajoutés par %q).
func esc(s string) string { return strings.ToValidUTF8(s, "?") }
