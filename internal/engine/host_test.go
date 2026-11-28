package engine

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/LuckyS7evin/patchwarden/internal/config"
	"github.com/LuckyS7evin/patchwarden/internal/inventory"
	"github.com/LuckyS7evin/patchwarden/internal/jobs"
	"github.com/LuckyS7evin/patchwarden/internal/sshx"
	"github.com/LuckyS7evin/patchwarden/internal/sshx/sshtest"
)

// Faux shell de l'hôte autonome : mêmes substitutions que le faux pct (faux
// système de fichiers), puis exécution du script reçu sur l'entrée standard.
const fakeHostShell = `#!/bin/bash
[ "$1" = "-s" ] && shift
[ "$1" = "--" ] && shift
script="$(sed -e "s#/usr/bin/update#$FAKE_GUEST/usr/bin/update#g" -e "s#/root/\.#$FAKE_GUEST/root/.#g" \
	-e "s#/proc/meminfo#$FAKE_GUEST/proc/meminfo#g" -e "s#PROCDIR=/proc#PROCDIR=$FAKE_GUEST/proc#g")"
printf '%s\n' "$script" | exec bash -s -- "$@"
`

// Faux systemd-run : journalise et simule le redémarrage (nouvel identifiant
// de démarrage).
const fakeSystemdRun = `#!/bin/bash
echo "systemd-run $*" >> "$PCT_SET_LOG"
[ -n "$FAKE_REBOOT_FAIL" ] && exit 1
echo "boot-$(date +%s%N)" > "$FAKE_BOOT_ID"
exit 0
`

func hostGuest() inventory.Guest {
	return inventory.Guest{Node: "vps", Type: inventory.TypeHost, VMID: 0, Name: "vps", Status: "running", Critical: true, CriticalReason: "hôte autonome"}
}

// setupHost ajoute à l'environnement de test un hôte autonome « vps » : même
// wrapper, sans répertoire Proxmox, joint avec le compte patchwarden.
func setupHost(t *testing.T) *env {
	t.Helper()
	e := setup(t)
	bin := filepath.Join(e.root, "bin")
	writeExec(t, filepath.Join(bin, "pw-host-sh"), fakeHostShell)
	writeExec(t, filepath.Join(bin, "systemd-run"), fakeSystemdRun)
	writeExec(t, filepath.Join(bin, "pveversion"), "#!/bin/sh\necho pve-manager/9.0.3/abcdef\n")
	bootID := filepath.Join(e.root, "boot_id")
	_ = os.WriteFile(bootID, []byte("boot-initial\n"), 0o644)
	wrapper, err := filepath.Abs("../../deploy/patchwarden-wrapper")
	if err != nil {
		t.Fatal(err)
	}
	// PATH sans pveversion ni pct, ni qm : une machine hors Proxmox. Les faux
	// outils de l'invité (apt-get, systemctl…) restent disponibles.
	hostBin := filepath.Join(e.root, "hostbin")
	_ = os.MkdirAll(hostBin, 0o755)
	for _, n := range []string{"apt-get", "systemctl", "dpkg-query", "hostname", "logger", "systemd-run", "pw-host-sh", "update"} {
		_ = os.Symlink(filepath.Join(bin, n), filepath.Join(hostBin, n))
	}
	srv := sshtest.Start(t, func(command string, stdout, stderr io.Writer) int {
		cmd := exec.Command("bash", wrapper)
		cmd.Env = append(os.Environ(),
			"SSH_ORIGINAL_COMMAND="+command, "PATCHWARDEN_PVE_DIR="+filepath.Join(e.root, "pas-de-pve"), "FAKE_GUEST="+filepath.Join(e.root, "guest"),
			"PATCHWARDEN_LOG_DIR="+filepath.Join(e.root, "hostlogs"), "PATCHWARDEN_LOCK_DIR="+e.root, "PCT_SET_LOG="+filepath.Join(e.root, "pctset.log"),
			"PATCHWARDEN_HOST_SHELL=pw-host-sh", "PATCHWARDEN_CPU_SAMPLE=0.1", "PATCHWARDEN_BOOT_ID="+bootID, "FAKE_BOOT_ID="+bootID,
			"PATH="+hostBin+":/usr/bin:/bin")
		cmd.Stdout, cmd.Stderr = stdout, stderr
		if err := cmd.Run(); err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				return ee.ExitCode()
			}
			return 255
		}
		return 0
	})
	// Un seul client (clé et clés d'hôte des deux serveurs), comme en vrai.
	srv.Trust(e.server.ClientKey.PublicKey())
	known := []ssh.PublicKey{e.server.HostKey, srv.HostKey}
	cb := func(_ string, _ net.Addr, key ssh.PublicKey) error {
		for _, k := range known {
			if bytes.Equal(k.Marshal(), key.Marshal()) {
				return nil
			}
		}
		return errors.New("clé d'hôte inconnue")
	}
	runner := sshx.NewWith("root", e.server.ClientKey, cb, map[string]string{"loki": e.server.Addr}, 5*time.Second)
	runner.AddHost("vps", srv.Addr, "patchwarden")
	e.eng.Runner, e.eng.HasNode = runner, runner.HasNode
	e.hostSrv = srv
	e.eng.HostPoll, e.eng.HostBack = 20*time.Millisecond, 5*time.Second
	return e
}

func TestHostDetectUpdateNoSnapshot(t *testing.T) {
	e := setupHost(t)
	h := hostGuest()
	done := e.detectGuest(t, h)
	log := e.logOf(t, done.ID)
	if done.Status != jobs.Success {
		t.Fatalf("détection de l'hôte : %+v\n%s", done, log)
	}
	if !strings.Contains(log, "▶ host-detect 0 1 · hôte autonome vps") || strings.Contains(log, "lxc-versions") {
		t.Errorf("verbes de l'hôte :\n%s", log)
	}
	if u := e.hostSrv.Users(); len(u) == 0 || u[0] != "patchwarden" {
		t.Errorf("compte SSH de l'hôte : %v", u)
	}
	det, _ := e.eng.Store.Get(h.Key())
	if det.Apt.Total != 2 || det.Snap.Known {
		t.Errorf("détection : apt %d, snapshots %+v", det.Apt.Total, det.Snap)
	}

	p := e.eng.PlanFor(h, ActSecurity)
	if len(p.Blockers) > 0 || p.Snap.Possible || p.Snap.Checked || !p.NeedName || !strings.Contains(p.Snap.Why, "hôte autonome") {
		t.Fatalf("plan : %+v", p)
	}
	if !strings.Contains(strings.Join(p.Warnings, " "), "aucun retour arrière") {
		t.Errorf("avertissements : %v", p.Warnings)
	}
	if _, err := e.eng.Execute(h, ActSecurity, false, "admin", true, "vps", true); err == nil || !strings.Contains(err.Error(), "snapshot impossible") {
		t.Errorf("snapshot demandé sur un hôte : %v", err)
	}
	if _, err := e.eng.Execute(h, ActSecurity, false, "admin", true, "", false); err == nil {
		t.Error("confirmation renforcée attendue (nom de l'hôte)")
	}
	j, err := e.eng.Execute(h, ActSecurity, false, "admin", true, "vps", false)
	if err != nil {
		t.Fatal(err)
	}
	done = wait(t, e.eng.Jobs, j.ID)
	log = e.logOf(t, j.ID)
	if done.Status != jobs.Success {
		t.Fatalf("mise à jour de l'hôte : %+v\n%s", done, log)
	}
	for _, want := range []string{"▶ host-apt 0 security 0", "pw.apt_rc=0", "▶ host-detect 0 1"} {
		if !strings.Contains(log, want) {
			t.Errorf("journal sans %q :\n%s", want, log)
		}
	}
	if strings.Contains(log, "snapshot") && strings.Contains(log, "host-snapshot") {
		t.Errorf("snapshot sur un hôte :\n%s", log)
	}
	if err := e.eng.CanSnapAction(h); err == nil || !strings.Contains(err.Error(), "hôte autonome") {
		t.Errorf("retour arrière : %v", err)
	}
	if err := e.eng.CanCycle(h); err == nil {
		t.Error("cycle démarrer/arrêter proposé pour un hôte")
	}
}

func TestHostRebootWaitsForNewBoot(t *testing.T) {
	e := setupHost(t)
	h := hostGuest()
	e.detectGuest(t, h)
	if _, err := e.eng.Reboot(h, "admin", true, "autre"); err == nil {
		t.Fatal("nom de l'hôte exigé")
	}
	j, err := e.eng.Reboot(h, "admin", true, "vps")
	if err != nil {
		t.Fatal(err)
	}
	done := wait(t, e.eng.Jobs, j.ID)
	log := e.logOf(t, j.ID)
	if done.Status != jobs.Success {
		t.Fatalf("redémarrage : %+v\n%s", done, log)
	}
	for _, want := range []string{"▶ host-reboot 0", "pw.boot_id=boot-initial", "redémarrage de l'hôte programmé", "nouveau démarrage", "▶ host-detect 0 1"} {
		if !strings.Contains(log, want) {
			t.Errorf("journal sans %q :\n%s", want, log)
		}
	}
	if !strings.Contains(e.pctSets(), "systemd-run --quiet --on-active=5") {
		t.Errorf("systemd-run : %s", e.pctSets())
	}
}

func TestHostNeverComesBack(t *testing.T) {
	e := setupHost(t)
	h := hostGuest()
	e.detectGuest(t, h)
	// systemd-run réussit sans changer l'identifiant de démarrage : l'hôte ne
	// redémarre jamais vraiment.
	writeExec(t, filepath.Join(e.root, "bin", "systemd-run"), "#!/bin/sh\nexit 0\n")
	e.eng.HostBack = 200 * time.Millisecond
	j, err := e.eng.Reboot(h, "admin", true, "vps")
	if err != nil {
		t.Fatal(err)
	}
	done := wait(t, e.eng.Jobs, j.ID)
	if done.Status != jobs.Failed || !strings.Contains(done.Error, "console de l'hébergeur") {
		t.Errorf("hôte jamais revenu : %+v", done)
	}
}

// Le wrapper refuse les verbes d'hôte autonome sur un nœud Proxmox, et les
// verbes sans objet sur un hôte.
func TestHostVerbsRefused(t *testing.T) {
	e := setupHost(t)
	run := func(node, cmd string) (int, string) {
		var b strings.Builder
		code, err := e.eng.Runner.Run(context.Background(), node, cmd, func(l sshx.Line) { b.WriteString(l.Text + "\n") })
		if err != nil {
			t.Fatal(err)
		}
		return code, b.String()
	}
	if code, out := run("loki", "host-detect 0 0"); code != 2 || !strings.Contains(out, "refusé sur un nœud Proxmox") {
		t.Errorf("host-detect sur un nœud : code %d\n%s", code, out)
	}
	for _, cmd := range []string{"host-snapshot 0 pw-20261127-1200-securite 1 90 0 -", "host-rollback 0 pw-20261127-1200-securite", "host-start 0", "host-shutdown 0", "host-cs-update 0 - 0 0"} {
		if code, out := run("vps", cmd); code != 2 || !strings.Contains(out, "indisponible pour un hôte autonome") {
			t.Errorf("%s : code %d\n%s", cmd, code, out)
		}
	}
	if code, out := run("vps", "host-detect 104 0"); code != 2 || !strings.Contains(out, "identifiant 0 attendu") {
		t.Errorf("identifiant : code %d\n%s", code, out)
	}
	if code, out := run("vps", "ping"); code != 0 || !strings.Contains(out, "pw.pve=\n") || !strings.Contains(out, "pw.boot_id=boot-initial") {
		t.Errorf("ping : code %d\n%s", code, out)
	}
	// Côté inventaire : l'hôte répond, il est démarré ; déclaré par erreur sur
	// un nœud Proxmox, il est refusé.
	res, err := inventory.HostSource{Host: hostConf("vps"), Runner: e.eng.Runner}.Guests(context.Background())
	if err != nil || len(res) != 3 || res[0].Status != "running" || res[0].Type != inventory.TypeHost {
		t.Fatalf("source hôte : %+v %v", res, err)
	}
	// Wrapper v15 : état de l'hôte, comme un nœud et son stockage.
	if n, st := res[1], res[2]; n.Type != "node" || n.Node != "vps" || n.MaxMem <= 0 || n.Mem <= 0 || n.CPU < 0 || n.CPU > 1 ||
		st.Type != "storage" || st.Storage != "/" || st.MaxDisk <= 0 || st.Disk <= 0 || st.Disk > st.MaxDisk {
		t.Errorf("statistiques de l'hôte : %+v %+v", n, st)
	}
	if _, err := (inventory.HostSource{Host: hostConf("loki"), Runner: e.eng.Runner}).Guests(context.Background()); err == nil || !strings.Contains(err.Error(), "nœud Proxmox") {
		t.Errorf("nœud déclaré en hôte : %v", err)
	}
}

func hostConf(name string) config.Host { return config.Host{Name: name, User: "patchwarden"} }
