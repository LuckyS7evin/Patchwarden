package engine

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/LuckyS7evin/patchwarden/internal/cs"
	"github.com/LuckyS7evin/patchwarden/internal/detect"
	"github.com/LuckyS7evin/patchwarden/internal/inventory"
	"github.com/LuckyS7evin/patchwarden/internal/jobs"
	"github.com/LuckyS7evin/patchwarden/internal/sshx"
	"github.com/LuckyS7evin/patchwarden/internal/sshx/sshtest"
	"github.com/LuckyS7evin/patchwarden/internal/upstream"
)

// Faux pct : « exec » exécute le script reçu sur l'entrée standard comme s'il
// tournait dans le CT, en redirigeant /usr/bin/update et /root/. vers un faux
// système de fichiers d'invité.
const fakePct = `#!/bin/bash
case "$1" in
status) [ "$2" = 108 ] && echo "status: stopped" || echo "status: running" ;;
set)
	shift 2; echo "pct set $*" >> "$PCT_SET_LOG"
	# Comme Proxmox : la mémoire est vue tout de suite par le CT, les CPU
	# seulement au passage suivant de pvestatd (FAKE_CPU_LAG lectures plus tard,
	# « jamais » : pvestatd arrêté).
	while [ $# -gt 0 ]; do
		case "$1" in
		--memory) echo "MemTotal: $(($2 * 1024)) kB" > "$FAKE_GUEST/proc/meminfo"; shift 2 ;;
		--cores) echo "$2" > "$FAKE_GUEST/cores.pending"; echo "${FAKE_CPU_LAG:-0}" > "$FAKE_GUEST/cores.lag"; shift 2 ;;
		*) shift ;;
		esac
	done
	exit 0 ;;
exec)
	shift 2; [ "$1" = "--" ] && shift
	script="$(cat | sed -e "s#/usr/bin/update#$FAKE_GUEST/usr/bin/update#g" -e "s#/root/\.#$FAKE_GUEST/root/.#g" -e "s#/proc/meminfo#$FAKE_GUEST/proc/meminfo#g")"
	# nproc vu depuis le CT : applique les CPU en attente quand le délai est écoulé.
	script="nproc() {
		if [ -f \"\$FAKE_GUEST/cores.pending\" ]; then
			l=\$(cat \"\$FAKE_GUEST/cores.lag\")
			if [ \"\$l\" = jamais ]; then :
			elif [ \"\$l\" -le 0 ]; then mv \"\$FAKE_GUEST/cores.pending\" \"\$FAKE_GUEST/cores\"
			else echo \$((l - 1)) > \"\$FAKE_GUEST/cores.lag\"; fi
		fi
		cat \"\$FAKE_GUEST/cores\"
	}
$script"
	shift 2  # « sh -s »
	[ "$1" = "--" ] && shift
	# Comme le vrai pct : le script arrive sur l'entrée standard du shell.
	# bash lit un tuyau ligne par ligne (dash par blocs) : une commande qui lit
	# l'entrée standard sans redirection consommerait la suite du script.
	printf '%s\n' "$script" | exec bash -s -- "$@" ;;
esac
`

const fakeApt = `#!/bin/bash
# Comme dpkg ou apt-listchanges qui posent une question : lit l'entrée standard.
# Si le wrapper ne la redirige pas, la suite du script serait consommée.
cat >/dev/null
echo "[apt-get $*]"
case "$1" in update) exit 0 ;; esac
case "$*" in *autoclean*) exit 0 ;; esac
if [[ "$*" == *SourceList* ]]; then
	echo "Inst libssl3t64 [3.5.7-1~deb13u2] (3.5.7-1~deb13u3 Debian-Security:13/stable-security [amd64])"
	echo "1 upgraded, 0 newly installed, 0 to remove and 1 not upgraded."
elif [[ "$*" == *dist-upgrade* || "$*" == *--with-new-pkgs* ]]; then
	echo "Inst base-files [13.8+deb13u6] (13.8+deb13u7 Debian:13.7/stable [amd64])"
	echo "Inst libssl3t64 [3.5.7-1~deb13u2] (3.5.7-1~deb13u3 Debian-Security:13/stable-security [amd64])"
	echo "2 upgraded, 0 newly installed, 0 to remove and 0 not upgraded."
else
	echo "Inst base-files [13.8+deb13u6] (13.8+deb13u7 Debian:13.7/stable [amd64])"
fi
`

// Faux « update » community-scripts : écrit son journal détaillé comme le
// moteur (/tmp/create-lxc-*.log), lit une réponse, sort avec FAKE_UPDATE_RC.
const fakeUpdate = `#!/bin/sh
echo "BANNIERE"
# Comme le vrai script : refuse si le CT voit moins que les 4 CPU exigés.
if [ "$(cat "$FAKE_GUEST/cores")" -lt 4 ]; then
	echo "Not continuing: LXC is under-provisioned and there is nobody to ask."
	exit 113
fi
L=/tmp/create-lxc-pwtest-$$.log
echo "[INFO] Updating Termix" > "$L"
read -r REP
echo "[INFO] réponse reçue : '$REP'" >> "$L"
echo "[OK] Updated successfully!" >> "$L"
exit ${FAKE_UPDATE_RC:-0}
`

func writeExec(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
}

type env struct {
	eng    *Engine
	server *sshtest.Server
	guest  inventory.Guest
	base   string // base des scripts servie par le faux site
	web    *httptest.Server
	root   string
}

func setup(t *testing.T) *env {
	t.Helper()
	root := t.TempDir()
	bin, pve, guest := filepath.Join(root, "bin"), filepath.Join(root, "pve"), filepath.Join(root, "guest")
	for _, d := range []string{bin, filepath.Join(pve, "nodes", "loki", "lxc"), filepath.Join(guest, "usr", "bin"), filepath.Join(guest, "root")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{"104", "108"} {
		if err := os.WriteFile(filepath.Join(pve, "nodes", "loki", "lxc", id+".conf"), []byte("cores: 2\nmemory: 2048\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Ressources vues depuis le faux CT : 2 CPU, 2048 Mo.
	if err := os.MkdirAll(filepath.Join(guest, "proc"), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(guest, "cores"), []byte("2\n"), 0o644)
	_ = os.WriteFile(filepath.Join(guest, "proc", "meminfo"), []byte("MemTotal: 2097152 kB\n"), 0o644)
	writeExec(t, filepath.Join(bin, "update"), fakeUpdate)
	writeExec(t, filepath.Join(bin, "pct"), fakePct)
	writeExec(t, filepath.Join(bin, "apt-get"), fakeApt)
	writeExec(t, filepath.Join(bin, "hostname"), "#!/bin/sh\necho loki\n")
	writeExec(t, filepath.Join(bin, "logger"), "#!/bin/sh\nexit 0\n")

	// Faux site des scripts et fausse API GitHub.
	termix, err := os.ReadFile("../cs/testdata/termix.sh")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/ProxmoxVE/main/ct/termix.sh", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(termix) })
	mux.HandleFunc("/gh/repos/Termix-SSH/Termix/releases/latest", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"tag_name":"v26.11.1","html_url":"https://github.com/Termix-SSH/Termix/releases/tag/v26.11.1"}`))
	})
	mux.HandleFunc("/gh/repos/apache/guacamole-server/tags", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[{"name":"1.6.0"},{"name":"1.6.1"}]`))
	})
	web := httptest.NewTLSServer(mux)
	t.Cleanup(web.Close)
	base := web.URL + "/ProxmoxVE/main"

	// Faux CT 104 : entrée update au nouveau format, fichiers de version.
	if err := os.WriteFile(filepath.Join(guest, "usr", "bin", "update"), []byte("#!/usr/bin/env bash\nexport SCRIPT_SLUG=\"termix\"\nexport UPDATE_SCRIPT_NAME=\"termix\"\nexport COMMUNITY_SCRIPTS_URL=\""+base+"\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(guest, "root", ".termix"), []byte("release-2.6.1-tag\n"), 0o644)
	_ = os.WriteFile(filepath.Join(guest, "root", ".guacd"), []byte("1.6.0\n"), 0o644)

	wrapper, err := filepath.Abs("../../deploy/patchwarden-wrapper")
	if err != nil {
		t.Fatal(err)
	}
	srv := sshtest.Start(t, func(command string, stdout, stderr io.Writer) int {
		cmd := exec.Command("bash", wrapper)
		cmd.Env = append(os.Environ(),
			"SSH_ORIGINAL_COMMAND="+command, "PATCHWARDEN_PVE_DIR="+pve, "FAKE_GUEST="+guest,
			"PATCHWARDEN_LOG_DIR="+filepath.Join(root, "nodelogs"), "PATCHWARDEN_LOCK_DIR="+root, "PCT_SET_LOG="+filepath.Join(root, "pctset.log"),
			"PATCHWARDEN_RES_WAIT=2", "PATCHWARDEN_RES_POLL=0.1",
			"PATH="+bin+":"+os.Getenv("PATH"))
		cmd.Stdout, cmd.Stderr = stdout, stderr
		if err := cmd.Run(); err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				return ee.ExitCode()
			}
			return 255
		}
		return 0
	})

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	data := t.TempDir()
	jm, err := jobs.New(data, 2, 100, log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(jm.Close)
	store, _ := detect.OpenStore(data)
	answers, err := OpenAnswers(data)
	if err != nil {
		t.Fatal(err)
	}
	up := upstream.New("", time.Hour, web.Client())
	up.GitHubAPI = web.URL + "/gh"
	nodes := map[string]string{"loki": srv.Addr}
	runner := sshx.NewWith("root", srv.ClientKey, ssh.FixedHostKey(srv.HostKey), nodes, 5*time.Second)
	eng := &Engine{
		Runner: runner, HasNode: runner.HasNode, Jobs: jm, Store: store,
		Scripts: cs.NewFetcher([]string{base}, time.Hour, web.Client()), Upstream: up,
		Website: "https://community-scripts.org", AptRefresh: true, Timeout: time.Minute, Log: log,
		Answers: answers, SelfGuest: "loki/103",
	}
	return &env{eng: eng, server: srv, base: base, web: web, root: root, guest: inventory.Guest{Node: "loki", Type: "lxc", VMID: 104, Name: "termix", Status: "running", CommunityScript: true}}
}

func wait(t *testing.T, m *jobs.Manager, id string) jobs.Job {
	t.Helper()
	for i := 0; i < 500; i++ {
		if j, _ := m.Get(id); j.Status.Finished() {
			return j
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("tâche non terminée")
	return jobs.Job{}
}

func TestDetectEndToEnd(t *testing.T) {
	e := setup(t)
	j, err := e.eng.Detect(e.guest, "admin")
	if err != nil {
		t.Fatal(err)
	}
	done := wait(t, e.eng.Jobs, j.ID)
	lines, _ := e.eng.Jobs.Log(j.ID)
	var buf bytes.Buffer
	for _, l := range lines {
		buf.WriteString(l.Text + "\n")
	}
	if done.Status != jobs.Success {
		t.Fatalf("détection échouée : %+v\n%s", done, buf.String())
	}
	r, ok := e.eng.Store.Get("loki/104")
	if !ok {
		t.Fatal("résultat non enregistré")
	}
	if r.Apt.Total != 2 || r.Apt.Security != 1 || r.Apt.SecurityStrict != 1 {
		t.Errorf("apt : %+v", r.Apt)
	}
	c := r.CS
	if c.Entry != "helper" || c.Script != "termix" || !c.BaseAllowed || c.NeedCPU != 4 || len(c.Prompts) != 1 || c.PageURL != "https://community-scripts.org/scripts/termix" {
		t.Errorf("community-scripts : %+v", c)
	}
	if len(r.Apps) != 2 {
		t.Fatalf("applis : %+v\n%s", r.Apps, buf.String())
	}
	g, x := r.Apps[0], r.Apps[1]
	if g.Installed != "1.6.0" || g.Latest != "1.6.1" || !g.UpdateAvailable() {
		t.Errorf("guacd : %+v", g)
	}
	if x.Installed != "release-2.6.1-tag" || x.Latest != "v26.11.1" || x.ChangelogURL == "" || !x.UpdateAvailable() {
		t.Errorf("termix : %+v", x)
	}
	if !strings.Contains(done.Summary, "1 de sécurité") || !strings.Contains(done.Summary, "termix release-2.6.1-tag → v26.11.1") {
		t.Errorf("résumé : %q", done.Summary)
	}
	for _, want := range []string{"▶ lxc-detect 104 1", "▶ lxc-versions 104 guacd termix", "Update Nginx configuration?"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("journal sans %q :\n%s", want, buf.String())
		}
	}
	if got := e.server.Seen(); len(got) != 2 || got[0] != "lxc-detect 104 1" {
		t.Errorf("commandes envoyées au nœud : %q", got)
	}
}

func TestRefusals(t *testing.T) {
	e := setup(t)
	stopped := e.guest
	stopped.Status = "stopped"
	if _, err := e.eng.Detect(stopped, "admin"); err != ErrStopped {
		t.Errorf("invité arrêté : %v", err)
	}
	vm := e.guest
	vm.Type = "qemu"
	if _, err := e.eng.Detect(vm, "admin"); err != ErrNotLXC {
		t.Errorf("VM : %v", err)
	}
	other := e.guest
	other.Node = "tyr"
	if _, err := e.eng.Detect(other, "admin"); err == nil || !strings.Contains(err.Error(), "[ssh.nodes]") {
		t.Errorf("nœud sans SSH : %v", err)
	}
	ro := *e.eng
	ro.Runner = nil
	if _, err := ro.Detect(e.guest, "admin"); err != ErrNoSSH {
		t.Errorf("lecture seule : %v", err)
	}
	if len(e.server.Seen()) != 0 {
		t.Error("aucune commande ne doit partir pour un refus local")
	}

	// Le wrapper refuse un CT absent du nœud : la tâche échoue avec son message.
	ghost := e.guest
	ghost.VMID = 999
	j, err := e.eng.Detect(ghost, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if done := wait(t, e.eng.Jobs, j.ID); done.Status != jobs.Failed || !strings.Contains(done.Error, "CT 999 absent du nœud loki") {
		t.Errorf("refus du wrapper : %+v", done)
	}
}
