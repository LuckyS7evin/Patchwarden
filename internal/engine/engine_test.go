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
status) if [ "$2" = 108 ] || [ -e "$FAKE_GUEST/stopped" ]; then echo "status: stopped"; else echo "status: running"; fi ;;
snapshot)
	# pct snapshot <vmid> <nom> --description <texte>
	echo "pct snapshot $2 $3" >> "$PCT_SET_LOG"
	[ -n "$FAKE_SNAP_FAIL" ] && { echo "snapshot feature is not available" >&2; exit 1; }
	# Comme Proxmox : arguments décodés selon la locale ; hors UTF-8, chaque
	# octet non ASCII devient « � ».
	case "${LC_ALL:-}" in
	*UTF-8*) d="$5" ;;
	*) d="$(printf '%s' "$5" | perl -CO -pe 's/[\x80-\xff]/\x{FFFD}/g')" ;;
	esac
	echo "$3 $(date +%s) $d" >> "$FAKE_GUEST/snaps"; exit 0 ;;
delsnapshot)
	echo "pct delsnapshot $2 $3" >> "$PCT_SET_LOG"
	grep -v "^$3 " "$FAKE_GUEST/snaps" > "$FAKE_GUEST/snaps.tmp"; mv "$FAKE_GUEST/snaps.tmp" "$FAKE_GUEST/snaps"; exit 0 ;;
rollback) echo "pct rollback $2 $3" >> "$PCT_SET_LOG"; touch "$FAKE_GUEST/stopped"; exit 0 ;;
reboot) echo "pct reboot $2 $3 $4" >> "$PCT_SET_LOG"; [ -n "$FAKE_REBOOT_FAIL" ] && exit 1; rm -rf "$FAKE_GUEST/proc/"[0-9]*; exit 0 ;;
start) echo "pct start $2" >> "$PCT_SET_LOG"; rm -f "$FAKE_GUEST/stopped"; exit 0 ;;
shutdown) echo "pct shutdown $2 $3 $4" >> "$PCT_SET_LOG"; touch "$FAKE_GUEST/stopped"; exit 0 ;;
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
	script="$(cat | sed -e "s#/usr/bin/update#$FAKE_GUEST/usr/bin/update#g" -e "s#/root/\.#$FAKE_GUEST/root/.#g" -e "s#/proc/meminfo#$FAKE_GUEST/proc/meminfo#g" -e "s#PROCDIR=/proc#PROCDIR=$FAKE_GUEST/proc#g")"
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

// Faux pvesh : possibilité de snapshot (FAKE_SNAP_FEATURE) et liste des
// snapshots tenue par le faux pct dans $FAKE_GUEST/snaps (« nom date description »).
const fakePvesh = `#!/bin/bash
case "$2" in
*/feature) if [ "${FAKE_SNAP_FEATURE:-1}" = 1 ]; then echo '{"hasFeature":1,"nodes":["loki"]}'; else echo '{"hasFeature":0}'; fi ;;
*/snapshot) perl -MJSON::PP -e '
	my @a;
	if (open my $f, "<", $ARGV[0]) { while (<$f>) { chomp; my ($n, $t, $d) = split / /, $_, 3; push @a, {name => $n, snaptime => $t + 0, description => $d // ""}; } }
	push @a, {name => "current", running => 1};
	print JSON::PP->new->encode(\@a);' "$FAKE_GUEST/snaps" ;;
*) exit 1 ;;
esac
`

// Faux qm : statut, agent invité (FAKE_AGENT_DOWN), qm guest exec avec la
// sortie encodée deux fois comme le vrai (octets lus en latin-1 puis JSON
// UTF-8), snapshots, retour arrière, redémarrage. Les scripts reçus subissent
// les mêmes substitutions que dans le faux pct (faux système de fichiers).
const fakeQm = `#!/bin/bash
transform() {
	sed -e "s#/usr/bin/update#$FAKE_GUEST/usr/bin/update#g" -e "s#/root/\.#$FAKE_GUEST/root/.#g" \
		-e "s#/proc/meminfo#$FAKE_GUEST/proc/meminfo#g" -e "s#PROCDIR=/proc#PROCDIR=$FAKE_GUEST/proc#g"
}
case "$1" in
status) [ -e "$FAKE_GUEST/vmstopped" ] && echo "status: stopped" || echo "status: running" ;;
agent) [ -n "$FAKE_AGENT_DOWN" ] && { echo "QEMU guest agent is not running" >&2; exit 2; }; exit 0 ;;
guest)
	shift 3 # guest exec <vmid>
	pass=0
	while [ "$1" != "--" ]; do
		case "$1" in --pass-stdin) pass="$2"; shift 2 ;; --timeout) shift 2 ;; *) shift ;; esac
	done
	shift
	in="$(mktemp)" out="$(mktemp)" err="$(mktemp)"
	if [ "$pass" = 1 ]; then cat | transform > "$in"; else : > "$in"; fi
	if [ "$1" = sh ] && [ "$2" = -s ]; then
		shift 2; [ "$1" = "--" ] && shift
		bash -s -- "$@" < "$in" > "$out" 2> "$err"
	else
		"$@" < "$in" > "$out" 2> "$err"
	fi
	rc=$?
	perl -MJSON::PP -e 'local $/; open my $o, "<", $ARGV[0]; my $od = <$o> // ""; open my $e, "<", $ARGV[1]; my $ed = <$e> // "";
		print JSON::PP->new->utf8->canonical->encode({exitcode => $ARGV[2] + 0, exited => 1, "out-data" => $od, "err-data" => $ed});' "$out" "$err" "$rc"
	rm -f "$in" "$out" "$err" ;;
snapshot) echo "qm snapshot $2 $3" >> "$PCT_SET_LOG"; echo "$3 $(date +%s) $5" >> "$FAKE_GUEST/snaps"; exit 0 ;;
delsnapshot) echo "qm delsnapshot $2 $3" >> "$PCT_SET_LOG"; grep -v "^$3 " "$FAKE_GUEST/snaps" > "$FAKE_GUEST/snaps.tmp"; mv "$FAKE_GUEST/snaps.tmp" "$FAKE_GUEST/snaps"; exit 0 ;;
rollback) echo "qm rollback $2 $3" >> "$PCT_SET_LOG"; touch "$FAKE_GUEST/vmstopped"; exit 0 ;;
start) echo "qm start $2" >> "$PCT_SET_LOG"; rm -f "$FAKE_GUEST/vmstopped"; exit 0 ;;
reboot) echo "qm reboot $2 $3 $4" >> "$PCT_SET_LOG"; exit 0 ;;
esac
`

// Faux dpkg-query : FAKE_SPECIAL = paquet installé (openmediavault, pve-manager…).
const fakeDpkgQuery = `#!/bin/bash
p="${@: -1}"
if [ -n "$FAKE_SPECIAL" ] && [ "$p" = "$FAKE_SPECIAL" ]; then echo "install ok installed 7.4.1-1"; exit 0; fi
exit 1
`

// Faux omv-upgrade.
const fakeOmvUpgrade = `#!/bin/bash
echo "omv-upgrade : mise à jour et déploiement de la configuration"
echo "2 upgraded, 0 newly installed, 0 to remove and 0 not upgraded."
`

// Faux systemctl (dans le CT) : « redémarre » un service en supprimant ses
// processus du faux /proc.
const fakeSystemctl = `#!/bin/bash
# list-units --state=failed : services en échec (FAKE_FAILED_UNIT).
if [ "$1" = list-units ]; then [ -n "$FAKE_FAILED_UNIT" ] && echo "$FAKE_FAILED_UNIT loaded failed failed Faux service"; exit 0; fi
[ "$1" = restart ] || exit 0
u="$3"
echo "systemctl restart $u" >> "$PCT_SET_LOG"
[ -n "$FAKE_SYSTEMCTL_FAIL" ] && [ "$u" = "$FAKE_SYSTEMCTL_FAIL" ] && exit 1
for d in "$FAKE_GUEST"/proc/[0-9]*; do
	grep -q "/$u\$" "$d/cgroup" 2>/dev/null && rm -rf "$d"
done
exit 0
`

// Faux pvesm : remplissage du stockage (FAKE_STORAGE_PCT).
const fakePvesm = `#!/bin/bash
echo "Name Type Status Total Used Available %"
echo "$3 lvmthin active 100 45 55 ${FAKE_STORAGE_PCT:-45.00}%"
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
	[[ "$*" == *dist-upgrade* && -n "$FAKE_REMOVE" ]] && echo "Remv vieux-paquet [1.0]"
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
	// hostSrv : serveur de l'hôte autonome (setupHost).
	hostSrv *sshtest.Server
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
	for _, id := range []string{"104", "105", "108"} {
		if err := os.WriteFile(filepath.Join(pve, "nodes", "loki", "lxc", id+".conf"), []byte("cores: 2\nmemory: 2048\nrootfs: local-lvm:vm-"+id+"-disk-0,size=8G\nmp0: /srv/partage,mp=/partage\n"), 0o644); err != nil {
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
	writeExec(t, filepath.Join(bin, "pvesh"), fakePvesh)
	writeExec(t, filepath.Join(bin, "pvesm"), fakePvesm)
	writeExec(t, filepath.Join(bin, "systemctl"), fakeSystemctl)
	writeExec(t, filepath.Join(bin, "qm"), fakeQm)
	writeExec(t, filepath.Join(bin, "dpkg-query"), fakeDpkgQuery)
	writeExec(t, filepath.Join(bin, "omv-upgrade"), fakeOmvUpgrade)
	// VM 403 : un disque sur local-lvm, un CD-ROM, un disque physique en passthrough.
	if err := os.MkdirAll(filepath.Join(pve, "nodes", "loki", "qemu-server"), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(pve, "nodes", "loki", "qemu-server", "403.conf"),
		[]byte("cores: 2\nmemory: 4096\nscsi0: local-lvm:vm-403-disk-0,size=32G\nide2: none,media=cdrom\nscsi1: /dev/disk/by-id/ata-DISQUE,size=4T\n"), 0o644)
	_ = os.MkdirAll(filepath.Join(guest, "tmp"), 0o755)
	// Un snapshot manuel, que PatchWarden ne doit jamais toucher.
	_ = os.WriteFile(filepath.Join(guest, "snaps"), []byte("avant-maj 1700000000 snapshot manuel\n"), 0o644)
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
			"PATCHWARDEN_VM_TMP="+filepath.Join(guest, "tmp"), "PATCHWARDEN_VM_POLL=0.1",
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
	prefs, err := OpenPrefs(data, "snapshots.json")
	if err != nil {
		t.Fatal(err)
	}
	batches, err := OpenBatches(data)
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
		Snap: SnapConfig{Keep: 1, MaxPct: 90}, SnapPrefs: prefs, Batches: batches,
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
	odd := e.guest
	odd.Type = "autre"
	if _, err := e.eng.Detect(odd, "admin"); err != ErrNotLXC {
		t.Errorf("type inconnu : %v", err)
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
