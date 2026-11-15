package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/LuckyS7evin/patchwarden/internal/inventory"
	"github.com/LuckyS7evin/patchwarden/internal/jobs"
)

// stale crée dans le faux /proc du CT un processus lié à une bibliothèque
// remplacée (unit vide : processus hors service systemd).
func (e *env) stale(t *testing.T, pid int, unit, comm string) {
	t.Helper()
	d := filepath.Join(e.root, "guest", "proc", strconv.Itoa(pid))
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	cg := "0::/init.scope"
	if unit != "" {
		cg = "0::/system.slice/" + unit
	}
	_ = os.WriteFile(filepath.Join(d, "maps"), []byte("7f00-7f10 r-xp 00000000 00:2a 123 /usr/lib/x86_64-linux-gnu/libssl.so.3 (deleted)\n"), 0o644)
	_ = os.WriteFile(filepath.Join(d, "cgroup"), []byte(cg+"\n"), 0o644)
	_ = os.WriteFile(filepath.Join(d, "comm"), []byte(comm+"\n"), 0o644)
}

func TestStaleLibrariesDetectedAndServicesRestarted(t *testing.T) {
	e := setup(t)
	e.stale(t, 2001, "nginx.service", "nginx")
	e.stale(t, 2002, "dbus.service", "dbus-daemon")
	e.stale(t, 2003, "", "bash")
	// Un processus sain : jamais signalé.
	_ = os.MkdirAll(filepath.Join(e.root, "guest", "proc", "2004"), 0o755)
	_ = os.WriteFile(filepath.Join(e.root, "guest", "proc", "2004", "maps"), []byte("/usr/lib/libc.so.6\n"), 0o644)
	e.detect(t)
	det, _ := e.eng.Store.Get(e.guest.Key())
	if strings.Join(det.RestartUnits, ",") != "dbus.service,nginx.service" || strings.Join(det.RestartProcs, ",") != "bash" {
		t.Fatalf("détection : unités %v, processus %v", det.RestartUnits, det.RestartProcs)
	}
	p := e.eng.PlanRestart(e.guest)
	if !p.CanServices() || strings.Join(p.Units, ",") != "nginx.service" || strings.Join(p.Excluded, ",") != "dbus.service" || !p.Reboot {
		t.Errorf("plan : %+v", p)
	}

	if _, err := e.eng.RestartServices(e.guest, "admin", false); !errors.Is(err, ErrConfirm) {
		t.Errorf("sans confirmation : %v", err)
	}
	j, err := e.eng.RestartServices(e.guest, "admin", true)
	if err != nil {
		t.Fatal(err)
	}
	done := wait(t, e.eng.Jobs, j.ID)
	log := e.logOf(t, j.ID)
	if done.Status != jobs.Success || !strings.HasPrefix(done.Summary, "1 service redémarré") {
		t.Fatalf("redémarrage : %+v\n%s", done, log)
	}
	sets := e.pctSets()
	if !strings.Contains(sets, "systemctl restart nginx.service") || strings.Contains(sets, "dbus") {
		t.Errorf("services redémarrés : %q", sets)
	}
	for _, want := range []string{"PW: nginx.service redémarré", "dbus.service non redémarré (service système", "▶ lxc-detect 104"} {
		if !strings.Contains(log, want) {
			t.Errorf("journal sans %q :\n%s", want, log)
		}
	}
	det, _ = e.eng.Store.Get(e.guest.Key())
	if strings.Join(det.RestartUnits, ",") != "dbus.service" {
		t.Errorf("après : %v", det.RestartUnits)
	}
}

func TestServiceRestartFailure(t *testing.T) {
	e := setup(t)
	e.stale(t, 2001, "nginx.service", "nginx")
	e.detect(t)
	t.Setenv("FAKE_SYSTEMCTL_FAIL", "nginx.service")
	j, _ := e.eng.RestartServices(e.guest, "admin", true)
	done := wait(t, e.eng.Jobs, j.ID)
	if done.Status != jobs.Failed || !strings.Contains(done.Error, "code 50") || !strings.Contains(done.Error, "nginx.service") {
		t.Errorf("échec attendu et expliqué : %+v", done)
	}
}

func TestReboot(t *testing.T) {
	e := setup(t)
	e.stale(t, 2003, "", "bash")
	e.detect(t)
	if _, err := e.eng.Reboot(e.guest, "admin", false, ""); !errors.Is(err, ErrConfirm) {
		t.Errorf("sans confirmation : %v", err)
	}
	crit := e.guest
	crit.Critical, crit.CriticalReason = true, "tag critique"
	if _, err := e.eng.Reboot(crit, "admin", true, "autre"); !errors.Is(err, ErrConfirm) {
		t.Errorf("invité critique sans son nom : %v", err)
	}
	self := e.guest
	self.VMID = 103
	if _, err := e.eng.Reboot(self, "admin", true, self.Name); err == nil {
		t.Error("redémarrage de l'invité de PatchWarden accepté")
	}
	j, err := e.eng.Reboot(e.guest, "admin", true, "")
	if err != nil {
		t.Fatal(err)
	}
	done := wait(t, e.eng.Jobs, j.ID)
	if done.Status != jobs.Success || !strings.Contains(e.pctSets(), "pct reboot 104 --timeout 120") {
		t.Fatalf("redémarrage : %+v\n%s", done, e.logOf(t, j.ID))
	}
	det, _ := e.eng.Store.Get(e.guest.Key())
	if len(det.RestartProcs) != 0 {
		t.Errorf("après redémarrage : %v", det.RestartProcs)
	}
}

func waitBatch(t *testing.T, e *Engine, id string) Batch {
	t.Helper()
	for i := 0; i < 600; i++ {
		if b, _ := e.Batches.Get(id); !b.Running() {
			return b
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("lot non terminé")
	return Batch{}
}

func TestBatchStopsOnFailure(t *testing.T) {
	e := setup(t)
	adg := inventory.Guest{Node: "loki", Type: "lxc", VMID: 105, Name: "adguard", Status: "running"}
	e.detect(t)
	if j, err := e.eng.Detect(adg, "admin"); err != nil || wait(t, e.eng.Jobs, j.ID).Status != jobs.Success {
		t.Fatalf("détection de 105 : %v", err)
	}
	_ = e.eng.Answers.Set(e.guest.Key(), map[string]string{nginxPrompt: "y"})
	crit := inventory.Guest{Node: "loki", Type: "qemu", VMID: 403, Name: "OMV", Status: "running", Critical: true, CriticalReason: "nom contenant « omv »"}
	t.Setenv("FAKE_UPDATE_RC", "114")
	b, err := e.eng.StartBatch([]BatchRequest{
		{Guest: e.guest, Op: OpFull, Snapshot: true},
		{Guest: adg, Op: OpSecurity},
		{Guest: crit, Op: OpSecurity},
		{Guest: e.guest, Op: OpSecurity},
	}, false, true, "admin")
	if err != nil {
		t.Fatal(err)
	}
	b = waitBatch(t, e.eng, b.ID)
	st := func(i int) string { return b.Items[i].Status }
	if st(0) != ItemFailed || st(1) != ItemCancelled || st(2) != ItemSkipped || st(3) != ItemSkipped || b.Status != BatchStopped {
		t.Fatalf("lot : %+v", b)
	}
	if !strings.Contains(b.Items[2].Error, "confirmation renforcée") || !strings.Contains(b.Items[3].Error, "déjà présent dans ce lot pour ce type") {
		t.Errorf("raisons : %+v", b.Items)
	}
	if !strings.Contains(e.pctSets(), "pct snapshot 104 pw-") {
		t.Error("le snapshot demandé n'a pas été pris")
	}
	if !e.eng.Batches.FromBatch(b.Items[0].JobID) {
		t.Error("la tâche du lot doit être marquée (notification unique)")
	}
	if list := e.eng.Jobs.List(adg.Key(), 10); len(list) != 1 || list[0].Kind != jobs.KindDetect {
		t.Errorf("rien ne doit avoir été lancé sur 105 : %+v", list)
	}

	// Rechargement : un lot interrompu est marqué comme tel.
	again, err := OpenBatches(filepath.Dir(e.eng.Batches.dir))
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := again.Get(b.ID); !ok || got.Status != BatchStopped || len(got.Items) != 4 {
		t.Errorf("lot relu : %+v", got)
	}
}

func TestBatchDryRunRunsEverything(t *testing.T) {
	e := setup(t)
	e.detect(t)
	_ = e.eng.Answers.Set(e.guest.Key(), map[string]string{nginxPrompt: "y"})
	adg := inventory.Guest{Node: "loki", Type: "lxc", VMID: 105, Name: "adguard", Status: "running"}
	if j, _ := e.eng.Detect(adg, "admin"); wait(t, e.eng.Jobs, j.ID).Status != jobs.Success {
		t.Fatal("détection de 105")
	}
	b, err := e.eng.StartBatch([]BatchRequest{{Guest: e.guest, Op: OpFull}, {Guest: adg, Op: OpSecurity}}, true, true, "admin")
	if err != nil {
		t.Fatal(err)
	}
	b = waitBatch(t, e.eng, b.ID)
	if b.Status != BatchDone || b.Count(ItemSuccess) != 2 {
		t.Fatalf("simulation : %+v", b)
	}
	for _, it := range b.Items {
		if j, _ := e.eng.Jobs.Get(it.JobID); !j.DryRun {
			t.Errorf("tâche réelle dans un lot simulé : %+v", j)
		}
	}
	if _, err := e.eng.StartBatch([]BatchRequest{{Guest: e.guest, Op: OpReboot}}, true, true, "admin"); !errors.Is(err, ErrEmptyBatch) {
		t.Errorf("redémarrage simulé : %v", err)
	}
}

func TestWrapperRestartVerbs(t *testing.T) {
	e := setup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, cmd := range []string{"lxc-restart-services 104 nginx.service", "lxc-reboot", "lxc-reboot 104 maintenant"} {
		_, _, code, err := e.eng.run(ctx, "loki", cmd, func(bool, string) {})
		if err != nil || code != exitRefused {
			t.Errorf("%s : code %d, %v (refus attendu)", cmd, code, err)
		}
	}
	if _, _, code, _ := e.eng.run(ctx, "loki", "lxc-reboot 108", func(bool, string) {}); code != exitNotRunning {
		t.Errorf("CT arrêté : code %d", code)
	}
}
