package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LuckyS7evin/patchwarden/internal/inventory"
	"github.com/LuckyS7evin/patchwarden/internal/jobs"
)

func vmGuest() inventory.Guest {
	return inventory.Guest{Node: "loki", Type: "qemu", VMID: 403, Name: "docker", Status: "running"}
}

func (e *env) detectGuest(t *testing.T, g inventory.Guest) jobs.Job {
	t.Helper()
	j, err := e.eng.Detect(g, "admin")
	if err != nil {
		t.Fatal(err)
	}
	return wait(t, e.eng.Jobs, j.ID)
}

func TestVMDetectThroughAgent(t *testing.T) {
	e := setup(t)
	vm := vmGuest()
	done := e.detectGuest(t, vm)
	log := e.logOf(t, done.ID)
	if done.Status != jobs.Success {
		t.Fatalf("détection de la VM : %+v\n%s", done, log)
	}
	if !strings.Contains(log, "▶ vm-detect 403 1") || strings.Contains(log, "lxc-versions") {
		t.Errorf("verbes de la VM :\n%s", log)
	}
	det, _ := e.eng.Store.Get(vm.Key())
	if det.Apt.Total != 2 || !det.Snap.Known || det.Snap.Binds != 1 || len(det.Snap.Storages) != 1 || det.Snap.Storages[0].Name != "local-lvm" {
		t.Errorf("détection : apt %d, snapshots %+v", det.Apt.Total, det.Snap)
	}
	// Accents conservés malgré le double encodage de qm guest exec.
	if !strings.Contains(log, "pw.detect=1") {
		t.Errorf("journal :\n%s", log)
	}
}

func TestVMAgentDown(t *testing.T) {
	e := setup(t)
	t.Setenv("FAKE_AGENT_DOWN", "1")
	done := e.detectGuest(t, vmGuest())
	if done.Status != jobs.Failed || !strings.Contains(done.Error, "agent invité") || !strings.Contains(done.Error, "QEMU Guest Agent") {
		t.Errorf("agent injoignable : %+v", done)
	}
}

func TestVMSecurityUpdateStreamedWithSnapshot(t *testing.T) {
	e := setup(t)
	vm := vmGuest()
	e.detectGuest(t, vm)
	j, err := e.eng.Execute(vm, ActSecurity, false, "admin", true, "", true)
	if err != nil {
		t.Fatal(err)
	}
	done := wait(t, e.eng.Jobs, j.ID)
	log := e.logOf(t, j.ID)
	if done.Status != jobs.Success {
		t.Fatalf("mise à jour de la VM : %+v\n%s", done, log)
	}
	for _, want := range []string{"▶ vm-snapshot 403 pw-", "▶ vm-apt 403 security 0", "PW: dépôts utilisés (sécurité uniquement)", "pw.apt_rc=0", "▶ vm-detect 403 1"} {
		if !strings.Contains(log, want) {
			t.Errorf("journal sans %q :\n%s", want, log)
		}
	}
	if os.Getenv("PW_VOIR") != "" {
		t.Log(log)
	}
	if !strings.Contains(e.pctSets(), "qm snapshot 403 pw-") {
		t.Errorf("snapshot de la VM : %q", e.pctSets())
	}
	if !strings.Contains(log, "disques en passthrough") {
		t.Error("le disque en passthrough doit être signalé")
	}
	left, _ := filepath.Glob(filepath.Join(e.root, "guest", "tmp", "patchwarden-*"))
	if len(left) != 0 {
		t.Errorf("fichiers de travail laissés dans la VM : %v", left)
	}
}

func TestVMRollbackRestartsVM(t *testing.T) {
	e := setup(t)
	vm := vmGuest()
	e.addSnap(t, "pw-20261116-0900-securite 1794830400 avant")
	e.detectGuest(t, vm)
	j, err := e.eng.Rollback(vm, "pw-20261116-0900-securite", "admin", "docker")
	if err != nil {
		t.Fatal(err)
	}
	if done := wait(t, e.eng.Jobs, j.ID); done.Status != jobs.Success {
		t.Fatalf("retour arrière : %+v\n%s", done, e.logOf(t, j.ID))
	}
	if !strings.Contains(e.pctSets(), "qm rollback 403 pw-20261116-0900-securite\nqm start 403") {
		t.Errorf("rollback puis démarrage : %q", e.pctSets())
	}
}

func TestOMVUsesOmvUpgradeAndNeedsName(t *testing.T) {
	e := setup(t)
	t.Setenv("FAKE_SPECIAL", "openmediavault")
	omv := inventory.Guest{Node: "loki", Type: "qemu", VMID: 403, Name: "stockage", Status: "running"}
	e.detectGuest(t, omv)
	det, _ := e.eng.Store.Get(omv.Key())
	if det.Special != "omv" || det.SpecialVersion != "7.4.1-1" {
		t.Fatalf("produit : %q %q", det.Special, det.SpecialVersion)
	}
	p := e.eng.PlanFor(omv, ActFull)
	if !p.OK() || p.AptMode != "omv" || !p.NeedName || !strings.Contains(strings.Join(p.Steps, "\n"), "omv-upgrade") {
		t.Fatalf("plan OMV : %+v", p)
	}
	if _, err := e.eng.Execute(omv, ActFull, false, "admin", true, "autre", false); !errors.Is(err, ErrConfirm) {
		t.Errorf("OMV sans son nom : %v", err)
	}
	j, err := e.eng.Execute(omv, ActFull, false, "admin", true, "stockage", false)
	if err != nil {
		t.Fatal(err)
	}
	done := wait(t, e.eng.Jobs, j.ID)
	log := e.logOf(t, j.ID)
	if done.Status != jobs.Success || !strings.Contains(log, "▶ vm-apt 403 omv 0") || !strings.Contains(log, "omv-upgrade : mise à jour") {
		t.Fatalf("mise à jour OMV : %+v\n%s", done, log)
	}
	// Jamais dans un lot.
	if why := e.eng.PreviewBatch([]BatchRequest{{Guest: omv, Op: OpSecurity}})[0]; !strings.Contains(why, "OpenMediaVault") {
		t.Errorf("lot : %q", why)
	}
}

func TestPBSRefusedWhenPackagesWouldBeRemoved(t *testing.T) {
	e := setup(t)
	t.Setenv("FAKE_SPECIAL", "proxmox-backup-server")
	t.Setenv("FAKE_REMOVE", "1")
	pbs := inventory.Guest{Node: "loki", Type: "qemu", VMID: 403, Name: "sauvegardes", Status: "running"}
	e.detectGuest(t, pbs)
	p := e.eng.PlanFor(pbs, ActFull)
	if p.OK() || !strings.Contains(p.Blockers[0], "supprimerait 1 paquet") || p.AptMode != "dist" {
		t.Errorf("plan PBS : %+v", p)
	}
	// Garde-fou du wrapper : même appelé directement, il refuse.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, _, code, err := e.eng.run(ctx, "loki", "vm-apt 403 dist 1", func(bool, string) {})
	if err != nil || code != 22 || !strings.Contains(strings.Join(out, "\n"), "supprimerait 1 paquet") {
		t.Errorf("wrapper : code %d, %v, %v", code, err, out)
	}
}

func TestProxmoxHostNeverUpdated(t *testing.T) {
	e := setup(t)
	t.Setenv("FAKE_SPECIAL", "pve-manager")
	vm := vmGuest()
	e.detectGuest(t, vm)
	if p := e.eng.PlanFor(vm, ActSecurity); p.OK() || !strings.Contains(p.Blockers[0], "jamais") {
		t.Errorf("hôte Proxmox : %+v", p.Blockers)
	}
	if p := e.eng.PlanRestart(vm); p.Why == "" {
		t.Error("redémarrage d'un hôte Proxmox accepté")
	}
}

func TestWrapperVMVerbs(t *testing.T) {
	e := setup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, cmd := range []string{"vm-cs-update 403 - 0 0", "vm-versions 403 termix", "vm-detect 999 1", "xx-detect 403 1"} {
		if _, _, code, err := e.eng.run(ctx, "loki", cmd, func(bool, string) {}); err != nil || code != exitRefused {
			t.Errorf("%s : code %d, %v (refus attendu)", cmd, code, err)
		}
	}
	_ = os.WriteFile(filepath.Join(e.root, "guest", "vmstopped"), nil, 0o644)
	if _, _, code, _ := e.eng.run(ctx, "loki", "vm-detect 403 0", func(bool, string) {}); code != exitNotRunning {
		t.Errorf("VM arrêtée : code %d", code)
	}
}
