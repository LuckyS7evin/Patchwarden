package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LuckyS7evin/patchwarden/internal/jobs"
)

func (e *env) snaps(t *testing.T) string {
	t.Helper()
	b, _ := os.ReadFile(filepath.Join(e.root, "guest", "snaps"))
	return string(b)
}

func (e *env) addSnap(t *testing.T, line string) {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(e.root, "guest", "snaps"), os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(line + "\n"); err != nil {
		t.Fatal(err)
	}
}

func TestSnapshotInfoInDetection(t *testing.T) {
	e := setup(t)
	e.addSnap(t, "pw-20250101-0000-complet 1735689600 ancien snapshot PatchWarden")
	e.detect(t)
	det, _ := e.eng.Store.Get(e.guest.Key())
	s := det.Snap
	if !s.Known || !s.Possible || s.Other != 1 || s.Binds != 1 || len(s.PW) != 1 || s.PW[0].Name != "pw-20250101-0000-complet" {
		t.Fatalf("infos de snapshot : %+v", s)
	}
	if len(s.Storages) != 1 || s.Storages[0].Name != "local-lvm" || s.Storages[0].UsedPct != 45 {
		t.Errorf("stockages : %+v", s.Storages)
	}
	p := e.eng.PlanFor(e.guest, ActFull)
	// Termix release-2.6.1-tag → v26.11.1 : version majeure, case pré-cochée.
	if !p.Snap.Possible || !p.Snap.Checked || p.Snap.Reason != "changement de version majeure" {
		t.Errorf("plan du snapshot : %+v", p.Snap)
	}
	if len(p.Snap.Removed) != 1 || p.Snap.Removed[0] != "pw-20250101-0000-complet" {
		t.Errorf("rétention annoncée : %v", p.Snap.Removed)
	}
	if ps := e.eng.PlanFor(e.guest, ActSecurity); ps.Snap.Checked {
		t.Errorf("sécurité uniquement, sans version majeure : case cochée (%s)", ps.Snap.Reason)
	}
}

func TestSnapshotPrecheckRules(t *testing.T) {
	e := setup(t)
	e.detect(t)
	key := e.guest.Key()
	_ = e.eng.SetSnapPref(key, PrefNever)
	if p := e.eng.PlanFor(e.guest, ActFull); p.Snap.Checked {
		t.Errorf("réglage « jamais » : case cochée")
	}
	_ = e.eng.SetSnapPref(key, PrefAlways)
	if p := e.eng.PlanFor(e.guest, ActSecurity); !p.Snap.Checked {
		t.Errorf("réglage « toujours » : case décochée")
	}
	_ = e.eng.SetSnapPref(key, PrefAuto)
	crit := e.guest
	crit.Critical, crit.CriticalReason = true, "tag critique"
	if p := e.eng.PlanFor(crit, ActSecurity); !p.Snap.Checked || !strings.Contains(p.Snap.Reason, "critique") {
		t.Errorf("invité critique : %+v", p.Snap)
	}
	e.eng.Snap.Default = true
	if p := e.eng.PlanFor(e.guest, ActSecurity); !p.Snap.Checked {
		t.Errorf("réglage global : case décochée")
	}
	if err := e.eng.SetSnapPref(key, "parfois"); err == nil {
		t.Error("réglage inconnu accepté")
	}
}

func TestSnapshotThenUpdate(t *testing.T) {
	e := setup(t)
	e.addSnap(t, "pw-20250101-0000-complet 1735689600 ancien")
	e.detect(t)
	_ = e.eng.Answers.Set(e.guest.Key(), map[string]string{nginxPrompt: "y"})
	j, err := e.eng.Execute(e.guest, ActFull, false, "admin", true, "", true)
	if err != nil {
		t.Fatal(err)
	}
	done := wait(t, e.eng.Jobs, j.ID)
	log := e.logOf(t, j.ID)
	if done.Status != jobs.Success {
		t.Fatalf("mise à jour : %+v\n%s", done, log)
	}
	snapAt, aptAt := strings.Index(log, "▶ lxc-snapshot 104 pw-"), strings.Index(log, "▶ lxc-apt 104")
	if snapAt < 0 || aptAt < 0 || snapAt > aptAt {
		t.Errorf("le snapshot doit précéder apt :\n%s", log)
	}
	sets := e.pctSets()
	if !strings.Contains(sets, "pct snapshot 104 pw-") || !strings.Contains(sets, "pct delsnapshot 104 pw-20250101-0000-complet") {
		t.Errorf("snapshot ou rétention manquants : %q", sets)
	}
	if strings.Contains(sets, "avant-maj") || !strings.Contains(e.snaps(t), "avant-maj") {
		t.Errorf("snapshot manuel touché : %q", sets)
	}
	if !strings.Contains(e.snaps(t), "PatchWarden avant « tout mettre à jour »") {
		t.Errorf("description absente ou mal décodée : %q", e.snaps(t))
	}
	if !strings.Contains(log, "points de montage liés") {
		t.Errorf("avertissement bind mount absent :\n%s", log)
	}
	det, _ := e.eng.Store.Get(e.guest.Key())
	if len(det.Snap.PW) != 1 || !strings.HasSuffix(det.Snap.PW[0].Name, "-complet") || det.Snap.PW[0].Name == "pw-20250101-0000-complet" {
		t.Errorf("snapshots enregistrés : %+v", det.Snap.PW)
	}
	if !strings.Contains(done.Summary, "snapshot pw-") {
		t.Errorf("résumé : %q", done.Summary)
	}
}

func TestSnapshotRefusedCancelsUpdate(t *testing.T) {
	e := setup(t)
	e.detect(t)
	_ = e.eng.Answers.Set(e.guest.Key(), map[string]string{nginxPrompt: "y"})
	t.Setenv("FAKE_STORAGE_PCT", "95.20")
	j, err := e.eng.Execute(e.guest, ActFull, false, "admin", true, "", true)
	if err != nil {
		t.Fatal(err)
	}
	done := wait(t, e.eng.Jobs, j.ID)
	log := e.logOf(t, j.ID)
	if done.Status != jobs.Failed || !strings.Contains(done.Error, "mise à jour annulée") || !strings.Contains(done.Error, "95.20 %") {
		t.Errorf("échec attendu et expliqué : %+v", done)
	}
	if strings.Contains(log, "▶ lxc-apt") || strings.Contains(e.pctSets(), "pct snapshot") {
		t.Errorf("rien ne doit être fait après un snapshot refusé :\n%s", log)
	}

	// Détection avec le stockage plein : la case est désactivée.
	e.detect(t)
	p := e.eng.PlanFor(e.guest, ActFull)
	if p.Snap.Possible || !strings.Contains(p.Snap.Why, "seuil : 90 %") {
		t.Errorf("plan : %+v", p.Snap)
	}
	if _, err := e.eng.Execute(e.guest, ActFull, false, "admin", true, "", true); err == nil {
		t.Error("snapshot impossible accepté")
	}
}

func TestSnapshotFailureCancelsUpdate(t *testing.T) {
	e := setup(t)
	e.detect(t)
	_ = e.eng.Answers.Set(e.guest.Key(), map[string]string{nginxPrompt: "y"})
	t.Setenv("FAKE_SNAP_FAIL", "1")
	j, _ := e.eng.Execute(e.guest, ActSecurity, false, "admin", true, "", true)
	done := wait(t, e.eng.Jobs, j.ID)
	if done.Status != jobs.Failed || !strings.Contains(done.Error, "code 43") || strings.Contains(e.logOf(t, j.ID), "▶ lxc-apt") {
		t.Errorf("échec de pct snapshot : %+v", done)
	}
}

func TestSnapshotUnsupportedStorage(t *testing.T) {
	e := setup(t)
	t.Setenv("FAKE_SNAP_FEATURE", "0")
	e.detect(t)
	p := e.eng.PlanFor(e.guest, ActFull)
	if p.Snap.Possible || !strings.Contains(p.Snap.Why, "ne permet pas les snapshots") || !strings.Contains(p.Snap.Why, "local-lvm") {
		t.Errorf("plan : %+v", p.Snap)
	}
	if !strings.Contains(strings.Join(p.Warnings, "\n"), "snapshot souhaité") {
		t.Errorf("avertissement attendu (case pré-cochée mais snapshot impossible) : %v", p.Warnings)
	}
	if _, err := e.eng.Execute(e.guest, ActFull, true, "admin", false, "", true); err == nil {
		t.Error("simulation avec snapshot impossible acceptée")
	}
}

func TestSnapshotDryRunOnlyChecks(t *testing.T) {
	e := setup(t)
	e.detect(t)
	_ = e.eng.Answers.Set(e.guest.Key(), map[string]string{nginxPrompt: "y"})
	j, err := e.eng.Execute(e.guest, ActFull, true, "admin", false, "", true)
	if err != nil {
		t.Fatal(err)
	}
	done := wait(t, e.eng.Jobs, j.ID)
	log := e.logOf(t, j.ID)
	if done.Status != jobs.Success || !strings.Contains(log, "possible") || strings.Contains(e.pctSets(), "pct snapshot") {
		t.Errorf("simulation : %+v\n%s", done, log)
	}
}

func TestRollbackAndDelete(t *testing.T) {
	e := setup(t)
	e.addSnap(t, "pw-20261115-0141-complet 1794703260 avant termix")
	e.detect(t)

	if _, err := e.eng.Rollback(e.guest, "pw-20261115-0141-complet", "admin", "autre"); !errors.Is(err, ErrConfirm) {
		t.Errorf("nom saisi incorrect accepté : %v", err)
	}
	if _, err := e.eng.Rollback(e.guest, "avant-maj", "admin", "termix"); err == nil {
		t.Error("retour à un snapshot manuel accepté")
	}
	self := e.guest
	self.VMID = 103
	if _, err := e.eng.Rollback(self, "pw-20261115-0141-complet", "admin", self.Name); err == nil {
		t.Error("retour arrière de l'invité de PatchWarden accepté")
	}
	j, err := e.eng.Rollback(e.guest, "pw-20261115-0141-complet", "admin", "termix")
	if err != nil {
		t.Fatal(err)
	}
	done := wait(t, e.eng.Jobs, j.ID)
	log := e.logOf(t, j.ID)
	if done.Status != jobs.Success || !strings.Contains(done.Summary, "état : running") {
		t.Fatalf("retour arrière : %+v\n%s", done, log)
	}
	sets := e.pctSets()
	if !strings.Contains(sets, "pct rollback 104 pw-20261115-0141-complet\npct start 104") {
		t.Errorf("rollback puis redémarrage attendus : %q", sets)
	}
	if !strings.Contains(log, "▶ lxc-detect 104") {
		t.Errorf("détection après le retour arrière absente :\n%s", log)
	}

	if _, err := e.eng.DeleteSnapshot(e.guest, "pw-20261115-0141-complet", "admin", false); !errors.Is(err, ErrConfirm) {
		t.Errorf("suppression sans confirmation : %v", err)
	}
	j, err = e.eng.DeleteSnapshot(e.guest, "pw-20261115-0141-complet", "admin", true)
	if err != nil {
		t.Fatal(err)
	}
	if done := wait(t, e.eng.Jobs, j.ID); done.Status != jobs.Success {
		t.Fatalf("suppression : %+v\n%s", done, e.logOf(t, j.ID))
	}
	det, _ := e.eng.Store.Get(e.guest.Key())
	if len(det.Snap.PW) != 0 || det.Snap.Other != 1 || !strings.Contains(e.snaps(t), "avant-maj") {
		t.Errorf("après suppression : %+v / %q", det.Snap, e.snaps(t))
	}
}

// Le wrapper lui-même refuse tout snapshot qui n'est pas de PatchWarden,
// même si PatchWarden était compromis.
func TestWrapperRefusesForeignSnapshots(t *testing.T) {
	e := setup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, cmd := range []string{
		"lxc-rollback 104 avant-maj",
		"lxc-snapdel 104 avant-maj",
		"lxc-snapshot 104 avant-maj 1 90 0 -",
		"lxc-snapshot 104 pw-20261115-0141-complet 0 90 0 -",
		"lxc-snapshot 104 pw-20261115-0141-complet 1 100 0 -",
	} {
		_, _, code, err := e.eng.run(ctx, "loki", cmd, func(bool, string) {})
		if err != nil || code != exitRefused {
			t.Errorf("%s : code %d, %v (refus attendu)", cmd, code, err)
		}
	}
	if strings.Contains(e.pctSets(), "avant-maj") {
		t.Errorf("snapshot manuel touché : %q", e.pctSets())
	}
}
