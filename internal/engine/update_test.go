package engine

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LuckyS7evin/patchwarden/internal/jobs"
)

func (e *env) detect(t *testing.T) {
	t.Helper()
	j, err := e.eng.Detect(e.guest, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if done := wait(t, e.eng.Jobs, j.ID); done.Status != jobs.Success {
		t.Fatalf("détection préalable : %+v", done)
	}
}

func (e *env) logOf(t *testing.T, id string) string {
	t.Helper()
	lines, _ := e.eng.Jobs.Log(id)
	var b strings.Builder
	for _, l := range lines {
		b.WriteString(l.Text + "\n")
	}
	return b.String()
}

func (e *env) pctSets() string {
	b, _ := os.ReadFile(filepath.Join(e.root, "pctset.log"))
	return string(b)
}

const nginxPrompt = "Update Nginx configuration? [Y/n]:"

func TestPlanBlockers(t *testing.T) {
	e := setup(t)
	if p := e.eng.PlanFor(e.guest, ActFull); p.OK() || !strings.Contains(p.Blockers[0], "aucune détection") {
		t.Errorf("sans détection : %+v", p.Blockers)
	}
	e.detect(t)

	p := e.eng.PlanFor(e.guest, ActFull)
	if p.OK() || !strings.Contains(strings.Join(p.Blockers, "|"), "questions sans terminal") {
		t.Errorf("question non répondue : %+v", p.Blockers)
	}
	if !p.CSRun || len(p.Answers) != 1 || p.Answers[0].Prompt != nginxPrompt || p.Answers[0].Set {
		t.Errorf("plan community-scripts : %+v", p)
	}
	if !strings.Contains(p.CSNote, "termix release-2.6.1-tag → v26.11.1") {
		t.Errorf("note : %q", p.CSNote)
	}

	self := e.guest
	self.VMID = 103
	if p := e.eng.PlanFor(self, ActFull); p.OK() || !strings.Contains(p.Blockers[0], "héberge PatchWarden") {
		t.Errorf("invité hôte : %+v", p.Blockers)
	}

	sec := e.eng.PlanFor(e.guest, ActSecurity)
	if !sec.OK() || sec.CSRun || len(sec.Packages) != 1 || sec.Packages[0].Name != "libssl3t64" {
		t.Errorf("sécurité : %+v", sec)
	}
	if _, err := e.eng.Execute(e.guest, ActSecurity, false, "admin", false, "", false); !errors.Is(err, ErrConfirm) {
		t.Errorf("exécution sans confirmation : %v", err)
	}
	crit := e.guest
	crit.Critical, crit.CriticalReason = true, "tag « critique »"
	if _, err := e.eng.Execute(crit, ActSecurity, false, "admin", true, "autre", false); !errors.Is(err, ErrConfirm) {
		t.Errorf("invité critique sans le nom : %v", err)
	}
	if n := len(e.eng.Jobs.List("", 0)); n != 1 {
		t.Errorf("aucune tâche ne doit être créée par un refus (%d tâches)", n)
	}
}

func TestSecuritySimulation(t *testing.T) {
	e := setup(t)
	e.detect(t)
	j, err := e.eng.Execute(e.guest, ActSecurity, true, "admin", false, "", false)
	if err != nil {
		t.Fatal(err)
	}
	done := wait(t, e.eng.Jobs, j.ID)
	log := e.logOf(t, j.ID)
	if done.Status != jobs.Success || !done.DryRun || done.Kind != jobs.KindSecurity {
		t.Fatalf("simulation : %+v\n%s", done, log)
	}
	for _, want := range []string{"SIMULATION", "▶ lxc-apt 104 security 1", " -s ", "Dir::Etc::SourceList=", "simulation apt : 1 paquet(s)"} {
		if !strings.Contains(log+done.Summary, want) {
			t.Errorf("simulation sans %q :\n%s", want, log)
		}
	}
	if strings.Contains(log, "apt-get update") && !strings.Contains(log, "apt-get update (index complet)") {
		t.Error("une simulation ne doit pas lancer apt-get update")
	}
	if e.pctSets() != "" {
		t.Error("une simulation ne doit pas toucher aux ressources")
	}
}

func TestFullUpdateEndToEnd(t *testing.T) {
	e := setup(t)
	e.detect(t)
	if err := e.eng.Answers.Set(e.guest.Key(), map[string]string{nginxPrompt: "n"}); err != nil {
		t.Fatal(err)
	}
	p := e.eng.PlanFor(e.guest, ActFull)
	if !p.OK() || answersArg(p.Answers) != "n" {
		t.Fatalf("plan : %+v", p.Blockers)
	}
	j, err := e.eng.Execute(e.guest, ActFull, false, "admin", true, "", false)
	if err != nil {
		t.Fatal(err)
	}
	done := wait(t, e.eng.Jobs, j.ID)
	log := e.logOf(t, j.ID)
	if done.Status != jobs.Success {
		t.Fatalf("mise à jour : %+v\n%s", done, log)
	}
	for _, want := range []string{
		"▶ lxc-apt 104 full 0", "PW: apt-get update", "pw.apt_rc=0",
		"▶ lxc-cs-update 104 n 4 4096",
		"ressources portées temporairement à 4 CPU / 4096 Mo",
		"[INFO] réponse reçue : 'n'", "[OK] Updated successfully!", "pw.update_rc=0",
		"ressources restaurées : 2 CPU / 2048 Mo",
		"▶ lxc-detect 104 1",
	} {
		if !strings.Contains(log, want) {
			t.Errorf("journal sans %q :\n%s", want, log)
		}
	}
	if !strings.Contains(e.pctSets(), "--cores 2 --memory 2048") {
		t.Errorf("ressources non restaurées : %q", e.pctSets())
	}
	if !strings.Contains(done.Summary, "apt : 2 paquet(s) mis à jour") || !strings.Contains(done.Summary, "après :") {
		t.Errorf("résumé : %q", done.Summary)
	}
	if left, _ := filepath.Glob("/tmp/create-lxc-pwtest-*.log"); len(left) != 0 {
		t.Errorf("journal temporaire laissé dans l'invité : %v", left)
	}
}

func TestCSUpdateFailureIsExplained(t *testing.T) {
	e := setup(t)
	e.detect(t)
	_ = e.eng.Answers.Set(e.guest.Key(), map[string]string{nginxPrompt: "y"})
	t.Setenv("FAKE_UPDATE_RC", "114")
	j, err := e.eng.Execute(e.guest, ActFull, false, "admin", true, "", false)
	if err != nil {
		t.Fatal(err)
	}
	done := wait(t, e.eng.Jobs, j.ID)
	if done.Status != jobs.Failed || !strings.Contains(done.Error, "code 114") || !strings.Contains(done.Error, "80 %") {
		t.Errorf("échec attendu et expliqué : %+v", done)
	}
	if !strings.Contains(e.pctSets(), "--cores 2 --memory 2048") {
		t.Errorf("ressources non restaurées après l'échec : %q", e.pctSets())
	}
}

// Proxmox n'applique les CPU d'un CT démarré qu'au passage suivant de
// pvestatd : update ne doit être lancé qu'une fois les CPU vus dans le CT
// (sinon le script refuse, code 113, comme sur Termix le 15/11/2026).
func TestCSUpdateWaitsForCPUs(t *testing.T) {
	e := setup(t)
	e.detect(t)
	_ = e.eng.Answers.Set(e.guest.Key(), map[string]string{nginxPrompt: "y"})
	t.Setenv("FAKE_CPU_LAG", "3")
	j, err := e.eng.Execute(e.guest, ActFull, false, "admin", true, "", false)
	if err != nil {
		t.Fatal(err)
	}
	done := wait(t, e.eng.Jobs, j.ID)
	log := e.logOf(t, j.ID)
	if done.Status != jobs.Success {
		t.Fatalf("mise à jour : %+v\n%s", done, log)
	}
	if !strings.Contains(log, "ressources vues dans le CT : 4 CPU / 4096 Mo") {
		t.Errorf("attente des ressources absente :\n%s", log)
	}
}

func TestCSUpdateCPUsNeverSeen(t *testing.T) {
	e := setup(t)
	e.detect(t)
	_ = e.eng.Answers.Set(e.guest.Key(), map[string]string{nginxPrompt: "y"})
	t.Setenv("FAKE_CPU_LAG", "jamais")
	j, err := e.eng.Execute(e.guest, ActFull, false, "admin", true, "", false)
	if err != nil {
		t.Fatal(err)
	}
	done := wait(t, e.eng.Jobs, j.ID)
	log := e.logOf(t, j.ID)
	if done.Status != jobs.Failed || !strings.Contains(done.Error, "pvestatd") {
		t.Errorf("échec attendu et expliqué : %+v", done)
	}
	if strings.Contains(log, "lancement de update") {
		t.Errorf("update lancé alors que le CT ne voit pas les CPU :\n%s", log)
	}
	if !strings.Contains(log, "le CT ne voit que 2 CPU / 4096 Mo") || !strings.Contains(e.pctSets(), "--cores 2 --memory 2048") {
		t.Errorf("diagnostic ou restauration manquants : %q\n%s", e.pctSets(), log)
	}
}

func TestAnswerStore(t *testing.T) {
	dir := t.TempDir()
	s, _ := OpenAnswers(dir)
	if err := s.Set("loki/104", map[string]string{"q": "peut-être"}); err == nil {
		t.Error("réponse invalide acceptée")
	}
	if err := s.Set("loki/104", map[string]string{"q1": "y", "q2": ""}); err != nil {
		t.Fatal(err)
	}
	s2, _ := OpenAnswers(dir)
	if got := s2.Get("loki/104"); got["q1"] != "y" || got["q2"] != "" || len(got) != 2 {
		t.Errorf("relu : %v", got)
	}
	if answersArg([]PromptAnswer{{Value: "y"}, {Value: ""}, {Value: "n"}}) != "y._.n" || answersArg(nil) != "-" {
		t.Error("encodage des réponses")
	}
}

func TestAptCount(t *testing.T) {
	real := []string{
		"Reading package lists...",
		"The following packages will be upgraded:",
		"  apt apt-utils libssl3t64",
		"3 upgraded, 1 newly installed, 0 to remove and 0 not upgraded.",
		"Setting up libssl3t64:amd64 (3.5.7-1~deb13u3) ...",
	}
	if n := aptCount(real); n != 4 {
		t.Errorf("exécution réelle : %d, attendu 4", n)
	}
	if n := aptCount([]string{"Inst a [1] (2 x)", "Inst b [1] (2 x)"}); n != 2 {
		t.Errorf("repli sur les lignes Inst : %d", n)
	}
}

func TestNeedsRerun(t *testing.T) {
	if !needsRerun([]string{"[2026-11-15 01:17:54] [WARN] Run update again to continue to the current Termix release"}) {
		t.Error("migration par étapes de Termix non repérée")
	}
	if needsRerun([]string{"[OK] Updated successfully!"}) {
		t.Error("faux positif")
	}
}

func TestExplainAptFetchError(t *testing.T) {
	out := []string{
		"PW: apt-get update",
		"Err:5 http://security.debian.org bullseye-security Release",
		"  404  Not Found",
		"PW-AVERTISSEMENT: apt-get update a signalé des erreurs, la mise à jour continue avec l'index disponible",
		"E: Unable to fetch some archives, maybe run apt-get update or try with --fix-missing?",
	}
	err := explainApt(100, nil, out)
	if err == nil || !strings.Contains(err.Error(), "Err:5 http://security.debian.org bullseye-security Release (404  Not Found)") || !strings.Contains(err.Error(), "apt-get update avait déjà échoué") {
		t.Errorf("explication : %v", err)
	}
}
