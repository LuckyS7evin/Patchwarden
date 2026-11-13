package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const fp = "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89"

func write(t *testing.T, body string, perm os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(p, []byte(body), perm); err != nil {
		t.Fatal(err)
	}
	return p
}

const valid = `
[auth]
username = "admin"
password_hash = "$2a$12$abcdefghijklmnopqrstuuabcdefghijklmnopqrstuvwxyz01234"

[[proxmox]]
name = "loki"
url = "https://192.168.0.141:8006"
token_id = "patchwarden@pve!inventaire"
token_secret = "secret"
fingerprint = "` + fp + `"
`

func TestLoadValidWithDefaults(t *testing.T) {
	cfg, warns, err := Load(write(t, valid, 0o600))
	if err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}
	if len(warns) != 0 {
		t.Errorf("avertissements inattendus : %v", warns)
	}
	if cfg.Server.Listen != "0.0.0.0:8080" || cfg.Auth.SessionDuration.Duration != 12*time.Hour {
		t.Errorf("valeurs par défaut non appliquées : %+v %+v", cfg.Server, cfg.Auth)
	}
	if cfg.Policy.CommunityScriptTag != "community-script" || cfg.Policy.CriticalTags[0] != "critique" {
		t.Errorf("politique par défaut incorrecte : %+v", cfg.Policy)
	}
	if cfg.Inventory.Refresh.Duration != 5*time.Minute {
		t.Errorf("refresh par défaut : %v", cfg.Inventory.Refresh)
	}
}

func TestLoadWarnsOnOpenPermissions(t *testing.T) {
	_, warns, err := Load(write(t, valid, 0o644))
	if err != nil {
		t.Fatal(err)
	}
	if len(warns) != 1 || !strings.Contains(warns[0], "chmod 640") {
		t.Errorf("avertissement attendu sur les droits, obtenu %v", warns)
	}
}

func TestLoadRejectsUnknownKeys(t *testing.T) {
	_, _, err := Load(write(t, valid+"\n[server]\nlisten = \"0.0.0.0:9000\"\nlsiten = \"x\"\n", 0o600))
	if err == nil || !strings.Contains(err.Error(), "server.lsiten") {
		t.Fatalf("clé inconnue non signalée : %v", err)
	}
}

func TestSecretFromEnv(t *testing.T) {
	body := strings.Replace(valid, `token_secret = "secret"`, `token_secret_env = "PW_TEST_SECRET"`, 1)
	t.Setenv("PW_TEST_SECRET", "depuis-env")
	cfg, _, err := Load(write(t, body, 0o600))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Proxmox[0].TokenSecret != "depuis-env" {
		t.Errorf("secret non lu dans l'environnement")
	}
	t.Setenv("PW_TEST_SECRET", "")
	if _, _, err := Load(write(t, body, 0o600)); err == nil || !strings.Contains(err.Error(), "PW_TEST_SECRET") {
		t.Errorf("variable vide non signalée : %v", err)
	}
}

func TestValidateCollectsErrors(t *testing.T) {
	body := `
[auth]
username = ""
password_hash = "clair"
[[proxmox]]
name = "Loki!"
url = "http://192.168.0.141:8006"
token_id = "patchwarden"
fingerprint = "zz"
`
	_, _, err := Load(write(t, body, 0o600))
	if err == nil {
		t.Fatal("erreurs attendues")
	}
	for _, want := range []string{"auth.username", "bcrypt", "name doit", "https://", "token_id", "token_secret", "fingerprint invalide"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("erreur %q absente de : %v", want, err)
		}
	}
}

func TestTLSVerificationIsMandatory(t *testing.T) {
	body := strings.Replace(valid, `fingerprint = "`+fp+`"`, "", 1)
	if _, _, err := Load(write(t, body, 0o600)); err == nil || !strings.Contains(err.Error(), "fingerprint ou ca_file") {
		t.Errorf("absence de vérification TLS non refusée : %v", err)
	}
}

func TestParseFingerprint(t *testing.T) {
	b, err := ParseFingerprint(fp)
	if err != nil || len(b) != 32 || b[0] != 0xab {
		t.Fatalf("empreinte avec deux-points : %v %x", err, b)
	}
	if _, err := ParseFingerprint(strings.ReplaceAll(fp, ":", "")); err != nil {
		t.Errorf("empreinte sans deux-points refusée : %v", err)
	}
	if _, err := ParseFingerprint("abcd"); err == nil {
		t.Error("empreinte trop courte acceptée")
	}
}

func TestGroupReadableIsAccepted(t *testing.T) {
	_, warns, err := Load(write(t, valid, 0o640))
	if err != nil || len(warns) != 0 {
		t.Errorf("640 doit être accepté sans avertissement : %v %v", err, warns)
	}
}

func TestSSHSection(t *testing.T) {
	dir := t.TempDir()
	key, kh := filepath.Join(dir, "id"), filepath.Join(dir, "known_hosts")
	_ = os.WriteFile(key, []byte("x"), 0o600)
	_ = os.WriteFile(kh, nil, 0o600)
	body := valid + `
[ssh]
key_file = "` + key + `"
known_hosts = "` + kh + `"
[ssh.nodes]
loki = "192.168.0.141"
tyr = "192.168.0.43:2222"
`
	cfg, _, err := Load(write(t, body, 0o600))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.SSH.Enabled() || cfg.SSH.User != "root" || cfg.SSH.Nodes["loki"] != "192.168.0.141:22" || cfg.SSH.Nodes["tyr"] != "192.168.0.43:2222" {
		t.Errorf("ssh : %+v", cfg.SSH)
	}
	if !*cfg.Detection.AptRefresh || cfg.Jobs.MaxParallel != 2 || cfg.CS.AllowedBases[0] != "https://raw.githubusercontent.com/community-scripts/ProxmoxVE/main" {
		t.Errorf("valeurs par défaut : %+v %+v %+v", cfg.Detection, cfg.Jobs, cfg.CS)
	}
	noKH := strings.Replace(body, `known_hosts = "`+kh+`"`, "", 1)
	if _, _, err := Load(write(t, noKH, 0o600)); err == nil || !strings.Contains(err.Error(), "known_hosts est obligatoire") {
		t.Errorf("known_hosts manquant accepté : %v", err)
	}
	if cfg, _, err := Load(write(t, valid, 0o600)); err != nil || cfg.SSH.Enabled() {
		t.Errorf("sans [ssh], lecture seule attendue : %v", err)
	}
	off := valid + "\n[detection]\napt_refresh = false\n"
	if cfg, _, err := Load(write(t, off, 0o600)); err != nil || *cfg.Detection.AptRefresh {
		t.Errorf("apt_refresh = false ignoré : %v", err)
	}
}
