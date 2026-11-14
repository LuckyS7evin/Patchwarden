package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadEnvFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "patchwarden.env")
	body := "# commentaire\n\nPW_T_A=abc-123\nexport PW_T_B=\"avec espaces\"\nPW_T_C='simple'\nPW_T_D=deja\n"
	if err := os.WriteFile(p, []byte(body), 0o640); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"PW_T_A", "PW_T_B", "PW_T_C"} {
		t.Setenv(k, "") // garantit le nettoyage en fin de test
		os.Unsetenv(k)
	}
	t.Setenv("PW_T_D", "environnement")
	warn, err := LoadEnvFile(p, false)
	if err != nil || warn != "" {
		t.Fatalf("%v %q", err, warn)
	}
	for k, want := range map[string]string{"PW_T_A": "abc-123", "PW_T_B": "avec espaces", "PW_T_C": "simple", "PW_T_D": "environnement"} {
		if got := os.Getenv(k); got != want {
			t.Errorf("%s = %q, attendu %q", k, got, want)
		}
	}
	if _, err := LoadEnvFile(filepath.Join(t.TempDir(), "absent"), true); err != nil {
		t.Errorf("fichier facultatif absent : %v", err)
	}
	if _, err := LoadEnvFile(filepath.Join(t.TempDir(), "absent"), false); err == nil {
		t.Error("fichier explicite absent accepté")
	}
	_ = os.WriteFile(p, []byte("pas une affectation\n"), 0o644)
	_ = os.Chmod(p, 0o644)
	warn, err = LoadEnvFile(p, false)
	if err == nil || !strings.Contains(err.Error(), "ligne 1") || !strings.Contains(warn, "chmod 640") {
		t.Errorf("ligne invalide / droits : %v %q", err, warn)
	}
}
