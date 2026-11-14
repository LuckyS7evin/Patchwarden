package detect

import (
	"strings"
	"testing"
	"time"
)

// Sortie réelle du wrapper (faux apt reprenant des lignes du CT 103).
const sample = `pw.detect=1
os.id=debian
os.version_id=13
os.pretty=Debian GNU/Linux 13 (trixie)
sys.nproc=2
sys.mem_mb=4096
sys.root_used_pct=69
sys.reboot_required=0
cs.entry=legacy
cs.script=termix
cs.slug=termix
cs.base=https://raw.githubusercontent.com/community-scripts/ProxmoxVE/main
apt.present=1
apt.refresh_rc=0
apt.index_age_h=0
apt.pkg=base-files 13.8+deb13u6 13.8+deb13u7 0
apt.pkg=bsdutils 1:2.41-5 1:2.41.5-0+deb13u1 1
apt.pkg=libnew1 - 2.0-1 0
apt.total=3
apt.security=1
apt.upgrade_simple=2
apt.security_repo=1
apt.strict_pkg=bsdutils
apt.security_strict=1
docker.present=0
pw.end=1`

func TestParse(t *testing.T) {
	r, err := Parse(strings.Split(sample, "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if r.OSPretty != "Debian GNU/Linux 13 (trixie)" || r.RootUsedPct != 69 || r.Nproc != 2 {
		t.Errorf("système : %+v", r)
	}
	if r.CS.Entry != "legacy" || r.CS.Script != "termix" || !r.CS.Present() {
		t.Errorf("community-scripts : %+v", r.CS)
	}
	a := r.Apt
	if !a.Present || a.Total != 3 || a.Security != 1 || a.SecurityStrict != 1 || a.UpgradeSimple != 2 || a.IndexAgeHours != 0 {
		t.Errorf("apt : %+v", a)
	}
	if a.RefreshRC == nil || *a.RefreshRC != 0 {
		t.Error("code de apt-get update non lu")
	}
	if len(a.Packages) != 3 || !a.Packages[1].Security || a.Packages[2].Old != "-" {
		t.Errorf("paquets : %+v", a.Packages)
	}
	if len(a.StrictPackages) != 1 || a.StrictPackages[0] != "bsdutils" {
		t.Errorf("paquets stricts : %v", a.StrictPackages)
	}
}

func TestParseIncomplete(t *testing.T) {
	cut := strings.Split(sample, "\n")
	if _, err := Parse(cut[:10]); err != ErrIncomplete {
		t.Errorf("sortie tronquée acceptée : %v", err)
	}
}

func TestParseVersions(t *testing.T) {
	inst, abs := ParseVersions([]string{"version.termix=release-2.6.1-tag", "version_absent.guacd=1", "bruit"})
	if inst["termix"] != "release-2.6.1-tag" || !abs["guacd"] || len(inst) != 1 {
		t.Errorf("versions : %v %v", inst, abs)
	}
}

func TestAppStatus(t *testing.T) {
	for _, c := range []struct {
		inst, latest string
		known        bool
		want         string
	}{
		{"v1.2.3", "1.2.3", true, "à jour"},
		{"1.2.3", "v1.2.4", true, "mise à jour disponible"},
		{"release-2.6.1-tag", "v26.11.1", true, "mise à jour disponible"},
		{"", "v1", false, "inconnue"},
		{"1.0", "", true, "inconnue"},
	} {
		a := App{Installed: c.inst, InstalledKnown: c.known, Latest: c.latest}
		if got := a.Status(); got != c.want {
			t.Errorf("%q vs %q : %q, attendu %q", c.inst, c.latest, got, c.want)
		}
	}
	if Normalize("version") != "version" {
		t.Error("un mot commençant par v ne doit pas être tronqué")
	}
}

func TestStore(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	r := Result{At: time.Date(2026, 11, 13, 23, 40, 0, 0, time.UTC), OSID: "debian"}
	if err := s.Put("loki/103", r); err != nil {
		t.Fatal(err)
	}
	s2, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := s2.Get("loki/103")
	if !ok || got.OSID != "debian" || !got.At.Equal(r.At) {
		t.Errorf("relu : %+v", got)
	}
}

func TestSinceIsCarried(t *testing.T) {
	s, _ := OpenStore(t.TempDir())
	t1 := time.Date(2026, 11, 10, 3, 40, 0, 0, time.UTC)
	t2 := t1.Add(24 * time.Hour)
	first := Result{At: t1, Apt: Apt{Packages: []Package{
		{Name: "libssl3t64", New: "3.5.7-2", Security: true},
		{Name: "bash", New: "5.2-10"},
	}}, Apps: []App{{Name: "termix", Installed: "1", InstalledKnown: true, Latest: "2"}}}
	_ = s.Put("loki/104", first)
	second := Result{At: t2, Apt: Apt{Packages: []Package{
		{Name: "libssl3t64", New: "3.5.7-2", Security: true}, // toujours en attente
		{Name: "curl", New: "8.14-7", Security: true},        // nouveau
	}}, Apps: []App{{Name: "termix", Installed: "1", InstalledKnown: true, Latest: "3"}}} // nouvelle version
	_ = s.Put("loki/104", second)
	got, _ := s.Get("loki/104")
	if !got.Apt.Packages[0].Since.Equal(t1) || !got.Apt.Packages[1].Since.Equal(t2) {
		t.Errorf("dates des paquets : %+v", got.Apt.Packages)
	}
	if !got.OldestSecurity().Equal(t1) {
		t.Errorf("plus ancien correctif : %v", got.OldestSecurity())
	}
	sec, apps := got.NewSince(t2)
	if len(sec) != 1 || sec[0].Name != "curl" || len(apps) != 1 || apps[0].Latest != "3" {
		t.Errorf("nouveautés : %+v %+v", sec, apps)
	}
}

func TestReconcileSecurity(t *testing.T) {
	lines := []string{"pw.detect=1",
		// openssl : une mise à jour de point (stable) remplace le correctif de sécurité.
		"apt.pkg=openssl 3.5.6 3.5.8 0",
		"apt.pkg=curl 8.14-4 8.14-7 1",
		"apt.pkg=bash 5.2-9 5.2-10 0",
		"apt.pkg=libnouvelle1 - 1.0 1",
		"apt.strict_pkg=openssl", "apt.strict_pkg=curl", "apt.strict_pkg=libnouvelle1", "apt.strict_pkg=libautre2",
		"apt.security_strict=4", "apt.total=4", "apt.security=2", "pw.end=1"}
	r, err := Parse(lines)
	if err != nil {
		t.Fatal(err)
	}
	if r.Apt.Security != 3 || !r.Apt.Packages[0].Security || r.Apt.Packages[2].Security {
		t.Errorf("sécurité : %d %+v", r.Apt.Security, r.Apt.Packages)
	}
	if r.Apt.StrictNew != 2 {
		t.Errorf("nouvelles dépendances : %d", r.Apt.StrictNew)
	}
	if n := r.Apt.SecurityNotStrict(); n != 0 {
		t.Errorf("hors strict : %d", n)
	}
}

func TestMajorChange(t *testing.T) {
	for _, c := range []struct {
		inst, latest string
		want         bool
	}{
		{"2.4.3", "v3.0.3", true},
		{"release-2.6.1-tag", "v26.11.1", true},
		{"2.19.11", "v2.20.23", false},
		{"v1.6.0", "1.6.1", false},
		{"4.0.0", "v4.4.0", false},
	} {
		a := App{Installed: c.inst, InstalledKnown: true, Latest: c.latest}
		if got := a.MajorChange(); got != c.want {
			t.Errorf("%s → %s : %v", c.inst, c.latest, got)
		}
	}
}
