package eol

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEvaluate(t *testing.T) {
	now := d("2026-11-16")
	c := New("", nil)
	cases := []struct {
		id, ver, level, text string
	}{
		{"debian", "13", "ok", "supporté jusqu'au 09/08/2028"},
		{"debian", "12", "warn", "correctifs Debian LTS jusqu'au 30/06/2028"},
		{"debian", "11", "crit", "plus aucun correctif de sécurité depuis le 31/08/2026"},
		{"ubuntu", "24.04", "ok", "29"},
		{"ubuntu", "25.04", "crit", "15/01/2026"},
		{"alpine", "3.21.2", "crit", "depuis le 01/11/2026"},
		{"alpine", "3.22.1", "warn", "fin du support le 01/05/2027 (dans 167 jours)"},
		{"centos", "7", "", ""},
	}
	for _, tc := range cases {
		st := c.Status(tc.id, tc.ver, now)
		if st.Level != tc.level || !strings.Contains(st.Text, tc.text) {
			t.Errorf("%s %s : %+v", tc.id, tc.ver, st)
		}
	}
	if st := c.Status("debian", "12.7", d("2026-01-01")); st.Level != "warn" || !strings.Contains(st.Text, "dans 161 jours") {
		t.Errorf("fin proche : %+v", st)
	}
	if st := c.Status("debian", "42", now); st.Level != "" || st.Name != "Debian 42" {
		t.Errorf("version inconnue : %+v", st)
	}
}

func TestOnlineRefresh(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/debian.json" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`[{"cycle":"14","eol":"2030-08-01","extendedSupport":false},{"cycle":"13","eol":"2028-08-09","extendedSupport":"2030-06-30"}]`))
	}))
	defer srv.Close()
	c := New(srv.URL, srv.Client())
	if err := c.Refresh("debian"); err != nil {
		t.Fatal(err)
	}
	if st := c.Status("debian", "14", d("2026-11-16")); st.Level != "ok" || !strings.Contains(st.Text, "01/08/2030") {
		t.Errorf("cycle lu en ligne : %+v", st)
	}
	if err := c.Refresh("ubuntu"); err == nil {
		t.Error("erreur HTTP attendue")
	}
	if st := c.Status("ubuntu", "24.04", d("2026-11-16")); st.Level != "ok" {
		t.Errorf("repli sur la table : %+v", st)
	}
}
