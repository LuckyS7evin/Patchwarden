package detect

import "testing"

func TestParseDocker(t *testing.T) {
	lines := []string{
		"pw.detect=1", "docker.present=1", "docker.containers=3", "docker.compose=2.29.1",
		"docker.ctr=aaaaaaaaaaaaffff|/mealie|ghcr.io/x/mealie:v1.8.0|sha256:i1|running|mealie|mealie|/data/compose/12|/data/compose/12/docker-compose.yml|v1.8.0|https://github.com/x/mealie",
		"docker.ctr=bbbbbbbbbbbbffff|/wt|containrrr/watchtower|sha256:i2|running|<no value>|<no value>|<no value>|<no value>|<no value>|<no value>",
		"docker.ctr=ccccccccccccffff|/beszel|henrygd/beszel|sha256:i3|exited|beszel|beszel|/opt/beszel|/opt/beszel/compose.yml||",
		"docker.img=sha256:i1|ghcr.io/x/mealie@sha256:m1",
		"docker.img=sha256:i2|",
		"docker.ref=henrygd/beszel|henrygd/beszel@sha256:b1,",
		"pw.end=1",
	}
	r, err := Parse(lines)
	if err != nil {
		t.Fatal(err)
	}
	d := r.DockerInfo
	if d.Compose != "2.29.1" || len(d.List) != 3 || d.List[0].ID != "aaaaaaaaaaaa" || len(d.List[0].Digests) != 1 || len(d.List[1].Digests) != 0 {
		t.Fatalf("conteneurs : %+v", d)
	}
	if d.List[1].Project != "" || d.List[1].Kind != "watchtower" || len(d.Watchtower) != 1 {
		t.Errorf("watchtower : %+v", d.List[1])
	}
	want := map[string]string{"portainer-12": GroupPortainer, "compose-beszel": GroupCompose, "run-wt": GroupRun}
	for k, kind := range want {
		g, ok := d.Group(k)
		if !ok || g.Kind != kind {
			t.Errorf("groupe %s : %+v", k, g)
		}
	}
	if g, _ := d.Group("compose-beszel"); g.Stopped != 1 {
		t.Errorf("conteneur arrêté non compté : %+v", g)
	}
	if c, _ := d.Container("beszel"); c.Tag() != "latest" || len(c.Digests) != 1 {
		t.Errorf("tag par défaut, ou empreintes lues par référence : %+v", c)
	}
}
