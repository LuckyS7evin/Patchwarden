package detect

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Container est un conteneur Docker d'un invité.
type Container struct {
	ID          string   `json:"id"` // 12 premiers caractères
	Name        string   `json:"name"`
	Image       string   `json:"image"` // référence telle que configurée (nginx:1.27)
	ImageID     string   `json:"image_id"`
	State       string   `json:"state"` // running, exited…
	Project     string   `json:"project,omitempty"`
	Service     string   `json:"service,omitempty"`
	WorkDir     string   `json:"work_dir,omitempty"`
	ConfigFiles string   `json:"config_files,omitempty"`
	Version     string   `json:"version,omitempty"` // label org.opencontainers.image.version
	Source      string   `json:"source,omitempty"`  // label org.opencontainers.image.source
	Digests     []string `json:"digests,omitempty"` // RepoDigests de l'image

	// Comparaison avec le registre (complétée par le moteur).
	Check        string    `json:"check,omitempty"` // voir Check*
	CheckText    string    `json:"check_text,omitempty"`
	RemoteDigest string    `json:"remote_digest,omitempty"`
	NewTag       string    `json:"new_tag,omitempty"` // version plus récente publiée sous un autre tag
	ChangelogURL string    `json:"changelog_url,omitempty"`
	Since        time.Time `json:"since,omitempty"` // première détection de la nouvelle image
	// Kind : rôle particulier (watchtower, portainer, agent).
	Kind string `json:"kind,omitempty"`
	// Health : état du HEALTHCHECK (healthy, unhealthy, starting), vide sans healthcheck.
	Health string `json:"health,omitempty"`
}

// États de la comparaison avec le registre.
const (
	CheckOK      = "ok"      // image à jour pour ce tag
	CheckUpdate  = "update"  // nouvelle image publiée pour ce tag
	CheckLocal   = "local"   // image construite sur place (pas d'empreinte de registre)
	CheckPinned  = "pinned"  // image fixée par empreinte (@sha256)
	CheckUnknown = "unknown" // registre injoignable ou dépôt privé
)

// Running dit si le conteneur tourne.
func (c Container) Running() bool { return c.State == "running" }

// UpdateAvailable : nouvelle image pour le tag utilisé.
func (c Container) UpdateAvailable() bool { return c.Check == CheckUpdate }

// Tag renvoie le tag de l'image (latest par défaut).
func (c Container) Tag() string {
	img := c.Image
	if i := strings.Index(img, "@"); i >= 0 {
		img = img[:i]
	}
	if i := strings.LastIndex(img, ":"); i >= 0 && !strings.Contains(img[i+1:], "/") {
		return img[i+1:]
	}
	return "latest"
}

// Groupes de conteneurs, selon la façon dont ils sont mis à jour.
const (
	GroupPortainer = "portainer" // stack Portainer : API Portainer
	GroupCompose   = "compose"   // projet docker compose classique : pull puis up -d
	GroupRun       = "run"       // conteneur lancé par docker run : détection seulement
)

// DockerGroup rassemble les conteneurs mis à jour ensemble.
type DockerGroup struct {
	Key        string   `json:"key"` // portainer-12, compose-beszel, run-portainer
	Kind       string   `json:"kind"`
	Name       string   `json:"name"`
	StackID    int      `json:"stack_id,omitempty"`
	Instance   string   `json:"instance,omitempty"` // instance Portainer ([[portainer]] name)
	EndpointID int      `json:"endpoint_id,omitempty"`
	Git        bool     `json:"git,omitempty"`
	WorkDir    string   `json:"work_dir,omitempty"`
	Containers []string `json:"containers"` // noms
	Updates    int      `json:"updates"`    // conteneurs démarrés avec une nouvelle image
	Newer      int      `json:"newer"`      // conteneurs dont une version plus récente existe (autre tag)
	Stopped    int      `json:"stopped"`
	// Blocker : la mise à jour depuis PatchWarden est impossible (raison).
	Blocker  string   `json:"blocker,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

// Label renvoie le libellé du groupe.
func (g DockerGroup) Label() string {
	switch g.Kind {
	case GroupPortainer:
		return "stack Portainer « " + g.Name + " »"
	case GroupCompose:
		return "projet compose « " + g.Name + " »"
	}
	return "conteneur « " + g.Name + " » (docker run)"
}

// Updatable : une mise à jour est possible et utile.
func (g DockerGroup) Updatable() bool { return g.Blocker == "" && g.Updates > 0 }

// Docker décrit les conteneurs d'un invité.
type Docker struct {
	Compose    string        `json:"compose,omitempty"` // version de docker compose v2
	List       []Container   `json:"list,omitempty"`
	Groups     []DockerGroup `json:"groups,omitempty"`
	Watchtower []string      `json:"watchtower,omitempty"` // conteneurs Watchtower démarrés
	// Checked : comparaison aux registres faite.
	Checked bool     `json:"checked,omitempty"`
	Errors  []string `json:"errors,omitempty"`
}

// Container renvoie un conteneur par son nom.
func (d Docker) Container(name string) (Container, bool) {
	for _, c := range d.List {
		if c.Name == name {
			return c, true
		}
	}
	return Container{}, false
}

// Group renvoie un groupe par sa clé.
func (d Docker) Group(key string) (DockerGroup, bool) {
	for _, g := range d.Groups {
		if g.Key == key {
			return g, true
		}
	}
	return DockerGroup{}, false
}

// Updates compte les conteneurs démarrés qui ont une nouvelle image.
func (d Docker) Updates() int {
	n := 0
	for _, c := range d.List {
		if c.Running() && c.UpdateAvailable() {
			n++
		}
	}
	return n
}

// Newer compte les conteneurs dont une version plus récente existe sous un autre tag.
func (d Docker) Newer() int {
	n := 0
	for _, c := range d.List {
		if c.NewTag != "" {
			n++
		}
	}
	return n
}

// UpdatableGroups renvoie les groupes qu'une mise à jour Docker traiterait.
func (d Docker) UpdatableGroups() []DockerGroup {
	var out []DockerGroup
	for _, g := range d.Groups {
		if g.Updatable() {
			out = append(out, g)
		}
	}
	return out
}

var portainerDirRe = regexp.MustCompile(`^/data/compose/([0-9]+)(/|$)`)

// PortainerStackID renvoie le numéro de stack Portainer d'après le dossier
// du projet (/data/compose/<id>, vu depuis le conteneur Portainer).
func PortainerStackID(workDir string) int {
	m := portainerDirRe.FindStringSubmatch(workDir)
	if m == nil {
		return 0
	}
	n, _ := strconv.Atoi(m[1])
	return n
}

// containerKind repère Watchtower et Portainer d'après l'image.
func containerKind(image string) string {
	low := strings.ToLower(image)
	switch {
	case strings.Contains(low, "watchtower"):
		return "watchtower"
	case strings.Contains(low, "portainer/agent"):
		return "agent"
	case strings.Contains(low, "portainer/portainer"):
		return "portainer"
	}
	return ""
}

var keySafe = regexp.MustCompile(`[^a-z0-9_-]+`)

// BuildGroups range les conteneurs par mode de mise à jour, d'après les labels
// posés par docker compose. Les champs propres à Portainer (instance,
// environnement) sont complétés par le moteur.
func (d *Docker) BuildGroups() {
	d.Groups = nil
	d.Watchtower = nil
	idx := map[string]int{}
	for i := range d.List {
		c := &d.List[i]
		c.Kind = containerKind(c.Image)
		if c.Kind == "watchtower" && c.Running() {
			d.Watchtower = append(d.Watchtower, c.Name)
		}
		var g DockerGroup
		switch {
		case c.Project != "" && PortainerStackID(c.WorkDir) > 0:
			g = DockerGroup{Key: "portainer-" + strconv.Itoa(PortainerStackID(c.WorkDir)), Kind: GroupPortainer, Name: c.Project, StackID: PortainerStackID(c.WorkDir), WorkDir: c.WorkDir}
		case c.Project != "":
			g = DockerGroup{Key: "compose-" + keySafe.ReplaceAllString(strings.ToLower(c.Project), "_"), Kind: GroupCompose, Name: c.Project, WorkDir: c.WorkDir}
		default:
			g = DockerGroup{Key: "run-" + keySafe.ReplaceAllString(strings.ToLower(c.Name), "_"), Kind: GroupRun, Name: c.Name}
		}
		j, ok := idx[g.Key]
		if !ok {
			j = len(d.Groups)
			idx[g.Key] = j
			d.Groups = append(d.Groups, g)
		}
		gr := &d.Groups[j]
		gr.Containers = append(gr.Containers, c.Name)
		if !c.Running() {
			gr.Stopped++
		}
		if c.Running() && c.UpdateAvailable() {
			gr.Updates++
		}
		if c.NewTag != "" {
			gr.Newer++
		}
	}
	sort.SliceStable(d.Groups, func(i, j int) bool {
		if d.Groups[i].Kind != d.Groups[j].Kind {
			return kindOrder(d.Groups[i].Kind) < kindOrder(d.Groups[j].Kind)
		}
		return d.Groups[i].Name < d.Groups[j].Name
	})
}

func kindOrder(k string) int {
	switch k {
	case GroupPortainer:
		return 0
	case GroupCompose:
		return 1
	}
	return 2
}

// parseDocker interprète une ligne docker.ctr ou docker.img.
func (d *Docker) parseLine(k, v string, images, refs map[string][]string) {
	clean := func(s string) string {
		if s == "<no value>" {
			return ""
		}
		return strings.TrimSpace(s)
	}
	switch k {
	case "docker.compose":
		d.Compose = clean(v)
	case "docker.ctr":
		f := strings.SplitN(v, "|", 11)
		if len(f) != 11 {
			return
		}
		id := clean(f[0])
		if len(id) > 12 {
			id = id[:12]
		}
		d.List = append(d.List, Container{
			ID: id, Name: strings.TrimPrefix(clean(f[1]), "/"), Image: clean(f[2]), ImageID: clean(f[3]),
			State: clean(f[4]), Project: clean(f[5]), Service: clean(f[6]), WorkDir: clean(f[7]),
			ConfigFiles: clean(f[8]), Version: clean(f[9]), Source: clean(f[10]),
		})
	case "docker.img", "docker.ref":
		key, digests, ok := strings.Cut(v, "|")
		if !ok {
			return
		}
		m := images
		if k == "docker.ref" {
			m = refs
		}
		for _, s := range strings.Split(digests, ",") {
			if s = clean(s); s != "" {
				m[clean(key)] = append(m[clean(key)], s)
			}
		}
	}
}

// carryDockerSince reporte la date de première apparition d'une nouvelle image.
func carryDockerSince(prev Docker, d *Docker, at time.Time) {
	seen := map[string]time.Time{}
	for _, c := range prev.List {
		if c.UpdateAvailable() && !c.Since.IsZero() {
			seen[c.Name+"="+c.RemoteDigest] = c.Since
		}
	}
	for i := range d.List {
		c := &d.List[i]
		if !c.UpdateAvailable() {
			c.Since = time.Time{}
			continue
		}
		if t, ok := seen[c.Name+"="+c.RemoteDigest]; ok {
			c.Since = t
		} else if c.Since.IsZero() {
			c.Since = at
		}
	}
}
