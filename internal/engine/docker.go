package engine

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/LuckyS7evin/patchwarden/internal/detect"
	"github.com/LuckyS7evin/patchwarden/internal/inventory"
	"github.com/LuckyS7evin/patchwarden/internal/jobs"
	"github.com/LuckyS7evin/patchwarden/internal/portainer"
	"github.com/LuckyS7evin/patchwarden/internal/registry"
)

// ActDocker : mise à jour des conteneurs Docker (snapshot nommé pw-…-docker).
const ActDocker Action = "docker"

// Portainer est l'accès d'une instance Portainer, vu par le moteur.
type Portainer interface {
	Endpoints(ctx context.Context) ([]portainer.Endpoint, error)
	Containers(ctx context.Context, endpoint int) ([]portainer.Container, error)
	ProjectContainers(ctx context.Context, endpoint int, project string) ([]portainer.Container, error)
	Stacks(ctx context.Context) ([]portainer.Stack, error)
	Stack(ctx context.Context, id int) (portainer.Stack, error)
	StackFile(ctx context.Context, id int) (string, error)
	Redeploy(ctx context.Context, s portainer.Stack) error
}

// dockerHosts garde en cache, par instance Portainer, les conteneurs de
// chaque environnement (pour retrouver l'environnement d'un invité).
type dockerHosts struct {
	mu sync.Mutex
	m  map[string]hostsEntry
}

type hostsEntry struct {
	at  time.Time
	eps map[int]map[string]bool // environnement → identifiants courts des conteneurs
	err error
}

var hostCacheMu sync.Mutex

func (e *Engine) hostCache() *dockerHosts {
	hostCacheMu.Lock()
	defer hostCacheMu.Unlock()
	if e.hosts == nil {
		e.hosts = &dockerHosts{m: map[string]hostsEntry{}}
	}
	return e.hosts
}

var composeProjectRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// enrichDocker compare les images aux registres, associe les stacks à leur
// instance Portainer et indique, groupe par groupe, si PatchWarden peut les
// mettre à jour. Les erreurs sont journalisées sans faire échouer la détection.
func (e *Engine) enrichDocker(ctx context.Context, g inventory.Guest, res *detect.Result, log jobs.Logger) {
	d := &res.DockerInfo
	if !res.Docker || len(d.List) == 0 {
		return
	}
	log(false, fmt.Sprintf("▶ conteneurs Docker : %d (docker compose %s)", len(d.List), orDash(d.Compose)))
	if e.Registry != nil {
		e.checkImages(ctx, d, log)
		d.Checked = true
	} else {
		log(false, "  comparaison aux registres désactivée ([docker] registry_check = false)")
	}
	d.BuildGroups()
	e.linkPortainer(ctx, d, log)
	e.dockerBlockers(d)
	for _, gr := range d.Groups {
		line := fmt.Sprintf("  %s : %d conteneur(s)", gr.Label(), len(gr.Containers))
		if gr.Updates > 0 {
			line += fmt.Sprintf(", %d nouvelle(s) image(s)", gr.Updates)
		}
		if gr.Blocker != "" {
			line += " · mise à jour depuis PatchWarden impossible : " + gr.Blocker
		}
		log(false, line)
	}
	for _, w := range d.Watchtower {
		log(true, "⚠ Watchtower démarré ("+w+") : il met les images à jour de son côté ; arrêtez-le pour que PatchWarden reste juste")
	}
}

func (e *Engine) checkImages(ctx context.Context, d *detect.Docker, log jobs.Logger) {
	for i := range d.List {
		c := &d.List[i]
		ref, err := registry.Parse(c.Image)
		if err != nil {
			c.Check, c.CheckText = detect.CheckUnknown, err.Error()
			continue
		}
		c.ChangelogURL = registry.ChangelogURL(ref, c.Source)
		switch {
		case ref.Digest != "":
			c.Check, c.CheckText = detect.CheckPinned, "image fixée par empreinte (@sha256) : aucune mise à jour à suivre"
		case len(c.Digests) == 0:
			c.Check, c.CheckText = detect.CheckLocal, "image construite sur place ou chargée sans registre : rien à comparer"
		default:
			remote, err := e.Registry.Digest(ctx, ref)
			if err != nil {
				c.Check, c.CheckText = detect.CheckUnknown, err.Error()
				break
			}
			c.RemoteDigest = remote
			if hasDigest(c.Digests, ref, remote) {
				c.Check, c.CheckText = detect.CheckOK, "à jour pour le tag "+ref.Tag
			} else {
				c.Check, c.CheckText = detect.CheckUpdate, "nouvelle image publiée pour le tag "+ref.Tag
			}
		}
		if ref.Tag != "" && registry.IsVersionTag(ref.Tag) {
			if tags, err := e.Registry.Tags(ctx, ref); err == nil {
				c.NewTag = registry.Newer(ref.Tag, tags)
			} else {
				log(false, fmt.Sprintf("  %s : liste des tags indisponible (%v)", c.Name, err))
			}
		}
		line := fmt.Sprintf("  %s (%s) : %s", c.Name, ref.Short()+tagSuffix(ref), c.CheckText)
		if c.NewTag != "" {
			line += " · version plus récente publiée : " + c.NewTag + " (tag non modifié)"
		}
		log(false, line)
	}
}

func tagSuffix(r registry.Ref) string {
	if r.Tag != "" {
		return ":" + r.Tag
	}
	return "@" + r.Digest
}

// hasDigest dit si l'une des empreintes locales (« dépôt@sha256:… ») est
// l'empreinte publiée ; celles d'un autre dépôt sont ignorées, sauf s'il n'y a
// que celles-là.
func hasDigest(local []string, ref registry.Ref, remote string) bool {
	matched := false
	for _, l := range local {
		name, dg, ok := strings.Cut(l, "@")
		if !ok {
			continue
		}
		if r, err := registry.Parse(name); err == nil && registry.Same(r, ref) {
			matched = true
			if dg == remote {
				return true
			}
		}
	}
	if matched {
		return false
	}
	for _, l := range local {
		if strings.HasSuffix(l, "@"+remote) {
			return true
		}
	}
	return false
}

// linkPortainer retrouve l'instance et l'environnement Portainer de l'invité
// (conteneurs en commun), puis chaque stack.
func (e *Engine) linkPortainer(ctx context.Context, d *detect.Docker, log jobs.Logger) {
	need := false
	for _, gr := range d.Groups {
		if gr.Kind == detect.GroupPortainer {
			need = true
		}
	}
	if !need || len(e.Portainers) == 0 {
		return
	}
	ids := map[string]bool{}
	for _, c := range d.List {
		ids[c.ID] = true
	}
	inst, ep := "", 0
	for _, name := range e.portainerNames() {
		hosts, err := e.portainerHosts(ctx, name)
		if err != nil {
			log(true, fmt.Sprintf("⚠ Portainer %s : %v", name, err))
			continue
		}
		best := 0
		for id, set := range hosts {
			n := 0
			for c := range ids {
				if set[c] {
					n++
				}
			}
			if n > best {
				best, inst, ep = n, name, id
			}
		}
		if best > 0 {
			break
		}
	}
	if inst == "" {
		log(false, "  aucun environnement Portainer ne contient ces conteneurs")
		return
	}
	log(false, fmt.Sprintf("  environnement Portainer : %s, n° %d", inst, ep))
	stacks, err := e.Portainers[inst].Stacks(ctx)
	if err != nil {
		log(true, fmt.Sprintf("⚠ Portainer %s : liste des stacks : %v", inst, err))
		for i := range d.Groups {
			if d.Groups[i].Kind == detect.GroupPortainer {
				d.Groups[i].Instance, d.Groups[i].EndpointID = inst, ep
			}
		}
		return
	}
	for i := range d.Groups {
		gr := &d.Groups[i]
		if gr.Kind != detect.GroupPortainer {
			continue
		}
		gr.Instance, gr.EndpointID = inst, ep
		found := false
		for _, s := range stacks {
			if s.ID != gr.StackID {
				continue
			}
			found = true
			gr.Git = s.Git()
			switch {
			case s.EndpointID != ep:
				gr.Blocker = fmt.Sprintf("la stack n° %d de Portainer %s appartient à un autre environnement (n° %d)", s.ID, inst, s.EndpointID)
			case s.Type != 2:
				gr.Blocker = "stack Portainer qui n'est pas de type docker compose (swarm, kubernetes)"
			case s.Status != 1:
				gr.Blocker = "stack arrêtée dans Portainer : rien n'est relancé"
			case !strings.EqualFold(s.Name, gr.Name):
				gr.Warnings = append(gr.Warnings, fmt.Sprintf("nom de la stack dans Portainer : « %s » (projet compose : « %s »)", s.Name, gr.Name))
			}
			break
		}
		if !found && gr.Blocker == "" {
			gr.Blocker = fmt.Sprintf("stack n° %d introuvable dans Portainer %s (droits du jeton ?)", gr.StackID, inst)
		}
	}
}

func (e *Engine) portainerNames() []string {
	if len(e.PortainerOrder) > 0 {
		return e.PortainerOrder
	}
	out := make([]string, 0, len(e.Portainers))
	for n := range e.Portainers {
		out = append(out, n)
	}
	return out
}

// portainerHosts renvoie les conteneurs de chaque environnement joignable
// d'une instance (cache de 2 minutes).
func (e *Engine) portainerHosts(ctx context.Context, name string) (map[int]map[string]bool, error) {
	hc := e.hostCache()
	hc.mu.Lock()
	if h, ok := hc.m[name]; ok && time.Since(h.at) < 2*time.Minute {
		hc.mu.Unlock()
		return h.eps, h.err
	}
	hc.mu.Unlock()
	p := e.Portainers[name]
	eps, err := p.Endpoints(ctx)
	out := map[int]map[string]bool{}
	if err == nil {
		for _, ep := range eps {
			if ep.Status != 1 {
				continue
			}
			cs, cerr := p.Containers(ctx, ep.ID)
			if cerr != nil {
				continue
			}
			set := map[string]bool{}
			for _, c := range cs {
				id := c.ID
				if len(id) > 12 {
					id = id[:12]
				}
				set[id] = true
			}
			out[ep.ID] = set
		}
	}
	hc.mu.Lock()
	hc.m[name] = hostsEntry{at: time.Now(), eps: out, err: err}
	hc.mu.Unlock()
	return out, err
}

// dockerBlockers indique, groupe par groupe, pourquoi PatchWarden ne peut pas
// le mettre à jour, et ce qu'il faut savoir avant.
func (e *Engine) dockerBlockers(d *detect.Docker) {
	for i := range d.Groups {
		gr := &d.Groups[i]
		var kinds []string
		for _, n := range gr.Containers {
			if c, ok := d.Container(n); ok && c.Kind != "" {
				kinds = append(kinds, c.Kind)
			}
		}
		has := func(k string) bool {
			for _, x := range kinds {
				if x == k {
					return true
				}
			}
			return false
		}
		switch gr.Kind {
		case detect.GroupRun:
			if gr.Blocker == "" {
				if has("portainer") {
					gr.Blocker = "Portainer lui-même (docker run) : à mettre à jour à la main, en suivant sa documentation"
				} else {
					gr.Blocker = "lancé par docker run : ses options de création sont inconnues, PatchWarden ne le recrée pas (passez-le en docker compose, ou mettez-le à jour à la main)"
				}
			}
		case detect.GroupPortainer:
			switch {
			case gr.Blocker != "":
			case len(e.Portainers) == 0:
				gr.Blocker = "stack Portainer : déclarez l'instance dans une section [[portainer]] (URL et jeton d'accès) pour la mettre à jour"
			case gr.Instance == "":
				gr.Blocker = "environnement Portainer de cet invité introuvable dans les instances [[portainer]] déclarées"
			case has("agent"):
				gr.Blocker = "la stack contient l'agent Portainer : son re-déploiement couperait Portainer en cours de route ; mettez-le à jour à la main"
			case has("portainer"):
				gr.Blocker = "la stack contient Portainer lui-même : à mettre à jour à la main"
			}
			if gr.Stopped > 0 {
				gr.Warnings = append(gr.Warnings, fmt.Sprintf("%d conteneur(s) arrêté(s) dans cette stack : le re-déploiement par Portainer les redémarrera", gr.Stopped))
			}
			if gr.Git {
				gr.Warnings = append(gr.Warnings, "stack déployée depuis Git : Portainer relit la branche configurée et peut appliquer de nouveaux commits")
			}
		case detect.GroupCompose:
			switch {
			case gr.Blocker != "":
			case d.Compose == "":
				gr.Blocker = "docker compose v2 absent de l'invité (commande « docker compose »)"
			case gr.WorkDir == "":
				gr.Blocker = "dossier du projet inconnu (conteneurs créés par une ancienne version de docker-compose)"
			case !composeProjectRe.MatchString(gr.Name):
				gr.Blocker = "nom de projet compose inattendu : " + gr.Name
			case gr.Stopped == len(gr.Containers):
				gr.Blocker = "aucun conteneur du projet n'est démarré"
			}
			if gr.Stopped > 0 && gr.Stopped < len(gr.Containers) {
				gr.Warnings = append(gr.Warnings, fmt.Sprintf("%d conteneur(s) arrêté(s) : laissés tels quels (seuls les services démarrés sont mis à jour)", gr.Stopped))
			}
		}
		if len(d.Watchtower) > 0 {
			gr.Warnings = append(gr.Warnings, "Watchtower est démarré ("+strings.Join(d.Watchtower, ", ")+") : il peut mettre à jour ces conteneurs en même temps")
		}
	}
}

// DockerPlan décrit une mise à jour des conteneurs d'un invité.
type DockerPlan struct {
	Guest    inventory.Guest
	Det      *detect.Result
	Groups   []detect.DockerGroup
	Steps    []string
	Warnings []string
	Blockers []string
	// Newer : versions plus récentes publiées sous un autre tag (information).
	Newer    []string
	NeedName bool
	Snap     SnapPlan
}

// OK indique que la mise à jour est possible.
func (p DockerPlan) OK() bool { return len(p.Blockers) == 0 }

// Keys renvoie les clés des groupes retenus.
func (p DockerPlan) Keys() []string {
	out := make([]string, len(p.Groups))
	for i, g := range p.Groups {
		out[i] = g.Key
	}
	return out
}

// PlanDocker construit le plan de mise à jour des groupes demandés (aucun :
// tous ceux qui ont une nouvelle image et que PatchWarden sait traiter).
func (e *Engine) PlanDocker(g inventory.Guest, keys []string) DockerPlan {
	p := DockerPlan{Guest: g, NeedName: g.Critical}
	if err := e.CanDetect(g); err != nil {
		p.Blockers = append(p.Blockers, err.Error())
		return p
	}
	det, ok := e.Store.Get(target(g).Key())
	if !ok {
		p.Blockers = append(p.Blockers, "aucune détection : lancez d'abord « Détecter les mises à jour »")
		return p
	}
	p.Det = &det
	if det.Special == "pve" {
		p.Blockers = append(p.Blockers, "Proxmox VE est installé dans cet invité : PatchWarden n'y agit pas")
		return p
	}
	if det.Special != "" {
		p.NeedName = true
	}
	if age := time.Since(det.At); age > MaxDetectionAge {
		p.Blockers = append(p.Blockers, fmt.Sprintf("dernière détection trop ancienne (%s) : relancez-la", age.Round(time.Hour)))
	}
	d := det.DockerInfo
	if !det.Docker || len(d.List) == 0 {
		p.Blockers = append(p.Blockers, "aucun conteneur Docker détecté dans cet invité")
		return p
	}
	if !d.Checked {
		p.Blockers = append(p.Blockers, "images non comparées aux registres : relancez une détection (comparaison activée, wrapper v10 requis)")
		return p
	}
	if len(keys) == 0 {
		p.Groups = d.UpdatableGroups()
		if len(p.Groups) == 0 {
			p.Blockers = append(p.Blockers, "aucune stack ni aucun projet compose à mettre à jour")
		}
	} else {
		seen := map[string]bool{}
		for _, k := range keys {
			if seen[k] {
				continue
			}
			seen[k] = true
			gr, ok := d.Group(k)
			switch {
			case !ok:
				p.Blockers = append(p.Blockers, "groupe de conteneurs inconnu : "+k+" (relancez une détection)")
			case gr.Blocker != "":
				p.Blockers = append(p.Blockers, gr.Label()+" : "+gr.Blocker)
			case gr.Updates == 0:
				p.Blockers = append(p.Blockers, gr.Label()+" : images à jour")
			default:
				p.Groups = append(p.Groups, gr)
			}
		}
	}
	for _, gr := range p.Groups {
		var imgs []string
		for _, n := range gr.Containers {
			c, _ := d.Container(n)
			if c.Running() && c.UpdateAvailable() {
				imgs = append(imgs, c.Name+" ("+c.Image+")")
			}
		}
		switch gr.Kind {
		case detect.GroupPortainer:
			p.Steps = append(p.Steps, fmt.Sprintf("%s : re-déploiement par Portainer %s (stack n° %d) avec téléchargement des images, même fichier et mêmes variables ; nouvelles images : %s", gr.Label(), gr.Instance, gr.StackID, strings.Join(imgs, ", ")))
		case detect.GroupCompose:
			p.Steps = append(p.Steps, fmt.Sprintf("%s (%s) : docker compose pull puis up -d des services démarrés ; nouvelles images : %s", gr.Label(), gr.WorkDir, strings.Join(imgs, ", ")))
		}
		for _, w := range gr.Warnings {
			p.Warnings = append(p.Warnings, gr.Label()+" : "+w)
		}
	}
	for _, c := range d.List {
		if c.NewTag != "" {
			p.Newer = append(p.Newer, fmt.Sprintf("%s : %s publiée (tag actuel %s, non modifié)", c.Name, c.NewTag, c.Tag()))
		}
	}
	if det.RootUsedPct >= 85 {
		p.Warnings = append(p.Warnings, fmt.Sprintf("disque / plein à %d %% : le téléchargement des images peut échouer faute de place", det.RootUsedPct))
	}
	if g.Critical {
		p.Warnings = append(p.Warnings, "invité critique ("+g.CriticalReason+") : saisissez son nom pour confirmer")
	}
	p.Steps = append(p.Steps, "anciennes images laissées sur le disque (docker image prune à faire vous-même si besoin)", "détection après la mise à jour, pour vérifier le résultat")
	sp := Plan{Action: ActDocker, Guest: g, Det: &det}
	e.planSnapshot(&sp, det)
	p.Snap = sp.Snap
	p.Warnings = append(p.Warnings, sp.Warnings...)
	return p
}

// ExecuteDocker lance la mise à jour des conteneurs (ou sa simulation).
func (e *Engine) ExecuteDocker(g inventory.Guest, keys []string, dryRun bool, user string, confirmed bool, typedName string, snapshot bool) (jobs.Job, error) {
	p := e.PlanDocker(g, keys)
	if !p.OK() {
		return jobs.Job{}, errors.New(p.Blockers[0])
	}
	if snapshot && !p.Snap.Possible {
		return jobs.Job{}, errors.New("snapshot impossible : " + p.Snap.Why)
	}
	if !dryRun {
		if !confirmed {
			return jobs.Job{}, fmt.Errorf("%w : cochez la case de confirmation", ErrConfirm)
		}
		if p.NeedName && strings.TrimSpace(typedName) != g.Name {
			return jobs.Job{}, fmt.Errorf("%w : saisissez exactement le nom de l'invité (%s)", ErrConfirm, g.Name)
		}
	}
	return e.Jobs.Submit(jobs.KindDocker, target(g), dryRun, user, e.dockerFunc(p, dryRun, snapshot, user))
}

func (e *Engine) dockerFunc(p DockerPlan, dryRun, snapshot bool, user string) jobs.Func {
	g := p.Guest
	return func(ctx context.Context, job jobs.Job, log jobs.Logger) (_ string, err error) {
		taken := ""
		defer func() {
			if err != nil && taken != "" {
				err = fmt.Errorf("%w · snapshot %s pris avant la mise à jour : retour arrière possible depuis la page de l'invité", err, taken)
			}
		}()
		if dryRun {
			log(false, "SIMULATION : aucun conteneur ne sera modifié")
		}
		log(false, fmt.Sprintf("Plan « conteneurs Docker » pour %s %d (%s) sur %s :", guestNoun(g), g.VMID, g.Name, g.Node))
		if snapshot {
			log(false, "  0. snapshot avant toute modification ; s'il échoue, la mise à jour est annulée")
		} else {
			log(false, "  0. pas de snapshot")
		}
		for i, s := range p.Steps {
			log(false, fmt.Sprintf("  %d. %s", i+1, s))
		}
		for _, w := range p.Warnings {
			log(false, "  ⚠ "+w)
		}
		for _, n := range p.Newer {
			log(false, "  ℹ "+n)
		}
		var summary []string
		if snapshot {
			sp := Plan{Action: ActDocker, Guest: g, Det: p.Det, CSNote: "Docker : " + groupNames(p.Groups)}
			name, err := e.takeSnapshot(ctx, sp, dryRun, user, log)
			if err != nil {
				if dryRun {
					return "", fmt.Errorf("le snapshot serait refusé : %w", err)
				}
				return "", fmt.Errorf("mise à jour annulée, rien n'a été modifié : snapshot impossible : %w", err)
			}
			if dryRun {
				summary = append(summary, "snapshot possible")
			} else {
				taken = name
				summary = append(summary, "snapshot "+name)
			}
		}
		done := 0
		for _, gr := range p.Groups {
			var gerr error
			switch gr.Kind {
			case detect.GroupPortainer:
				gerr = e.redeployStack(ctx, gr, updatedContainers(p.Det, gr), dryRun, log)
			case detect.GroupCompose:
				gerr = e.composeUpdate(ctx, g, gr, dryRun, log)
			}
			if gerr != nil {
				if done > 0 {
					summary = append(summary, fmt.Sprintf("%d groupe(s) mis à jour avant l'échec", done))
				}
				return strings.Join(summary, " · "), fmt.Errorf("%s : %w", gr.Label(), gerr)
			}
			done++
			if dryRun {
				summary = append(summary, gr.Label()+" : simulation réussie")
			} else {
				summary = append(summary, gr.Label()+" : mise à jour")
			}
		}
		if !dryRun {
			res, err := e.afterOp(ctx, g, p.Det, job, log)
			if err != nil {
				return strings.Join(summary, " · "), err
			}
			summary = append(summary, "après : "+summarize(res), "vérification réussie")
		}
		return strings.Join(summary, " · "), nil
	}
}

// updatedContainers : conteneurs démarrés d'un groupe qui ont une nouvelle
// image (nom → identifiant court actuel).
func updatedContainers(det *detect.Result, gr detect.DockerGroup) map[string]string {
	out := map[string]string{}
	if det == nil {
		return out
	}
	for _, n := range gr.Containers {
		if c, ok := det.DockerInfo.Container(n); ok && c.Running() && c.UpdateAvailable() {
			out[n] = c.ID
		}
	}
	return out
}

func groupNames(gs []detect.DockerGroup) string {
	n := make([]string, len(gs))
	for i, g := range gs {
		n[i] = g.Name
	}
	return strings.Join(n, ", ")
}

func guestNoun(g inventory.Guest) string {
	if g.Type == "qemu" {
		return "VM"
	}
	return "CT"
}

// redeployStack re-déploie une stack Portainer (simulation : vérifications seules).
func (e *Engine) redeployStack(ctx context.Context, gr detect.DockerGroup, want map[string]string, dryRun bool, log jobs.Logger) error {
	p, ok := e.Portainers[gr.Instance]
	if !ok {
		return fmt.Errorf("instance Portainer %q absente de la configuration", gr.Instance)
	}
	log(false, fmt.Sprintf("▶ Portainer %s : stack n° %d (%s)", gr.Instance, gr.StackID, gr.Name))
	s, err := p.Stack(ctx, gr.StackID)
	if err != nil {
		return err
	}
	switch {
	case s.EndpointID != gr.EndpointID:
		return fmt.Errorf("la stack appartient désormais à l'environnement n° %d (attendu : %d) : relancez une détection", s.EndpointID, gr.EndpointID)
	case s.Type != 2:
		return errors.New("stack qui n'est pas de type docker compose")
	case s.Status != 1:
		return errors.New("stack arrêtée dans Portainer : rien n'est relancé")
	}
	if s.Git() {
		log(false, fmt.Sprintf("  stack Git : %s (référence %s)", s.GitConfig.URL, orDash(s.GitConfig.ReferenceName)))
	} else {
		f, err := p.StackFile(ctx, s.ID)
		if err != nil {
			return err
		}
		log(false, fmt.Sprintf("  fichier de la stack lu (%d lignes), %d variable(s) d'environnement reprises telles quelles", strings.Count(f, "\n")+1, len(s.Env)))
	}
	if dryRun {
		log(false, "  simulation : re-déploiement non lancé")
		return nil
	}
	log(false, "  re-déploiement avec téléchargement des images (pullImage), sans suppression (prune désactivé)")
	start := time.Now()
	stop := make(chan struct{})
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				log(false, fmt.Sprintf("  … re-déploiement en cours (%s)", time.Since(start).Round(time.Second)))
			}
		}
	}()
	err = p.Redeploy(ctx, s)
	close(stop)
	if err != nil {
		return err
	}
	// Portainer peut répondre avant la fin du re-déploiement : attendre que
	// les conteneurs soient recréés, sinon la détection de fin verrait un état
	// intermédiaire (conteneur temporaire « <id>_nom », stack « arrêtée »).
	if err := e.waitStack(ctx, p, s.EndpointID, gr.Name, want, log); err != nil {
		return err
	}
	log(false, fmt.Sprintf("  stack re-déployée en %s", time.Since(start).Round(time.Second)))
	return nil
}

var tempContainerRe = regexp.MustCompile(`^[0-9a-f]{12}_`)

// Délais du suivi d'un re-déploiement (modifiables pour les tests).
var (
	stackPoll    = 5 * time.Second
	stackSettle  = 60 * time.Second
	stackTimeout = 15 * time.Minute
)

// waitStack attend la fin d'un re-déploiement : chaque conteneur qui avait
// une nouvelle image (want : nom → ancien identifiant court) est recréé et
// démarré, et il ne reste aucun conteneur temporaire de docker compose. Si
// une image téléchargée se révèle identique (rien n'est recréé), l'état
// stable depuis une minute suffit.
func (e *Engine) waitStack(ctx context.Context, p Portainer, endpoint int, project string, want map[string]string, log jobs.Logger) error {
	start, lastLog, stable := time.Now(), time.Now(), 0
	for {
		cs, err := p.ProjectContainers(ctx, endpoint, project)
		if err == nil {
			temp, running := false, map[string]string{}
			for _, c := range cs {
				n := c.Name()
				if tempContainerRe.MatchString(n) {
					temp = true
				}
				if c.State == "running" {
					running[n] = c.ID
				}
			}
			recreated, up := true, true
			for name, old := range want {
				id, ok := running[name]
				if !ok {
					up, recreated = false, false
				} else if strings.HasPrefix(id, old) {
					recreated = false
				}
			}
			switch {
			case !temp && recreated:
				return nil
			case !temp && up && time.Since(start) >= stackSettle:
				if stable++; stable >= 2 {
					log(false, "  aucun conteneur recréé : les images téléchargées sont identiques à celles en place")
					return nil
				}
			default:
				stable = 0
			}
		}
		if time.Since(start) > stackTimeout {
			return fmt.Errorf("Portainer a accepté le re-déploiement, mais les conteneurs ne sont pas recréés après %s : vérifiez la stack dans Portainer", stackTimeout)
		}
		if time.Since(lastLog) >= 30*time.Second {
			log(false, fmt.Sprintf("  … attente des conteneurs recréés (%s)", time.Since(start).Round(time.Second)))
			lastLog = time.Now()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(stackPoll):
		}
	}
}

// composeUpdate met à jour un projet compose par le wrapper.
func (e *Engine) composeUpdate(ctx context.Context, g inventory.Guest, gr detect.DockerGroup, dryRun bool, log jobs.Logger) error {
	if !composeProjectRe.MatchString(gr.Name) {
		return errors.New("nom de projet compose inattendu")
	}
	dry := "0"
	if dryRun {
		dry = "1"
	}
	cmd := verb(g, "docker-compose") + " " + strconv.Itoa(g.VMID) + " " + gr.Name + " " + dry
	log(false, "▶ "+cmd)
	out, errs, code, err := e.run(ctx, g.Node, cmd, log)
	if err != nil {
		return connLost(err, out)
	}
	return explainCompose(code, errs, out)
}

func explainCompose(code int, errs, out []string) error {
	if code >= 60 && code <= 68 {
		msg := strings.TrimPrefix(lastMatching(out, "PW-ERREUR: "), "PW-ERREUR: ")
		return fmt.Errorf("%s (code %d)", msg, code)
	}
	return explainExit(code, errs)
}
