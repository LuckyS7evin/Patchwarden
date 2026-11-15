package detect

import (
	"strconv"
	"strings"
	"time"
)

// Snapshot est un snapshot créé par PatchWarden (nom pw-…).
type Snapshot struct {
	Name        string    `json:"name"`
	Time        time.Time `json:"time"`
	Description string    `json:"description,omitempty"`
}

// StorageUse est le remplissage d'un stockage utilisé par l'invité.
type StorageUse struct {
	Name    string  `json:"name"`
	Type    string  `json:"type"`
	UsedPct float64 `json:"used_pct"` // -1 : inconnu
}

// SnapInfo décrit les snapshots d'un invité, lus sur le nœud par le wrapper.
type SnapInfo struct {
	Known    bool         `json:"known"`
	Possible bool         `json:"possible"`
	Storages []StorageUse `json:"storages,omitempty"`
	// Binds : points de montage liés à l'hôte, absents des snapshots.
	Binds int        `json:"binds,omitempty"`
	PW    []Snapshot `json:"pw,omitempty"`
	// Other : snapshots créés hors de PatchWarden (jamais touchés).
	Other int `json:"other,omitempty"`
}

// ParseSnap lit le dernier bloc snap.* d'une sortie du wrapper.
func ParseSnap(lines []string) (SnapInfo, bool) {
	var s SnapInfo
	found := false
	for _, l := range lines {
		k, v, ok := strings.Cut(l, "=")
		if !ok || !strings.HasPrefix(k, "snap.") {
			continue
		}
		switch k {
		case "snap.info":
			s, found = SnapInfo{Known: true}, true
		case "snap.possible":
			s.Possible = v == "1"
		case "snap.storage":
			f := strings.Fields(v)
			if len(f) == 3 {
				pct, err := strconv.ParseFloat(f[2], 64)
				if err != nil {
					pct = -1
				}
				s.Storages = append(s.Storages, StorageUse{Name: f[0], Type: f[1], UsedPct: pct})
			}
		case "snap.bind":
			s.Binds = atoi(v)
		case "snap.pw":
			f := strings.SplitN(v, " ", 3)
			if len(f) >= 2 {
				sn := Snapshot{Name: f[0]}
				if ts, err := strconv.ParseInt(f[1], 10, 64); err == nil && ts > 0 {
					sn.Time = time.Unix(ts, 0)
				}
				if len(f) == 3 {
					sn.Description = f[2]
				}
				s.PW = append(s.PW, sn)
			}
		case "snap.other":
			s.Other = atoi(v)
		}
	}
	return s, found
}

// Fullest renvoie le stockage le plus rempli (UsedPct -1 si un remplissage est inconnu).
func (s SnapInfo) Fullest() (StorageUse, bool) {
	var best StorageUse
	if len(s.Storages) == 0 {
		return best, false
	}
	best = s.Storages[0]
	for _, st := range s.Storages[1:] {
		if st.UsedPct < 0 || (best.UsedPct >= 0 && st.UsedPct > best.UsedPct) {
			best = st
		}
	}
	return best, true
}

// Has dit si un snapshot PatchWarden de ce nom est connu.
func (s SnapInfo) Has(name string) (Snapshot, bool) {
	for _, sn := range s.PW {
		if sn.Name == name {
			return sn, true
		}
	}
	return Snapshot{}, false
}

// UpdateSnap remplace les informations de snapshots d'un invité déjà détecté
// (après un snapshot, une suppression ou un retour arrière).
func (s *Store) UpdateSnap(key string, info SnapInfo) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.m[key]
	if !ok {
		return nil
	}
	r.Snap = info
	s.m[key] = r
	return s.saveLocked()
}
