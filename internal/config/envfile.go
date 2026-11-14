package config

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
)

var envKeyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// LoadEnvFile lit un fichier KEY=VALEUR (format EnvironmentFile de systemd,
// lignes « export » acceptées) et définit les variables qui ne le sont pas
// déjà : une valeur fournie par l'environnement reste prioritaire. Un fichier
// absent n'est pas une erreur si optional est vrai. Renvoie un avertissement
// si le fichier est lisible par tous.
func LoadEnvFile(path string, optional bool) (warning string, err error) {
	f, err := os.Open(path)
	if err != nil {
		if optional && errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", fmt.Errorf("fichier d'environnement : %w", err)
	}
	defer f.Close()
	if st, err := f.Stat(); err == nil && st.Mode().Perm()&0o007 != 0 {
		warning = fmt.Sprintf("%s est lisible par tous les utilisateurs (droits %o) : utilisez chmod 640 (root:patchwarden) ou 600", path, st.Mode().Perm())
	}
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		k, v, ok := strings.Cut(line, "=")
		k = strings.TrimSpace(k)
		if !ok || !envKeyRe.MatchString(k) {
			return warning, fmt.Errorf("%s, ligne %d : « NOM=valeur » attendu", path, n)
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' && v[len(v)-1] == '"' || v[0] == '\'' && v[len(v)-1] == '\'') {
			v = v[1 : len(v)-1]
		}
		if _, set := os.LookupEnv(k); !set {
			if err := os.Setenv(k, v); err != nil {
				return warning, err
			}
		}
	}
	return warning, sc.Err()
}
