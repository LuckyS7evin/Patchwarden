// Package tlspin construit la configuration TLS des clients HTTP de
// PatchWarden : épinglage d'empreinte (certificats auto-signés), autorité
// dédiée, ou autorités du système.
package tlspin

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/LuckyS7evin/patchwarden/internal/config"
)

// Config renvoie la configuration TLS : épinglage si fingerprint est donné,
// autorité lue dans caFile sinon, autorités du système si les deux sont vides.
func Config(fingerprint, caFile string) (*tls.Config, error) {
	c := &tls.Config{MinVersion: tls.VersionTLS12}
	switch {
	case fingerprint != "":
		want, err := config.ParseFingerprint(fingerprint)
		if err != nil {
			return nil, err
		}
		// Épinglage : la chaîne n'est pas vérifiée (certificat auto-signé),
		// mais l'empreinte du certificat présenté doit correspondre exactement.
		// VerifyConnection est appelé même avec InsecureSkipVerify.
		c.InsecureSkipVerify = true //nolint:gosec // remplacé par l'épinglage ci-dessous
		c.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("aucun certificat présenté")
			}
			got := sha256.Sum256(cs.PeerCertificates[0].Raw)
			if subtle.ConstantTimeCompare(got[:], want) != 1 {
				return fmt.Errorf("empreinte du certificat inattendue (%s) : vérifiez fingerprint", Format(got[:]))
			}
			return nil
		}
	case caFile != "":
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s ne contient aucun certificat PEM", caFile)
		}
		c.RootCAs = pool
	}
	return c, nil
}

// Format écrit une empreinte au format AA:BB:…
func Format(b []byte) string {
	parts := make([]string, len(b))
	for i, x := range b {
		parts[i] = fmt.Sprintf("%02X", x)
	}
	return strings.Join(parts, ":")
}
