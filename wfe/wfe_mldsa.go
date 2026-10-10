//go:build go1.27

package wfe

import (
	"crypto/mldsa"
	"crypto/x509"

	jose "github.com/go-jose/go-jose/v4"
)

func init() {
	goodSignatureAlgorithms[x509.MLDSA44] = true
	goodSignatureAlgorithms[x509.MLDSA65] = true
	goodSignatureAlgorithms[x509.MLDSA87] = true

	goodJWSSignatureAlgorithms = append(goodJWSSignatureAlgorithms, jose.ML_DSA_44, jose.ML_DSA_65, jose.ML_DSA_87)
}

func mldsaAlgorithmForKey(key *jose.JSONWebKey) string {
	switch k := key.Key.(type) {
	case *mldsa.PublicKey:
		switch k.Parameters() {
		case mldsa.MLDSA44():
			return string(jose.ML_DSA_44)
		case mldsa.MLDSA65():
			return string(jose.ML_DSA_65)
		case mldsa.MLDSA87():
			return string(jose.ML_DSA_87)
		}
	}

	return ""
}
