package certs

import (
	"crypto/x509"
	"encoding/pem"
)

func CertPEM() string {
	return ca_certs
}

func CertX509() []*x509.Certificate {
	blocks := decodePEM([]*pem.Block{}, []byte(ca_certs))

	var crts []*x509.Certificate

	for _, block := range blocks {
		crt, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}

		crts = append(crts, crt)
	}

	return crts
}

func CertPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(ca_certs))

	return pool
}

func decodePEM(blocks []*pem.Block, pemBytes []byte) []*pem.Block {
	b, rest := pem.Decode(pemBytes)
	if rest != nil {
		blocks = append(blocks, b)
		return decodePEM(blocks, rest)
	}

	return blocks
}
