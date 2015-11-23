package crypto

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

func LoadCertificate(cert []byte) (*x509.Certificate, error) {
	return x509.ParseCertificate(cert)
}

func LoadPrivateKey(key []byte) (interface{}, error) {
	block, _ := pem.Decode(key)
	if block == nil {
		return nil, errors.New("can not decode pem.")
	}

	pkcs1_key, err1 := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err1 == nil {
		return pkcs1_key, nil
	}

	pkcs8_key, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err2 == nil {
		return pkcs8_key, nil
	}

	ec_key, err3 := x509.ParseECPrivateKey(block.Bytes)
	if err3 == nil {
		return ec_key, nil
	}

	return nil, fmt.Errorf("invalid format private key. error '%s' '%s' '%s'", err1, err2, err3)
}

func LoadPublicKey(key []byte) (interface{}, error) {
	block, _ := pem.Decode(key)
	if block == nil {
		return nil, errors.New("can not decode public key pem.")
	}

	pkix_key, err1 := x509.ParsePKIXPublicKey(block.Bytes)
	if err1 == nil {
		return pkix_key, nil
	}

	cert, err2 := x509.ParseCertificate(block.Bytes)
	if err2 == nil {
		return cert.PublicKey, nil
	}

	return nil, fmt.Errorf("invalid format public key, error '%s' '%s'", err1, err2)
}
