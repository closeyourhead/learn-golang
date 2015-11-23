package crypto

import (
	"errors"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

func LoadRSAPrivateKey(key []byte) (*rsa.PrivateKey, error) {
	parsed_key, err := LoadPrivateKey(key)
	if err != nil {
		return nil, err
	}

	var rsa_private_key *rsa.PrivateKey
	var ok bool = false
	rsa_private_key, ok = parsed_key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("invalid RSA private key.")
	}

	return rsa_private_key, nil
}

func LoadRSAPublicKey(key []byte) (*rsa.PublicKey, error) {
	parsed_key, err := LoadPublicKey(key)
	if err != nil {
		return nil, err
	}

	var rsa_public_key *rsa.PublicKey
	var ok bool = false
	rsa_public_key, ok = parsed_key.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("invalid RSA public key.")
	}

	return rsa_public_key, nil
}

func CreateRSAPrivateKeyPEM(prvkey *rsa.PrivateKey) ([]byte, error) {
	der := x509.MarshalPKCS1PrivateKey(prvkey)
	data := pem.EncodeToMemory(
		&pem.Block{
			Type: "RSA PRIVATE KEY",
			Bytes: der,
		},
	)

	return data, nil
}

func CreateRSAPublicKeyPEM(pubkey *rsa.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return nil, err
	}
	data := pem.EncodeToMemory(
		&pem.Block{
			Type: "RSA PUBLIC KEY",
			Bytes: der,
		},
	)

	return data, nil
}
