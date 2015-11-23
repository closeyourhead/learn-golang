package crypto

import (
	"errors"
	"crypto/ecdsa"
	"encoding/pem"
	"crypto/x509"
	"encoding/asn1"
	"crypto/elliptic"
	"math/big"
)

var (
	oidNamedCurveP224 = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	oidNamedCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidNamedCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidNamedCurveP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
)

type EcdsaSignature struct {
	R, S *big.Int
}

func OidFromNamedCurve(curve elliptic.Curve) (asn1.ObjectIdentifier, bool) {
	switch curve {
	case elliptic.P224():
		return oidNamedCurveP224, true
	case elliptic.P256():
		return oidNamedCurveP256, true
	case elliptic.P384():
		return oidNamedCurveP384, true
	case elliptic.P521():
		return oidNamedCurveP521, true
	}

	return nil, false
}


func LoadECPrivateKey(key []byte) (*ecdsa.PrivateKey, error) {
	parsed_key, err := LoadPrivateKey(key)
	if err != nil {
		return nil, err
	}

	var ecdsa_private_key *ecdsa.PrivateKey
	var ok bool = false
	ecdsa_private_key, ok = parsed_key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("invalid EC private key.")
	}

	return ecdsa_private_key, nil
}

func LoadECPublicKey(key []byte) (*ecdsa.PublicKey, error) {
	parsed_key, err := LoadPublicKey(key)
	if err != nil {
		return nil, err
	}

	var ecdsa_public_key *ecdsa.PublicKey
	var ok bool = false
	ecdsa_public_key, ok = parsed_key.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("invalid EC public key.")
	}

	return ecdsa_public_key, nil
}

func CreateECPrivateKeyPEM(prvkey *ecdsa.PrivateKey) ([]byte, error) {
	prv_der, err := x509.MarshalECPrivateKey(prvkey)
	if err != nil {
		return nil, err
	}
	prv_block := &pem.Block{
		Type: "EC PRIVATE KEY",
		Bytes: prv_der,
	}
	data := pem.EncodeToMemory(prv_block)

	return data, nil
}

func CreateECPublicKeyPEM(pubkey *ecdsa.PublicKey) ([]byte, error) {
	pub_der, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return nil, err
	}

	pub_block := &pem.Block{
		Type: "EC PUBLIC KEY",
		Bytes: pub_der,
	}
	data := pem.EncodeToMemory(pub_block)

	return data, nil
}

func CreateEcParametersPEM(prv *ecdsa.PrivateKey) ([]byte, error) {
	oid, is_valid_oid := OidFromNamedCurve(prv.Curve)
	if is_valid_oid != true {
		return nil, errors.New("curve not supported. " + prv.Curve.Params().Name)
	}
	oid_der, err := asn1.Marshal(oid)
	if err != nil {
		return nil, err
	}
	params_block := &pem.Block{
		Type: "EC PARAMETERS",
		Bytes: oid_der,
	}
	params_data := pem.EncodeToMemory(params_block)

	return params_data, nil
}

func EncodeSignature(r, s *big.Int) ([]byte, error) {
	return asn1.Marshal(EcdsaSignature{r, s})
}

func DecodeSignature(signature []byte) (r, s *big.Int, err error) {
	var sig EcdsaSignature

	_, err = asn1.Unmarshal(signature, &sig)
	if err != nil {
		return nil, nil, err
	}

	return sig.R, sig.S, nil
}
