package jose

import (
	"encoding/json"
	"crypto/rsa"
	"errors"
	"math/big"
	"encoding/binary"
	"crypto/ecdsa"
	"bytes"
	cyhbase64 "cyh/encoding/base64"
)

/*
	https://tools.ietf.org/html/rfc7517#appendix-A.1
 */
type JWK struct {
	Kty string `json:"kty,omitempty"`
	Use string `json:"use,omitempty"`
	Kid string `json:"kid,omitempty"`
	Key_ops string `json:"key_ops,omitempty"`
	Alg string `json:"alg,omitempty"`
	Crv string `json:"crv,omitempty"`
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`
	D string `json:"d,omitempty"`
	P string `json:"p,omitempty"`
	Q string `json:"q,omitempty"`
	Dp string `json:"dp,omitempty"`
	Dq string `json:"dq,omitempty"`
	Qi string `json:"qi,omitempty"`
	X string `json:"x,omitempty"`
	Y string `json:"y,omitempty"`
	K string `json:"k,omitempty"`
	X5u string `json:"x5u,omitempty"`
	X5c []string `json:"x5c,omitempty"`
	X5t string `json:"x5t,omitempty"`
}
type JWKSet struct {
	Keys []JWK `json:"keys,omitempty"`
}

func (jwk_set *JWKSet) Decode(jwk_set_json []byte) (*JWKSet, error) {
	bytes_r := bytes.NewReader(jwk_set_json)
	dec := json.NewDecoder(bytes_r)

	var new_jwk_set *JWKSet
	err := dec.Decode(new_jwk_set)
	if err != nil {
		return nil, err
	}

	return new_jwk_set, nil
}

func (jwk_set *JWKSet) Encode() ([]byte, error) {
	jwk_set_json, err := json.Marshal(jwk_set)
	if err != nil {
		return nil, err
	}

	return jwk_set_json, nil
}

func (jwk_set *JWKSet) Append(jwk JWK) {
	jwk_set.Keys = append(jwk_set.Keys, jwk)
}

func (jwk_set *JWKSet) GetRSAPublicKey(index int) (*rsa.PublicKey, error) {
	var index_found = false;
	for i, _ := range jwk_set.Keys {
		if i == index {
			index_found = true
			break;
		}
	}
	if !index_found {
		return nil, errors.New("undefined key offset.")
	}

	jwk := jwk_set.Keys[index]

	if jwk.Kty != "RSA" {
		return nil, errors.New("is not RSA key. ")
	}

	modulus, err := cyhbase64.DecodeURLSafe(jwk.N)
	if err != nil {
		return nil, err
	}
	exponent, err := cyhbase64.DecodeURLSafe(jwk.E)
	if err != nil {
		return nil, err
	}
	if len(exponent) < 4 {
		new_exponent := make([]byte, 4)
		copy(new_exponent[4 - len(exponent):], exponent)
		exponent = new_exponent
	}

	key := &rsa.PublicKey{
		N: new(big.Int).SetBytes(modulus),
		E: int(binary.BigEndian.Uint32(exponent)),
	}

	return key, nil
}

func GenerateRSAJWK(kid string, alg string, use string, prv_key *rsa.PrivateKey) (*JWK, error) {
	buf_exponent := new(bytes.Buffer)
	num_exponent := uint32(prv_key.PublicKey.E)
	err_exponent := binary.Write(buf_exponent, binary.BigEndian, num_exponent)
	if err_exponent != nil {
		return nil, err_exponent
	}
	trim_buf_exponent := bytes.TrimLeft(buf_exponent.Bytes(), "\x00")

	exponent_base64 := cyhbase64.EncodeURLSafe(trim_buf_exponent)
	modulus_base64 := cyhbase64.EncodeURLSafe(prv_key.PublicKey.N.Bytes())

	var base_jwk *JWK
	base_jwk.Kid = kid
	base_jwk.Kty = "RSA"
	base_jwk.Alg = alg
	base_jwk.Use = use
	base_jwk.N = modulus_base64
	base_jwk.E = exponent_base64

	return base_jwk, nil
}

func GenerateECJWK(kid string, alg string, use string, prv_key ecdsa.PrivateKey) (*JWK, error) {
	x_base64 := cyhbase64.EncodeURLSafe(prv_key.X.Bytes())
	y_base64 := cyhbase64.EncodeURLSafe(prv_key.Y.Bytes())

	var base_jwk *JWK
	base_jwk.Kid = kid
	base_jwk.Kty = "EC"
	base_jwk.Crv = prv_key.Curve.Params().Name
	base_jwk.Alg = alg
	base_jwk.Use = use
	base_jwk.X = x_base64
	base_jwk.Y = y_base64

	return base_jwk, nil
}
