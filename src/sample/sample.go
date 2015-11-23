package main

import (
	"fmt"
	"os"
	"io/ioutil"
	cyhcrypto "cyh/crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/elliptic"
)

func main () {
	prv_filename := "./ec_p256.prv"
	pub_filename := "./ec_p256.pub"
	createNewKeyPair(prv_filename, pub_filename)

	msg := []byte("hogehoge")
	signature := sign(prv_filename, msg)

	result_ok := verify(pub_filename, msg, signature)
	fmt.Println(result_ok)

	msg_ng := []byte("hogehog")
	result_ng := verify(pub_filename, msg_ng, signature)
	fmt.Println(result_ng)
}

func createNewKeyPair(prv_filename string, pub_filename string) {
	// generate and save ecdsa private key.
	new_ecprv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	new_ecprv_pem, err := cyhcrypto.CreateECPrivateKeyPEM(new_ecprv)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	err = ioutil.WriteFile(prv_filename, new_ecprv_pem, 0600)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// save ecdsa public key.
	new_ecpub_pem, err := cyhcrypto.CreateECPublicKeyPEM(&new_ecprv.PublicKey)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	err = ioutil.WriteFile(pub_filename, new_ecpub_pem, 0600)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func sign(prv_key_filename string, msg []byte) []byte {
	// load ecdsa private key from file
	prv_data, err := ioutil.ReadFile(prv_key_filename)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	ecprv, err := cyhcrypto.LoadECPrivateKey(prv_data)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// sign to message
	msg_hasher := sha256.New()
	_, _ = msg_hasher.Write(msg)
	hashed := msg_hasher.Sum(nil)
	r, s, err := ecdsa.Sign(rand.Reader, ecprv, hashed)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	signature, err := cyhcrypto.EncodeSignature(r, s)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	return signature
}

func verify(pub_key_filename string, msg []byte, signature []byte) bool {
	// load ecdsa public key from file
	pub_data, err := ioutil.ReadFile(pub_key_filename)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	ecpub, err := cyhcrypto.LoadECPublicKey(pub_data)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// verify signature
	v_msg_hasher := sha256.New()
	_, _ = v_msg_hasher.Write(msg)
	v_hashed := v_msg_hasher.Sum(nil)

	sig_r, sig_s, err := cyhcrypto.DecodeSignature(signature)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	result := ecdsa.Verify(ecpub, v_hashed, sig_r, sig_s)

	return result
}