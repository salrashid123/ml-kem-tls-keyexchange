package main

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"fmt"
	"log"
	"os"
)

/*

Simple demo that shows how the TLS X25519MLKEM768 key exchange is done by hand

 https://www.ietf.org/archive/id/draft-kwiatkowski-tls-ecdhe-mlkem-02.html

https://www.netmeister.org/blog/tls-hybrid-kex.html
https://cryptopedia.dev/posts/kyber/

What this demo will do is exchange a shared key using quantum-safe X25519MLKEM768

between the client and server and arrive at the same shared key on both ends which involves both ML-KEM and X25519

*/

func main() {

	// 1. Client creates ECDH key and get its PublicKey bytes
	// X25518 ECDH
	clientEC, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	ecClientPublicBytes := clientEC.PublicKey().Bytes()

	// generate KEM and get its the encapsulation keys' bytes
	clientKE, err := mlkem.GenerateKey768()
	if err != nil {
		log.Fatal(err)
	}
	kemClientPublicBytes := clientKE.EncapsulationKey().Bytes()

	// When the X25519MLKEM768 group is negotiated, the client's key_exchange value is the concatenation of
	// the client's ML-KEM-768 encapsulation key and the client's X25519 ephemeral share. The size of the
	//  client share is 1216 bytes (1184 bytes for the ML-KEM part and 32 bytes for X25519)

	// fmt.Printf("kem len(%d)\n", len(kemClientPublicBytes))  // 1184
	// fmt.Printf("ec len(%d)\n", len(ecClientPublicBytes))  // 32
	// fmt.Fprintf(os.Stdout, "KeyExchange: Client => Server: kemClientPublic (%x) || ecClientPublic (%x)\n", kemClientPublicBytes, ecClientPublicBytes)

	// ###################  Client -> Server

	// 2. Server generates ECDH and get its PublicKey Bytes
	serverEC, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	ecServerPublicBytes := serverEC.PublicKey().Bytes()

	// convert the client's ECDH public key bytes from the keyExchange back so its usable
	ecClientPublicN, err := ecdh.X25519().NewPublicKey(ecClientPublicBytes)
	if err != nil {
		panic(err)
	}

	// use the server ecdh key and the client's public to arrive at the ECDH share
	ecSharedServer, err := serverEC.ECDH(ecClientPublicN)
	if err != nil {
		panic(err)
	}

	// now use the client KEMPublic to arrive at a kem secret and its encrypted form (ciphertext)
	ek, err := mlkem.NewEncapsulationKey768(kemClientPublicBytes)
	if err != nil {
		log.Fatal(err)
	}
	kemSharedSecret, ciphertext := ek.Encapsulate()

	// For X25519MLKEM768, the shared secret is the concatenation of the ML-KEM shared
	// secret and the X25519 shared secret. The shared secret is 64 bytes (32 bytes for each part).
	// fmt.Printf("kemSharedSecret len(%d)\n", len(kemSharedSecret))  // 32
	// fmt.Printf("ecSharedServer len(%d)\n", len(ecSharedServer))  // 32
	fmt.Fprintf(os.Stdout, "SharedSecret: kemShared (%x) || ecShared (%x)\n", kemSharedSecret, ecSharedServer)

	// When the X25519MLKEM768 group is negotiated, the server's key exchange value is
	// the concatenation of an ML-KEM ciphertext returned from encapsulation to the
	// client's encapsulation key, and the server's ephemeral X25519 share.
	//  The size of the server share is 1120 bytes (1088 bytes for the ML-KEM part and 32 bytes for X25519)

	//fmt.Fprintf(os.Stdout, "KeyExchange: Server => Client: ciphertext (%x) || ecServerPublic (%x)\n", ciphertext, ecServerPublicBytes)

	// ###################  Server -> Client

	// 3. Client

	// first recover Server's ECDH Public key from the KeyExchange
	ecServerPublicN, err := ecdh.X25519().NewPublicKey(ecServerPublicBytes)
	if err != nil {
		panic(err)
	}

	// recover the ecdh share
	recoveredECShared, err := clientEC.ECDH(ecServerPublicN)
	if err != nil {
		panic(err)
	}

	// now recover the kem share
	recoveredKEMShared, err := clientKE.Decapsulate(ciphertext)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Fprintf(os.Stdout, "SharedSecret: kemShared (%x) || ecShared (%x)\n", recoveredKEMShared, recoveredECShared)

}
