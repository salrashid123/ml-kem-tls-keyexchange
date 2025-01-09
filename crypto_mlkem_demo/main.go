package main

import (
	"crypto/mlkem"
	"encoding/base64"
	"log"
)

// https://cs.opensource.google/go/go/+/master:src/crypto/mlkem/example_test.go
// https://pkg.go.dev/crypto/mlkem@go1.24rc1

// $ go install golang.org/dl/go1.24rc1@latest
// $ go1.24rc1 download

func main() {

	// Alice generates a new key pair and sends the encapsulation key to Bob.
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		log.Fatal(err)
	}
	encapsulationKey := dk.EncapsulationKey().Bytes()

	// Bob uses the encapsulation key to encapsulate a shared secret, and sends
	// back the ciphertext to Alice.
	ciphertext := Bob(encapsulationKey)

	// Alice decapsulates the shared secret from the ciphertext.
	sharedSecret, err := dk.Decapsulate(ciphertext)
	if err != nil {
		log.Fatal(err)
	}

	// Alice and Bob now share a secret.
	log.Printf("Alice Key: %s", base64.StdEncoding.EncodeToString(sharedSecret))
}

func Bob(encapsulationKey []byte) (ciphertext []byte) {
	// Bob encapsulates a shared secret using the encapsulation key.
	ek, err := mlkem.NewEncapsulationKey768(encapsulationKey)
	if err != nil {
		log.Fatal(err)
	}
	ciphertext, sharedSecret := ek.Encapsulate()

	// Alice and Bob now share a secret.
	log.Printf("Bob Key: %s", base64.StdEncoding.EncodeToString(sharedSecret))

	// Bob sends the ciphertext to Alice.
	return ciphertext
}
