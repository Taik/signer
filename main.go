package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
)

func main() {
	pemPath := flag.String("pem", "", "Path of the pem file")
	flag.Parse()

	pemData, err := ioutil.ReadFile(*pemPath)
	if err != nil {
		fmt.Printf("Could not read file: %s\n", err)
		os.Exit(-1)
	}

	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		fmt.Println("No valid PEM data found")
		os.Exit(-1)
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		fmt.Printf("Cannot parse PEM data: %s\n", err)
		os.Exit(-1)
	}

	fs, err := os.Stdin.Stat()
	if err != nil {
		os.Exit(-1)
	}

	if (fs.Mode() & os.ModeCharDevice) == 0 {
		bytes, _ := ioutil.ReadAll(os.Stdin)

		hash := sha1.New()
		hash.Write(bytes)

		sig, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA1, hash.Sum(nil))
		if err != nil {
			fmt.Printf("Could not get signature: %s\n", err)
			os.Exit(-1)
		}

		fmt.Printf("%s\n", bytes)
		fmt.Println(base64.StdEncoding.EncodeToString(sig))
	}
}
