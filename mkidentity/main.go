package main

import (
	"crypto/rand"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/rabarar/crypto/goca"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func main() {

	caKey := flag.String("ca-key", "../config_rot/goca-key.pem", "Root private key filename, PEM encoded.")
	caCert := flag.String("ca-cert", "../config_rot/goca.pem", "Root certificate filename, PEM encoded.")

	domains := flag.String("domains", "", "Comma separated domain names to include as Server Alternative Names.")
	filename := flag.String("out", "identity.pkcs12", "identity output filename")

	flag.Parse()

	if *domains == "" {
		fmt.Printf("must add a domain\n")
		os.Exit(1)
	}
	splitDomains, err := goca.SplitDomains(*domains)
	if err != nil {
		panic(err)
	}

	issuer, err := goca.GetIssuer(*caKey, *caCert)
	if err != nil {
		fmt.Printf("failed to get issuer cert or key\n")
		os.Exit(1)
	}

	rootPEM, err := ioutil.ReadFile("../config_rot/goca.pem")
	if err != nil {
		log.Fatal(err)
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		log.Fatal(err)
	}
	ok := roots.AppendCertsFromPEM([]byte(rootPEM))
	if !ok {
		panic("failed to parse root certificate")
	}

	cp := goca.GetDefaultCertificateParams()

	log.Printf("Generating new Identity Certificates, Serial: %s\n", cp.SerialNumber.String())
	cp.Subject.CommonName = "Identitiy: Rob"
	cp.Domains = splitDomains

	cert509, key, _, _, err := goca.Sign(issuer, cp)
	if err != nil {
		panic(err)
	} else {

		pkx, err := pkcs12.Encode(rand.Reader, key, cert509, nil, "foobar")
		if err != nil {
			panic(err)
		}

		pkxFile, err := os.OpenFile(*filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			panic(err)
		}
		defer pkxFile.Close()
		pkxFile.Write(pkx)
		fmt.Printf("Identity Serial No: %s\n", cp.SerialNumber.String())

	}
}
