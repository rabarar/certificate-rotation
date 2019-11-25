package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
)

func main() {
	// Connecting with a custom root-certificate set.

	// First, create the set of root certificates. For this example we only
	// have one. It's also possible to omit this in order to use the
	// default root set of the current operating system.

	var hostname string
	useCA := flag.Bool("useCACerts", false, "use CA Certs instead of dynamically generated cert/key for config")
	flag.StringVar(&hostname, "host", "localhost", "hostname to use for X509 Certificate Common Name")
	flag.Parse()

	var err error
	var cert tls.Certificate
	if *useCA {
		log.Printf("Using CA CertKey\n")
		cert, err = tls.LoadX509KeyPair("../config_rot/goca.pem", "../config/goca-key.pem")
		if err!=nil {
				log.Fatal(err)
		}
	} else {
		log.Printf("Using cert-0/key-0\n")
		cert, err = tls.LoadX509KeyPair("../config_rot/cert-0.pem", "../config_rot/key-0.pem")
		if err!=nil {
				log.Fatal(err)
		}
	}

	if err != nil {
		log.Fatal(err)
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

	conn, err := tls.Dial("tcp", hostname+":8000", &tls.Config{
		RootCAs:            roots,
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: false,
		ServerName:         hostname,
	})
	if err != nil {
		panic("failed to connect: " + err.Error())
	} else {
		fmt.Printf("connection Dialed, attempting to write...\n")
	}

	var data []byte = make([]byte, 1024)
	_, err = conn.Read(data)
	if err != nil {
		fmt.Printf("Err reading on conn: %s\n", err)
	} else {
		fmt.Printf("read: [%s]\n", data)
	}
	conn.Close()
	fmt.Printf("closed\n")

}
