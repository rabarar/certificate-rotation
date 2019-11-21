package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
)

func main() {
	// Connecting with a custom root-certificate set.

	// First, create the set of root certificates. For this example we only
	// have one. It's also possible to omit this in order to use the
	// default root set of the current operating system.

	//cert, err := tls.LoadX509KeyPair("./clientCert-0.txt", "./clientKey-0.txt")
	cert, err := tls.LoadX509KeyPair("./CAfile.txt", "./CAkey.txt")
	if err != nil {
		log.Fatal(err)
	}

	rootPEM, err := ioutil.ReadFile("./CAfile.txt")
	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM([]byte(rootPEM))
	if !ok {
		panic("failed to parse root certificate")
	}

	conn, err := tls.Dial("tcp", "mbp2018-8.local:8000", &tls.Config{
		RootCAs:            roots,
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true, //false,
		ServerName:         "mbp2018-8.local",
	})
	if err != nil {
		panic("failed to connect: " + err.Error())
	}

	var data []byte = make([]byte, 1024)
	_, err = conn.Read(data)
	if err != nil {
		fmt.Printf("Err reading on conn: %s\n", err)
	} else {
		fmt.Printf("read: [%s]\n", data)
	}
	conn.Close()

}
