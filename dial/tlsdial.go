package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	"github.com/rabarar/crypto/goca"
)

func main() {
	// Connecting with a custom root-certificate set.

	// First, create the set of root certificates. For this example we only
	// have one. It's also possible to omit this in order to use the
	// default root set of the current operating system.

	var hostname string
	useCA := flag.Bool("useCACerts", false, "use CA Certs instead of dynamically generated cert/key for config")
	dynamicCerts := flag.Bool("dynamicCerts", false, "generate a new cert and dial away")
	caKey := flag.String("ca-key", "../config_rot/goca-key.pem", "Root private key filename, PEM encoded.")
	caCert := flag.String("ca-cert", "../config_rot/goca.pem", "Root certificate filename, PEM encoded.")

	flag.StringVar(&hostname, "host", "mbp2019.local", "hostname to use for X509 Certificate Common Name")
	domains := flag.String("domains", "", "Comma separated domain names to include as Server Alternative Names.")
	ipAddresses := flag.String("ip-addresses", "", "Comma separated IP addresses to include as Server Alternative Names.")
	resetTime := flag.Int("cycle", 500, "Certificate Cycle Time. Regenerate a new Cert very cycle (in millisecodns")

	flag.Parse()

	splitDomains, err := goca.SplitDomains(*domains)
	splitIPAddresses, err := goca.SplitIPAddresses(*ipAddresses)

	issuer, err := goca.GetIssuer(*caKey, *caCert)
	if err != nil {
		fmt.Printf("failed to get issuer cert or key\n")
		os.Exit(1)
	}

	var cert tls.Certificate
	if *useCA {
		log.Printf("Using CA CertKey\n")
		cert, err = tls.LoadX509KeyPair("../config_rot/goca.pem", "../config/goca-key.pem")
		if err != nil {
			log.Fatal(err)
		}
	} else {
		log.Printf("Using cert-0/key-0\n")
		cert, err = tls.LoadX509KeyPair("../config_rot/cert-0.pem", "../config_rot/key-0.pem")
		if err != nil {
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

	for {

		if *dynamicCerts {

			var certPEM, keyPEM []byte
			log.Printf("Generating new certificates.\n")
			cp := goca.GetDefaultCertificateParams()
			cp.Domains = splitDomains
			cp.IpAddresses = splitIPAddresses
			_, key, certDER, _, err := goca.Sign(issuer, cp)
			if err != nil {
				fmt.Printf("error when generating new cert: %v", err)
				continue
			} else {
				certPEM = pem.EncodeToMemory(&pem.Block{
					Type: "CERTIFICATE", Bytes: certDER})

				keyPEM = pem.EncodeToMemory(&pem.Block{
					Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

				cert, err = tls.X509KeyPair(certPEM, keyPEM)
				if err != nil {
					fmt.Printf("can't create keypair: %s\n", err)
					break
				}
			}

		}

		fmt.Printf("dialing...\n")
		conn, err := tls.Dial("tcp", hostname+":8000", &tls.Config{
			RootCAs:               roots,
			Certificates:          []tls.Certificate{cert},
			InsecureSkipVerify:    false,
			ServerName:            hostname,
			VerifyPeerCertificate: verifyServer,
		})
		if err != nil {
			panic("failed to connect: " + err.Error())
		} else {
			fmt.Printf("connection Dialed, attempting to write...\n")
			fmt.Printf("OCSP Staple: [%x]\n", conn.OCSPResponse())
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

		if !*dynamicCerts {
			break
		} else {
			time.Sleep(time.Millisecond * time.Duration(*resetTime))
		}
	}
}

func verifyServer(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if len(verifiedChains) > 0 {
		fmt.Printf("Server Serial No: %s\n", verifiedChains[0][0].SerialNumber.String())
	} else {
		fmt.Printf("No verified chains\n")
	}

	return nil
}
