package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/rabarar/crypto/goca"
)

func main() {
	// Connecting with a custom root-certificate set.

	// First, create the set of root certificates. For this example we only
	// have one. It's also possible to omit this in order to use the
	// default root set of the current operating system.

	useCA := flag.Bool("useCACerts", false, "use CA Certs instead of dynamically generated cert/key for config")
	caKey := flag.String("ca-key", "../config_rot/goca-key.pem", "Root private key filename, PEM encoded.")
	caCert := flag.String("ca-cert", "../config_rot/goca.pem", "Root certificate filename, PEM encoded.")

	hostname := flag.String("host", "mbp2019.local", "hostname to use for sercret server")
	port := flag.Int("port", 8080, "port to use for secret server")
	domains := flag.String("domains", "", "Comma separated domain names to include as Server Alternative Names.")
	ipAddresses := flag.String("ip-addresses", "", "Comma separated IP addresses to include as Server Alternative Names.")

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

	var certPEM, keyPEM []byte
	log.Printf("Generating new certificates.\n")

	cert509, key, certDER, _, err := goca.Sign(issuer, splitDomains, splitIPAddresses)
	if err != nil {
		fmt.Printf("error when generating new cert: %v", err)
		panic(err)

	} else {
		certPEM = pem.EncodeToMemory(&pem.Block{
			Type: "CERTIFICATE", Bytes: certDER})

		keyPEM = pem.EncodeToMemory(&pem.Block{
			Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

		cert, err = tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			fmt.Printf("can't create keypair: %s\n", err)
			panic(err)
		}
	}

	tr := &http.Transport{
		MaxIdleConns:       10,
		IdleConnTimeout:    30 * time.Second,
		DisableCompression: true,
		TLSClientConfig: &tls.Config{
			RootCAs:               roots,
			Certificates:          []tls.Certificate{cert},
			InsecureSkipVerify:    false,
			ServerName:            *hostname, //+ ":" + strconv.Itoa(*port),
			VerifyPeerCertificate: verifyServer,
		},
	}

	// Post to secret server with serial number and CN hash ...
	fmt.Printf("Posting to Secret Server: Hash[%s] for SerialNo: %s\n", cert509.Subject.CommonName, cert509.SerialNumber.String())
	client := &http.Client{Transport: tr}

	baseUrl, err := url.Parse(fmt.Sprintf("https://%s:%d/secret", *hostname, *port))
	if err != nil {
		log.Fatal("Malformed URL: ", err.Error())
	}

	resp, err := client.Post(baseUrl.String(), "application/json", bytes.NewBuffer([]byte(fmt.Sprintf("{\"serial\":\"%s\", \"hash\":\"%s\"}", cert509.SerialNumber.String(), cert509.Subject.CommonName))))

	if err != nil {
		panic(err)
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Error: %s\n", err)
	} else {
		log.Printf("Post Response: %s\n", body)
	}

	// Get verification
	baseUrl, err = url.Parse(fmt.Sprintf("https://%s:%d/secret", *hostname, *port))
	if err != nil {
		log.Fatal("Malformed URL: ", err.Error())
	}

	// Prepare Query Parameters
	params := url.Values{}
	params.Add("key", cert509.SerialNumber.String())
	params.Add("hash", cert509.Subject.CommonName)

	// Add Query Parameters to the URL
	baseUrl.RawQuery = params.Encode()
	respGet, err := client.Get(baseUrl.String())
	if err != nil {
		panic(err)
	}
	defer respGet.Body.Close()
	body, err = ioutil.ReadAll(respGet.Body)
	if err != nil {
		panic(err)
	}

	log.Printf("GET Body: [%s]\n", body)
}

func verifyServer(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if len(verifiedChains) > 0 {
		fmt.Printf("Server Serial No: %s\n", verifiedChains[0][0].SerialNumber.String())
	} else {
		fmt.Printf("No verified chains\n")
	}

	return nil
}
