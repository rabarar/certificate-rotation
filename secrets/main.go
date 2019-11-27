package main

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"html"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/rabarar/goca"
)

var (
	rootCAs     *x509.CertPool = nil
	serialCount int64          = 0
)

// CertificateInfo returns a string describing the certificate
func CertificateInfo(cert *x509.Certificate) string {
	if cert.Subject.CommonName == cert.Issuer.CommonName {
		return fmt.Sprintf("    Self-signed certificate %v\n", cert.Issuer.CommonName)
	}

	s := fmt.Sprintf("    Subject %v\n", cert.DNSNames)
	s += fmt.Sprintf("    Serial No  %s\n", cert.SerialNumber.String())
	s += fmt.Sprintf("    Issued by %s\n", cert.Issuer.CommonName)
	return s
}

func generatePKIXName(serial int64, organization []byte, common string) pkix.Name {

	var pkixName pkix.Name

	pkixName.Country = []string{"US"}
	pkixName.Organization = []string{string(organization)}
	pkixName.OrganizationalUnit = []string{"Department A"}
	pkixName.Locality = []string{"Local B"}
	pkixName.Province = []string{"Provice C"}
	pkixName.StreetAddress = []string{"Street D"}
	pkixName.PostalCode = []string{"21227"}
	pkixName.SerialNumber = strconv.Itoa(int(serial))
	pkixName.CommonName = common

	return pkixName
}

func getClientValidator(helloInfo *tls.ClientHelloInfo) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		log.Printf("calling validator\n")
		//copied from the default options in src/crypto/tls/handshake_server.go, 680 (go 1.11)
		//but added DNSName
		opts := x509.VerifyOptions{
			Roots:         rootCAs,
			CurrentTime:   time.Now(),
			Intermediates: x509.NewCertPool(),
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			DNSName:       helloInfo.ServerName,
			//DNSName:       strings.Split(helloInfo.Conn.RemoteAddr().String(), ":")[0],
		}

		var err error
		if len(verifiedChains) > 0 {
			_, err = verifiedChains[0][0].Verify(opts)
			log.Printf("DNSNames [RemoteAddr]: %s\n", helloInfo.Conn.RemoteAddr().String())
			log.Printf("DNSNames [ServerName]: %s\n", helloInfo.ServerName)
			if err != nil {
				log.Printf("Verified failed: %s\n", err)
				return err
			} else {
				log.Printf("Verified\n")
				return nil
			}
		} else {
			log.Printf("No Verified Chains, can't verifiy...\n")
			return errors.New("No Verified Chains")
		}
	}
}

func main() {

	var hostname string
	var caKey = flag.String("ca-key", "../config_rot/goca-key.pem", "Root private key filename, PEM encoded.")
	var caCert = flag.String("ca-cert", "../config_rot/goca.pem", "Root certificate filename, PEM encoded.")
	var domains = flag.String("domains", "", "Comma separated domain names to include as Server Alternative Names.")
	var ipAddresses = flag.String("ip-addresses", "", "Comma separated IP addresses to include as Server Alternative Names.")

	flag.StringVar(&hostname, "host", "localhost", "hostname to use for X509 Certificate Common Name")
	flag.Parse()

	issuer, err := goca.GetIssuer(*caKey, *caCert)
	if err != nil {
		fmt.Printf("failed to get issuer cert or key\n")
		os.Exit(1)
	}

	rootCAs, err := x509.SystemCertPool()
	rootPEM, err := ioutil.ReadFile(*caCert)

	ok := rootCAs.AppendCertsFromPEM(rootPEM)
	if !ok {
		log.Printf("Failed to Parse cert: %s\n", err)
		os.Exit(1)
	}

	done := make(chan struct{})

	splitDomains, err := goca.SplitDomains(*domains)
	splitIPAddresses, err := goca.SplitIPAddresses(*ipAddresses)

	var certPEM, keyPEM []byte
	log.Printf("Generating new certificates.\n")
	cert509, key, certDER, _, err := goca.Sign(issuer, splitDomains, splitIPAddresses)
	if err != nil {
		fmt.Printf("error when generating new cert: %v", err)
	} else {
		certPEM = pem.EncodeToMemory(&pem.Block{
			Type: "CERTIFICATE", Bytes: certDER})

		keyPEM = pem.EncodeToMemory(&pem.Block{
			Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	}

	defer close(done)
	certAndKey, err := tls.X509KeyPair(certPEM, keyPEM)
	log.Print(CertificateInfo(cert509))

	config := &tls.Config{
		GetConfigForClient: func(hi *tls.ClientHelloInfo) (*tls.Config, error) {
			log.Printf("calling GetConfigForClient:\n")
			serverConf := &tls.Config{
				Certificates:          []tls.Certificate{certAndKey},
				MinVersion:            tls.VersionTLS12,
				ClientAuth:            tls.RequireAndVerifyClientCert,
				ClientCAs:             rootCAs,
				VerifyPeerCertificate: getClientValidator(hi),
				ServerName:            hostname,
			}
			serverConf.BuildNameToCertificate()
			return serverConf, nil
		},
		PreferServerCipherSuites: true,
		Certificates:             []tls.Certificate{certAndKey},
	}

	//var myHandler http.HandlerFunc = handler
	mux := http.NewServeMux()
	mux.HandleFunc("/foo", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		fmt.Fprintf(w, "foo-Hello, %q", html.EscapeString(req.URL.Path))
	})

	mux.HandleFunc("/bar", func(w http.ResponseWriter, req *http.Request) {
		//w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		fmt.Fprintf(w, "bar-Hello, %q", html.EscapeString(req.URL.Path))
	})

	srv := &http.Server{
		TLSConfig:    config,
		Addr:         ":8080",
		Handler:      mux, //myHandler,
		ReadTimeout:  time.Minute,
		WriteTimeout: time.Minute,
	}

	log.Fatal(srv.ListenAndServeTLS("", ""))
}

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hi there, I love %s!", r.URL.Path[1:])
}
