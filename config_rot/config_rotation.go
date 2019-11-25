package main

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rabarar/goca"
)

var (
	rootCAs     *x509.CertPool = nil
	serialCount int64          = 0
)

type configController struct {
	sync.Mutex
	config    *tls.Config
	caCertPEM []byte
	caKeyPEM  []byte
	caCert    *tls.Certificate
	cert509   *x509.Certificate
}

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

func (c *configController) Get() *tls.Config {
	c.Lock()
	defer c.Unlock()

	return c.config
}

func (c *configController) SaveCACertKey(cert, key []byte) {
	c.Lock()
	c.caCertPEM = cert
	c.caKeyPEM = key
	defer c.Unlock()
}

func (c *configController) Set(hostname string, version uint16, cert509 *x509.Certificate, cert, key []byte, override bool) error {
	c.Lock()
	defer c.Unlock()

	var certAndKey tls.Certificate
	var err error
	if override {
		log.Printf("Using Saved CA Certs \n")
		certAndKey, err = tls.X509KeyPair(c.caCertPEM, c.caKeyPEM)
	} else {
		log.Printf("Using Newly Generated Certs \n")
		certAndKey, err = tls.X509KeyPair(cert, key)
		log.Print(CertificateInfo(cert509))
	}
	if err != nil {
		return err
	}

	c.config = &tls.Config{
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			log.Printf("\tcalling GetCertificate:\n")
			return &certAndKey, nil
		},
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
		MinVersion:               version,
		Certificates:             []tls.Certificate{certAndKey},
	}

	return nil
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
			DNSName:       strings.Split(helloInfo.Conn.RemoteAddr().String(), ":")[0],
		}

		var err error
		if len(verifiedChains) > 0 {
			_, err = verifiedChains[0][0].Verify(opts)
			if err != nil {
				log.Printf("Verified failed: %s\n", err)
			} else {
				log.Printf("Verified\n")
			}
		} else {
			log.Printf("No Verified Chains, can't verifiy...\n")
		}
		return err
	}
}

func main() {

	var hostname string
	var caKey = flag.String("ca-key", "goca-key.pem", "Root private key filename, PEM encoded.")
	var caCert = flag.String("ca-cert", "goca.pem", "Root certificate filename, PEM encoded.")
	var caCertDER = flag.String("ca-cert-der", "goca.der", "Root certificate filename, DER encoded.")
	var domains = flag.String("domains", "", "Comma separated domain names to include as Server Alternative Names.")
	var ipAddresses = flag.String("ip-addresses", "", "Comma separated IP addresses to include as Server Alternative Names.")

	flag.StringVar(&hostname, "host", "localhost", "hostname to use for X509 Certificate Common Name")
	overrideCAForConfig := flag.Bool("useCACerts", false, "use CA Certs instead of dynamically generated cert/key for config")
	makeCA := flag.Bool("makeCA", false, "Generatedcert/key for CA")
	flag.Parse()

	if *makeCA == true {
		err := goca.MakeIssuer(*caKey, *caCert, *caCertDER)
		if err != nil {
			fmt.Printf("%s\n", err)
			os.Exit(1)
		} else {
			fmt.Printf("Issuer generated\n")
		}
		os.Exit(0)
	}

	issuer, err := goca.GetIssuer(*caKey, *caCert)
	if err != nil {
		fmt.Printf("failed to get issuer cert or key\n")
		os.Exit(1)
	}

	rootCAs, err := x509.SystemCertPool()
	rootPEM, err := ioutil.ReadFile(*caCert)
	var rootCACert *x509.Certificate
	var c, k, rootCACertDER []byte

	fmt.Printf("Using EXISTING Root Cerificate Authority\n")
	ok := rootCAs.AppendCertsFromPEM(rootPEM)
	if !ok {
		log.Printf("Failed to Parse cert: %s\n", err)
		os.Exit(1)
	}

	rootCACertDER, err = ioutil.ReadFile(*caCertDER)
	if err != nil {
		log.Printf("Failed to read cert der file: %s\n", err)
		os.Exit(1)
	}
	rootCACert, err = x509.ParseCertificate(rootCACertDER)
	if err != nil {
		log.Printf("Failed to Parse cert der file: %s\n", err)
		os.Exit(1)
	}

	c, err = ioutil.ReadFile(*caCert)
	if err != nil {
		log.Printf("Failed to read cert PEM  file: %s\n", err)
		os.Exit(1)
	}

	k, err = ioutil.ReadFile(*caKey)
	if err != nil {
		log.Printf("Failed to read key  PEM  file: %s\n", err)
		os.Exit(1)
	}

	if rootCACert == nil {
		log.Printf("rootCACert is nil\n")
		os.Exit(1)
	}
	configController := &configController{}
	configController.SaveCACertKey(c, k)
	network := hostname + ":8000"
	listener, err := net.Listen("tcp", network)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	var currentVersion uint16
	done := make(chan struct{})

	splitDomains, err := goca.SplitDomains(*domains)
	splitIPAddresses, err := goca.SplitIPAddresses(*ipAddresses)

	go func() {
		ticker := time.NewTicker(5000 * time.Millisecond)
		defer ticker.Stop()
		clientCount := 0
		for {
			select {
			case <-ticker.C:

				var certPEM, keyPEM []byte
				log.Printf("Generating new certificates.\n")
				cert509, key, certDER, _, err := goca.Sign(issuer, splitDomains, splitIPAddresses)
				if err != nil {
					fmt.Printf("error when generating new cert: %v", err)
					continue
				} else {
					certPEM = pem.EncodeToMemory(&pem.Block{
						Type: "CERTIFICATE", Bytes: certDER})

					keyPEM = pem.EncodeToMemory(&pem.Block{
						Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

					if clientCount == 0 {
						// Only write it if it doesn't exist... otherwise we overwrite an installed KeyChain trusted Cert/Key
						if _, err := os.Stat("./cert-0.pem"); os.IsNotExist(err) {
							err = ioutil.WriteFile(fmt.Sprintf("./cert-%d.pem", clientCount), certPEM, 0644)
							if err != nil {
								fmt.Print("failed to write certfile: %s\n", err)
							}
							err = ioutil.WriteFile(fmt.Sprintf("./key-%d.pem", clientCount), keyPEM, 0644)
							if err != nil {
								fmt.Print("failed to write keyfile: %s\n", err)
							}
						}
						clientCount++
					}
				}

				currentVersion = tls.VersionSSL30

				// trivial example of setting a value in the configController...
				err = configController.Set(hostname, currentVersion, cert509, certPEM, keyPEM, *overrideCAForConfig)
				if err != nil {
					fmt.Printf("error when loading cert: %v", err)
				}
			case <-done:
				return
			}
		}
	}()
	defer close(done)
	// loop for incoming connections
	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println(err.Error())
			continue
		}

		config := configController.Get()
		fmt.Printf("Using config: %v\n", config.MinVersion)
		conn = tls.Server(conn, config)
		fmt.Fprintf(conn, "testing 1, 2, 3...\n")
		conn.Close()
	}
}
