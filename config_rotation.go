package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
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

func (c *configController) Set(hostname string, version uint16, cert, key []byte, override bool) error {
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

func generateNewCert(hostname string, parent *x509.Certificate) ([]byte, []byte, *x509.Certificate, []byte, error) {

	serialCount++

	var organization []byte
	if parent == nil {
		organization = []byte("Rob-Root-CA")
	} else {
		organization = []byte("Rob-Client-" + strconv.Itoa(int(serialCount)))
	}

	template := &x509.Certificate{
		IsCA: func(parent *x509.Certificate) bool {
			if parent == nil {
				return true
			} else {
				return false
			}
		}(parent),
		BasicConstraintsValid: func(parent *x509.Certificate) bool {
			if parent == nil {
				return true
			} else {
				return true
			}
		}(parent),
		SubjectKeyId: []byte{1},
		SerialNumber: big.NewInt(serialCount),
		Subject:      generatePKIXName(serialCount, organization, hostname),
		Issuer:       generatePKIXName(serialCount, organization, hostname),
		DNSNames:     []string{hostname},
		IPAddresses: []net.IP{
			net.ParseIP("127.0.0.1"),
		},

		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(1, 0, 0), // expire one year from now
		ExtKeyUsage: func(parent *x509.Certificate) []x509.ExtKeyUsage {
			if parent == nil {
				return []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageEmailProtection}
			} else {
				return []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageEmailProtection}
			}
		}(parent),
		KeyUsage: func(parent *x509.Certificate) x509.KeyUsage {
			if parent == nil {
				return x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageDataEncipherment
			} else {
				return x509.KeyUsageDigitalSignature | x509.KeyUsageDataEncipherment
			}
		}(parent),
	}

	privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, []byte{}, err
	}
	publickey := &privatekey.PublicKey
	certDER, err := x509.CreateCertificate(rand.Reader, template,
		func(parent, template *x509.Certificate) *x509.Certificate {
			if parent == nil {
				return template
			} else {
				return parent
			}
		}(parent, template),
		publickey, privatekey)

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, nil, []byte{}, err
	}

	return pem.EncodeToMemory(&pem.Block{
			Type: "CERTIFICATE", Bytes: certDER}),
		pem.EncodeToMemory(&pem.Block{
			Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privatekey)}),
		cert,
		certDER,
		err
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
	flag.StringVar(&hostname, "host", "localhost", "hostname to use for X509 Certificate Common Name")
	overrideCAForConfig := flag.Bool("useCACerts", false, "use CA Certs instead of dynamically generated cert/key for config")
	flag.Parse()

	rootCAs = x509.NewCertPool()

	rootPEM, err := ioutil.ReadFile("./CAfile.txt")
	var rootCACert *x509.Certificate
	var c, k, rootCACertDER []byte

	if err != nil {
		// Generate a root CA Certificate and write it to disk so a client app can add it to it's RootCA
		fmt.Printf("Generating NEW Root Cerificate Authority\n")
		c, k, rootCACert, rootCACertDER, err = generateNewCert(hostname, nil)
		err = ioutil.WriteFile("./CAfile.txt", c, 0644)
		err = ioutil.WriteFile("./CAkey.txt", k, 0644)
		err = ioutil.WriteFile("./CAfile.der", rootCACertDER, 0644)
		rootCAs.AddCert(rootCACert)
	} else {
		fmt.Printf("Using EXISTING Root Cerificate Authority\n")
		ok := rootCAs.AppendCertsFromPEM(rootPEM)
		if !ok {
			log.Printf("Failed to Parse cert: %s\n", err)
			os.Exit(1)
		}

		rootCACertDER, err := ioutil.ReadFile("./CAfile.der")
		if err != nil {
			log.Printf("Failed to read cert der file: %s\n", err)
			os.Exit(1)
		}
		rootCACert, err = x509.ParseCertificate(rootCACertDER)
		if err != nil {
			log.Printf("Failed to Parse cert der file: %s\n", err)
			os.Exit(1)
		}

		c, err = ioutil.ReadFile("./CAfile.txt")
		if err != nil {
			log.Printf("Failed to read cert PEM  file: %s\n", err)
			os.Exit(1)
		}

		k, err = ioutil.ReadFile("./CAkey.txt")
		if err != nil {
			log.Printf("Failed to read key  PEM  file: %s\n", err)
			os.Exit(1)
		}
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

	go func() {
		ticker := time.NewTicker(5000 * time.Millisecond)
		defer ticker.Stop()
		clientCount := 0
		for {
			select {
			case <-ticker.C:
				log.Printf("Generating new certificates.\n")
				cert, key, _, _, err := generateNewCert(hostname, rootCACert)
				if err != nil {
					fmt.Printf("error when generating new cert: %v", err)
					continue
				} else {
					if clientCount == 0 {
						// Only write it if it doesn't exist... otherwise we overwrite an installed KeyChain trusted Cert/Key
						if _, err := os.Stat("./clientCert-0.txt"); os.IsNotExist(err) {
							err = ioutil.WriteFile(fmt.Sprintf("./clientCert-%d.txt", clientCount), cert, 0644)
							err = ioutil.WriteFile(fmt.Sprintf("./clientKey-%d.txt", clientCount), key, 0644)
						}
						clientCount++
					}
				}

				currentVersion = tls.VersionSSL30

				// trivial example of setting a value in the configController...
				err = configController.Set(hostname, currentVersion, cert, key, *overrideCAForConfig)
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
