package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
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
	config *tls.Config
}

func (c *configController) Get() *tls.Config {
	c.Lock()
	defer c.Unlock()

	return c.config
}

func (c *configController) Set(version uint16, cert, key []byte) error {
	c.Lock()
	defer c.Unlock()

	certAndKey, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return err
	}

	c.config = &tls.Config{
		GetConfigForClient: func(hi *tls.ClientHelloInfo) (*tls.Config, error) {
			log.Printf("calling GetConfigForClient:\n")
			serverConf := &tls.Config{
				Certificates:          []tls.Certificate{certAndKey},
				MinVersion:            tls.VersionTLS12,
				ClientAuth:            tls.RequireAndVerifyClientCert,
				ClientCAs:             rootCAs,
				VerifyPeerCertificate: getClientValidator(hi),
				ServerName:            "mbp2018-8.local",
			}
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
	organization := make([]byte, 32)

	if parent == nil {
		organization = []byte("Rob-Root-CA")
	} else {
		rand.Read(organization)
		organization = []byte(base64.URLEncoding.EncodeToString(organization))
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
				return false
			}
		}(parent),
		SubjectKeyId: []byte{1},
		SerialNumber: big.NewInt(serialCount),
		Subject:      generatePKIXName(serialCount, organization, hostname),
		Issuer:       generatePKIXName(serialCount, organization, hostname),
		DNSNames:     []string{hostname},
		IPAddresses: []net.IP{
			net.ParseIP("192.168.1.15"),
			net.ParseIP("127.0.0.1"),
		},

		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(5, 5, 5),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
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
		_, err := verifiedChains[0][0].Verify(opts)
		if err != nil {
			log.Printf("Verified failed: %s\n", err)
		} else {
			log.Printf("Verified\n")
		}
		return nil //err
	}
}

func main() {

	var hostname string
	flag.StringVar(&hostname, "host", "mbp2018-8.local", "hostname to use for X509 Certificate Common Name")
	flag.Parse()

	rootCAs = x509.NewCertPool()

	rootPEM, err := ioutil.ReadFile("./CAfile.txt")
	var rootCACert *x509.Certificate

	if err != nil {
		// Generate a root CA Certificate and write it to disk so a client app can add it to it's RootCA
		fmt.Printf("Generating NEW Root Cerificate Authority\n")
		var c, k, rootCACertDER []byte
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
	}

	if rootCACert == nil {
		log.Printf("rootCACert is nil\n")
		os.Exit(1)
	}
	configController := &configController{}
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
						err = ioutil.WriteFile(fmt.Sprintf("./clientCert-%d.txt", clientCount), cert, 0644)
						err = ioutil.WriteFile(fmt.Sprintf("./clientKey-%d.txt", clientCount), key, 0644)
						clientCount++
					}
				}

				currentVersion = tls.VersionSSL30

				// trivial example of setting a value in the configController...
				err = configController.Set(currentVersion, cert, key)
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
