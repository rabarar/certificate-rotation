package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	otp "github.com/dgryski/dgoogauth"
	"github.com/rabarar/goca"
)

const (
	DefaultHOTPCounter = 0
	DefaultWindowSize  = 3
)

type OTPValidator struct {
	validator otp.OTPConfig
}

type SecretHash struct {
	hash map[string]*OTPValidator
	sync.Mutex
}

var (
	rootCAs     *x509.CertPool = nil
	serialCount int64          = 0

	secrets *SecretHash = nil
)

func NewSecretHash() *SecretHash {

	sh := &SecretHash{}
	sh.hash = make(map[string]*OTPValidator)

	return sh
}

func (m *SecretHash) Add(key string, validator *OTPValidator) error {
	m.Lock()
	defer m.Unlock()

	_, ok := m.hash[key]
	if ok {
		return errors.New("Key Exists, can't add")
	}
	m.hash[key] = validator
	return nil
}

func (m *SecretHash) Delete(key string) {
	m.Lock()
	defer m.Unlock()

	delete(m.hash, key)
}

func (m *SecretHash) Verify(key, token string) (bool, error) {
	m.Lock()
	defer m.Unlock()

	otpVal, ok := m.hash[key]

	if !ok {
		return false, errors.New("No Key Exists")
	}

	ok, err := otpVal.validator.Authenticate(token)

	c := otp.ComputeCode(otpVal.validator.Secret, int64(time.Now().Unix()/30))
	fmt.Printf("EXPECTING: %06d - validating with [%s]\n", c, token)

	if err != nil {
		return false, errors.New("OTP Auth Failure")
	}

	return ok, nil
}

func NewOTPValidator(secret string, hoptCounter, windowSize int) *OTPValidator {
	o := &OTPValidator{}
	o.validator = otp.OTPConfig{
		Secret:      secret,
		HotpCounter: hoptCounter,
		WindowSize:  windowSize,
	}
	return o
}

func defaultURLValue(val []string, defvalue string) string {
	if len(val) > 0 {
		return val[0]
	}
	return defvalue
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

	var caKey = flag.String("ca-key", "../config_rot/goca-key.pem", "Root private key filename, PEM encoded.")
	var caCert = flag.String("ca-cert", "../config_rot/goca.pem", "Root certificate filename, PEM encoded.")
	var domains = flag.String("domains", "", "Comma separated domain names to include as Server Alternative Names.")
	var ipAddresses = flag.String("ip-addresses", "", "Comma separated IP addresses to include as Server Alternative Names.")
	var hostname = flag.String("host", "mbp2019.local", "hostname to use for sercret server")
	var port = flag.Int("port", 8080, "port to use for secret server")

	flag.Parse()

	secrets = NewSecretHash()

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
				ServerName:            *hostname,
			}
			serverConf.BuildNameToCertificate()
			return serverConf, nil
		},
		PreferServerCipherSuites: true,
		Certificates:             []tls.Certificate{certAndKey},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/secret", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.Header().Add("content-type", "application/json")

		// print out url params
		for k, v := range req.URL.Query() {
			fmt.Printf("%s: %s\n", k, v)
		}
		params := req.URL.Query()
		key := defaultURLValue(params["key"], "")
		token := defaultURLValue(params["token"], "")

		switch req.Method {
		case http.MethodGet:
			log.Printf("Verifiying: %s with %s\n", key, token)
			ok, err := secrets.Verify(key, token)

			if err != nil {
				log.Printf("error!: %s\n", err)
			} else {
				if ok {
					log.Printf("ok!\n")
				} else {
					log.Printf("nope!\n")
				}
			}

		case http.MethodPost:
			reqBody, err := ioutil.ReadAll(req.Body)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("POST Body: [%s]\n", reqBody)
			// TODO - unmarshall JSON
			var objmap map[string]string
			err = json.Unmarshal(reqBody, &objmap)
			if err != nil {
				fmt.Fprintf(w, "{\"status\":\"fail to unmarshall json\"}\n")
			}

			key := objmap["serial"]
			secret := objmap["secret"]
			log.Printf("Adding Validator with secret:[%s]\n", secret)

			validator := NewOTPValidator(secret, DefaultHOTPCounter, DefaultWindowSize)
			err = secrets.Add(key, validator)
			if err != nil {
				fmt.Fprintf(w, "{\"status\":\"fail\"}\n")
			} else {
				fmt.Fprintf(w, "{\"status\":\"okay\", \"secret\":\"random-secret\"}")
			}
		default:
			log.Printf("unkown method: %s\n", req.Method)
			w.WriteHeader(http.StatusNotImplemented)
			w.Write([]byte(http.StatusText(http.StatusNotImplemented)))
		}
	})

	srv := &http.Server{
		TLSConfig:    config,
		Addr:         *hostname + ":" + strconv.Itoa(*port),
		Handler:      mux, //myHandler,
		ReadTimeout:  time.Minute,
		WriteTimeout: time.Minute,
	}

	log.Printf("Starting Secret Server on %s\n", srv.Addr)
	log.Fatal(srv.ListenAndServeTLS("", ""))
}
