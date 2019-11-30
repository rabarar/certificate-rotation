package main

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	cov "github.com/rabarar/crypto/covalid"
	"github.com/rabarar/crypto/goca"
	"github.com/rabarar/crypto/utils"
)

var (
	rootCAs     *x509.CertPool = nil
	serialCount int64          = 0

	secrets *cov.SecretHash = nil
)

const (
	PATH_SECRET    = "/secret"
	PATH_VALIDATOR = "/validator"
)

func defaultURLValue(val []string, defvalue string) string {
	if len(val) > 0 {
		return val[0]
	}
	return defvalue
}

func main() {

	var caKey = flag.String("ca-key", "../config_rot/goca-key.pem", "Root private key filename, PEM encoded.")
	var caCert = flag.String("ca-cert", "../config_rot/goca.pem", "Root certificate filename, PEM encoded.")
	var domains = flag.String("domains", "", "Comma separated domain names to include as Server Alternative Names.")
	var ipAddresses = flag.String("ip-addresses", "", "Comma separated IP addresses to include as Server Alternative Names.")
	var hostname = flag.String("host", "mbp2019.local", "hostname to use for sercret server")
	var port = flag.Int("port", 8080, "port to use for secret server")

	flag.Parse()

	secrets = cov.NewSecretHash()

	issuer, err := goca.GetIssuer(*caKey, *caCert)
	if err != nil {
		log.Printf("failed to get issuer cert or key\n")
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

	cp := &goca.CertificateParams{}
	cp.Domains = splitDomains
	cp.IpAddresses = splitIPAddresses
	cp.SerialNumber, _ = goca.NewSerialNumber()
	cp.KeyUsage = goca.DefaultKeyUsage
	cp.ExtKeyUsage = goca.DefaultExtKeyUsage
	cp.NotBefore = time.Now()
	cp.NotAfter = cp.NotBefore.AddDate(100, 0, 0)
	cp.Subject = pkix.Name{CommonName: "SecretServer"}

	cert509, key, certDER, _, err := goca.Sign(issuer, cp)
	if err != nil {
		log.Printf("Error when generating new cert: %v", err)
	} else {
		certPEM = pem.EncodeToMemory(&pem.Block{
			Type: "CERTIFICATE", Bytes: certDER})

		keyPEM = pem.EncodeToMemory(&pem.Block{
			Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	}

	defer close(done)
	certAndKey, err := tls.X509KeyPair(certPEM, keyPEM)
	log.Print(utils.CertificateInfo(cert509))

	mux := http.NewServeMux()
	mux.HandleFunc(PATH_VALIDATOR, func(w http.ResponseWriter, req *http.Request) {

		if len(req.TLS.VerifiedChains[0]) > 0 {
			//.SerialNumber.String()

			otpQRCode, err := secrets.AddIdentity(req.TLS.VerifiedChains[0][0].SerialNumber.String())
			if err != nil {
				fmt.Fprintf(w, "{\"status\":\"fail\"}\n")
			} else {
				w.Header().Set("Content-Type", "image/png")
				w.Header().Set("Content-Length", strconv.Itoa(len(otpQRCode)))
				if _, err := w.Write(otpQRCode); err != nil {
					log.Println("unable to write image.")
				}
			}
		} else {
			w.Write([]byte("no verified chains, no qr code written"))
		}
	})

	mux.HandleFunc(PATH_SECRET, func(w http.ResponseWriter, req *http.Request) {
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.Header().Add("content-type", "application/json")

		params := req.URL.Query()
		key := defaultURLValue(params["key"], "")
		hash := defaultURLValue(params["hash"], "")

		switch req.Method {
		case http.MethodGet:
			log.Printf("GET Method: Verifying: %s with %s\n", key, hash)
			ok := secrets.Verify(key, hash)

			if ok {
				log.Printf("OTP Verified\n")
				fmt.Fprintf(w, "{\"status\":\"ok\"}\n")
			} else {
				log.Printf("OTP Verification Failed\n")
				fmt.Fprintf(w, "{\"status\":\"fail\"}\n")
			}

		case http.MethodPost:
			reqBody, err := ioutil.ReadAll(req.Body)
			if err != nil {
				log.Fatal(err)
			}
			log.Printf("POST Body: [%s]\n", reqBody)
			req.Body.Close()

			var objmap map[string]string
			err = json.Unmarshal(reqBody, &objmap)
			if err != nil {
				fmt.Fprintf(w, "{\"status\":\"fail to unmarshall json\"}\n")
			}

			key := objmap["serial"]

			hashStr, err := secrets.Add(key)
			if err != nil {
				fmt.Fprintf(w, "{\"status\":\"fail\"}\n")
			} else {
				fmt.Fprintf(w, fmt.Sprintf("{\"status\":\"okay\", \"hash\":\"%s\"}", hashStr))
			}
		default:
			log.Printf("Unkown method: %s\n", req.Method)
			w.WriteHeader(http.StatusNotImplemented)
			w.Write([]byte(http.StatusText(http.StatusNotImplemented)))
		}
	})

	srv := &http.Server{
		TLSConfig:    cov.GetServerValidatonConfig(*hostname, certAndKey, rootCAs),
		Addr:         *hostname + ":" + strconv.Itoa(*port),
		Handler:      mux, //myHandler,
		ReadTimeout:  time.Minute,
		WriteTimeout: time.Minute,
	}

	log.Printf("Starting Secret Server on %s\n", srv.Addr)
	log.Fatal(srv.ListenAndServeTLS("", ""))
}
