package main

import (
	"crypto/tls"
	"crypto/x509"
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

	cov "github.com/rabarar/covalid"
	"github.com/rabarar/goca"
)

var (
	rootCAs     *x509.CertPool = nil
	serialCount int64          = 0

	secrets *cov.SecretHash = nil
)

const (
	PATH_SECRET = "/secret"
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

	mux := http.NewServeMux()
	mux.HandleFunc(PATH_SECRET, func(w http.ResponseWriter, req *http.Request) {
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

			validator := cov.NewOTPValidator(secret, cov.DefaultHOTPCounter, cov.DefaultWindowSize)
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
		TLSConfig:    cov.GetServerValidatonConfig(*hostname, certAndKey, rootCAs),
		Addr:         *hostname + ":" + strconv.Itoa(*port),
		Handler:      mux, //myHandler,
		ReadTimeout:  time.Minute,
		WriteTimeout: time.Minute,
	}

	log.Printf("Starting Secret Server on %s\n", srv.Addr)
	log.Fatal(srv.ListenAndServeTLS("", ""))
}
