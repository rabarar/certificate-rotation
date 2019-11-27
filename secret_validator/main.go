package covalid

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	otp "github.com/dgryski/dgoogauth"
)

var (
	ErrNoKey          error = errors.New("Key Exists, can't add")
	ErrOTPAuthFailure error = errors.New("OTP Auth Failure")
	ErrNoChains       error = errors.New("No Verified Chains")
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
		return ErrNoKey
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
		return false, ErrNoKey
	}

	ok, err := otpVal.validator.Authenticate(token)

	c := otp.ComputeCode(otpVal.validator.Secret, int64(time.Now().Unix()/30))
	fmt.Printf("EXPECTING: %06d - validating with [%s]\n", c, token)

	if err != nil {
		return false, ErrOTPAuthFailure
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

func getClientValidator(helloInfo *tls.ClientHelloInfo) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		log.Printf("calling validator\n")
		//copied from the default options in src/crypto/tls/handshake_server.go, 680 (go 1.11)
		//but added DNSName
		opts := x509.VerifyOptions{
			// TODO - NOT SURE WHERE THIS COMES FROM LOL!!!! Roots:         rootCAs,
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
			return ErrNoChains
		}
	}
}

func GetServerValidatonConfig(hostname string, certAndKey tls.Certificate, rootCAs *x509.CertPool) *tls.Config {

	config := &tls.Config{
		GetConfigForClient: func(hi *tls.ClientHelloInfo) (*tls.Config, error) {
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

	return config
}
