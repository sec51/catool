// This file contains the enrollment loginc for the server side
// The enrollment works like this:
// Falcon generates a CA key pair.
// The nodes need to have the CA public certificate so that they can connect via HTTPs successfully.
// The nodes then enroll

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"os"
	"time"
)

const (
	crtExtension = ".crt"
	pemExtension = ".pem"
)

// GenerateCA Comma separated list of hosts or ip address to generate the certificate for
// validFor: years * 365*24*time.Hour
func generateKeyPairs(isCA, isRSA bool, name, org string, hostnames []string, ip []string, years int) error {

	log.Printf("Generating CA certificate for the following hostname %s with RSA: %v\n", hostnames, isRSA)
	log.Printf("Generating CA certificate for the following ip addresses %s with RSA: %v\n", ip, isRSA)

	// Generate a private/public key pair
	var privateKey interface{}
	var caPrivateKey interface{}
	var err error
	if isRSA {
		privateKey, err = rsa.GenerateKey(rand.Reader, 4096)
	} else {
		privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if err != nil {
		log.Fatalf("Failed to generate private key: %s", err)
	}

	// if the request is not for a CA authority generation then load the CA public key
	var caCRT *x509.Certificate
	if !isCA {
		caCRT, err = readCertificate("ca")
		if err != nil {
			return err
		}
	}

	template, err := makeTemplate(isCA, isRSA, org, hostnames, ip, years, caCRT)
	if err != nil {
		return err
	}

	// in case we are generating the certificates for a CA
	if isCA {
		caCRT = template
		caPrivateKey = privateKey
	} else {
		// in case we are signing a certificate with an existing certitifcate authority then load the CA private key
		caPrivateKey, err = readPrivateKey("ca")
		if err != nil {
			return err
		}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, caCRT, publicKey(privateKey), caPrivateKey)
	if err != nil {
		log.Printf("Certificate autohority generation: failed to create certificate with error %s", err)
		return err
	}

	if err := storeCertificate(name, derBytes); err != nil {
		return err
	}

	err = storePrivateKey(name, privateKey)

	return err

}

func storeCertificate(file string, derBytes []byte) error {
	fileName := file + crtExtension
	certOut, err := os.Create(fileName)
	if err != nil {
		log.Printf("Failed to open %s for writing: %s", fileName, err)
		return err
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()
	log.Printf("Public certificate written to: %s\n", fileName)

	return nil
}

func storePrivateKey(file string, privateKey interface{}) error {
	fileName := file + pemExtension
	keyOut, err := os.OpenFile(fileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Printf("Certificate autohority generation, failed to open %s for writing with error: %s\n", fileName, err)
		return err
	}
	pem.Encode(keyOut, pemBlockForKey(privateKey))
	keyOut.Close()
	log.Printf("Private key written to: %s\n", fileName)
	return nil
}

// - DONE for generation of both RSA and ECDSA

// func generateSignCertificate(isRSA bool, name, org string, hostnames []string, ip []string, years int) error {

// 	log.Printf("Generating certificate for the following hostname %s\n", hostnames)
// 	log.Printf("Generating certificate for the following ip addresses %s\n", ip)

// 	caCRT, err := readCertificate("ca")
// 	if err != nil {
// 		return err
// 	}

// 	template, err := makeTemplate(true, org, hostnames, ip, years, caCRT)
// 	if err != nil {
// 		return err
// 	}

// 	// CA private key
// 	caPrivateKeyFile, err := ioutil.ReadFile("ca.pem")
// 	if err != nil {
// 		return err
// 	}
// 	pemBlock, _ := pem.Decode(caPrivateKeyFile)
// 	if pemBlock == nil {
// 		return errors.New("CA private key PEM decoding failed")
// 	}

// 	caPrivateKey, err := x509.ParseECPrivateKey(pemBlock.Bytes)
// 	if err != nil {
// 		return err
// 	}

// 	// generate the certificate
// 	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
// 	if err != nil {
// 		return err
// 	}

// 	derBytes, err := x509.CreateCertificate(rand.Reader, template, caCRT, publicKey(priv), caPrivateKey)
// 	if err != nil {
// 		log.Printf("Certificate generation: failed to create certificate with error %s", err)
// 		return err
// 	}

// 	publicCertName := name + ".crt"
// 	privateCertName := name + ".pem"

// 	certOut, err := os.Create(publicCertName)
// 	if err != nil {
// 		log.Printf("failed to open %s for writing: %s", publicCertName, err)
// 		return err
// 	}
// 	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
// 	certOut.Close()
// 	log.Printf("Certificate generation: written %s\n", publicCertName)

// 	keyOut, err := os.OpenFile(privateCertName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
// 	if err != nil {
// 		log.Printf("Certificate autohority generation, failed to open %s for writing with error: %s\n", privateCertName, err)
// 		return err
// 	}
// 	pem.Encode(keyOut, pemBlockForKey(priv))
// 	keyOut.Close()
// 	log.Printf("Certificate autohority generation, written %s\n", privateCertName)

// 	return nil
// }

func makeTemplate(isCA, isRSA bool, org string, hostnames []string, ip []string, years int, caCRT *x509.Certificate) (*x509.Certificate, error) {
	// Calculate the duration
	yearsInDays := time.Duration(years * 365 * 24)
	validFor := yearsInDays * time.Hour
	notBefore := time.Now()
	notAfter := notBefore.Add(validFor)

	// calculate the serial number
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Printf("Certificate generation, failed to generate serial number with error %s", err)
		return nil, err
	}

	signatureAlgo := x509.ECDSAWithSHA256
	if isRSA {
		signatureAlgo = x509.SHA256WithRSA
	}

	log.Println(signatureAlgo)

	template := x509.Certificate{
		SignatureAlgorithm: signatureAlgo,
		SerialNumber:       serialNumber,

		Subject: pkix.Name{
			Organization: []string{org},
			CommonName:   hostnames[0],
		},

		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	if isCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	} else {
		// it means it's a new certificate therefore we should put the CA subject in the issuer
		if caCRT != nil {
			caCRT := *caCRT
			template.Issuer = caCRT.Subject
		}
	}

	// Add the aditional hostnames
	for _, h := range hostnames {
		template.DNSNames = append(template.DNSNames, h)

	}

	// Add the aditional ip addresses
	for _, h := range ip {
		if ipAddr := net.ParseIP(h); ipAddr != nil {
			template.IPAddresses = append(template.IPAddresses, ipAddr)
		}
	}

	return &template, nil
}

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func pemBlockForKey(priv interface{}) *pem.Block {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			log.Fatalf("Unable to marshal ECDSA private key: %v", err)
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	default:
		return nil
	}
}

func readCertificate(file string) (*x509.Certificate, error) {

	fileName := file + ".crt"
	// load CA key pair
	caPublicKeyFile, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	pemBlock, _ := pem.Decode(caPublicKeyFile)
	if pemBlock == nil {
		return nil, errors.New("CA public key PEM decoding failed")
	}
	caCRT, err := x509.ParseCertificate(pemBlock.Bytes)
	return caCRT, err
}

func readPrivateKey(file string) (interface{}, error) {

	fileName := file + pemExtension

	// Private key bytes
	caPrivateKeyFile, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}

	pemBlock, _ := pem.Decode(caPrivateKeyFile)
	if pemBlock == nil {
		return nil, errors.New("Private key PEM decoding failed")
	}
	var privateKey interface{}
	switch pemBlock.Type {
	case "RSA PRIVATE KEY":
		privateKey, err = x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
		return privateKey, err
	case "PRIVATE KEY":
		privateKey, err = x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
		return privateKey, err
	case "EC PRIVATE KEY":
		privateKey, err = x509.ParseECPrivateKey(pemBlock.Bytes)
		return privateKey, err
	default:
		log.Panic("Unknown KEY type", pemBlock.Type)
	}
	return privateKey, nil
}
