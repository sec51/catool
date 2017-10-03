package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

const (
	caCmd   = "ca"
	certCmd = "cert"
)

var (
	// certificate authority generation
	caCommandLine = flag.NewFlagSet(caCmd, flag.ExitOnError)

	// certificate generation and signing
	certCommandLine = flag.NewFlagSet(certCmd, flag.ExitOnError)

	// === adding the flags to CA
	rsaType   = caCommandLine.Bool("rsa", false, "Whether to create an RSA CA")
	orgName   = caCommandLine.String("org", "Sec51 Root CA", "The CA organization name")
	hostnames = caCommandLine.String("common-names", "", "Comma separated list of hostnames. Can be a wildcard: *.sec51.com")
	ips       = caCommandLine.String("ip", "", "Comma separated list of ip addresses")
	years     = caCommandLine.Int("years", 1, "CA certificate expires after N years")

	// === adding the flags
	rsaCertType   = certCommandLine.Bool("rsa", false, "Whether to create an RSA CA")
	name          = certCommandLine.String("name", "server", "The certificate file name")
	orgNameCert   = certCommandLine.String("org", "Sec51", "The certificate organization name")
	hostnamesCert = certCommandLine.String("common-names", "", "Comma separated list of hostnames valid for this certificate")
	ipsCert       = certCommandLine.String("ip", "", "Comma separated list of ip addresses valid for this certificate")
	yearsCert     = certCommandLine.Int("years", 1, "Issued certificate expires after N years")
)

func main() {
	types := os.Args
	if len(types) < 2 {
		printAllowedTypes("")
		os.Exit(1)
	}

	t0 := types[1]

	switch t0 {
	case caCmd:
		caCommandLine.Parse(os.Args[2:])
		break
	case certCmd:
		certCommandLine.Parse(os.Args[2:])
		break
	default:
		flag.PrintDefaults()
		os.Exit(1)
	}

	// ============================= CA
	if caCommandLine.Parsed() {

		// verify that the hostname
		if *hostnames == "" {
			fmt.Println("")
			fmt.Println("ERROR: -common-names parameters is required")
			fmt.Println("")
			caCommandLine.PrintDefaults()
			os.Exit(1)
		}

		hosts := parseCommaSeparated(*hostnames)
		ipAddresses := parseCommaSeparated(*ips)

		if err := generateKeyPairs(true, *rsaType, "ca", *orgName, hosts, ipAddresses, *years); err != nil {
			fmt.Printf("Failed to generate the CA %s\n", err)
			os.Exit(1)
		}
	}

	// ===================================== CERT
	if certCommandLine.Parsed() {

		// verify that the hostname
		if *hostnamesCert == "" {
			fmt.Println("")
			fmt.Println("ERROR: -common-names parameters is required")
			fmt.Println("")
			certCommandLine.PrintDefaults()
			os.Exit(1)
		}

		hosts := parseCommaSeparated(*hostnamesCert)
		ipAddresses := parseCommaSeparated(*ipsCert)

		if err := generateKeyPairs(false, *rsaCertType, *name, *orgNameCert, hosts, ipAddresses, *yearsCert); err != nil {
			fmt.Printf("Failed to generate the certificate %s\n", err)
			os.Exit(1)
		}
	}

}

func parseCommaSeparated(input string) []string {
	data := []string{}
	if strings.Contains(input, ",") {
		data = strings.Split(input, ",")
		for index, h := range data {
			data[index] = strings.TrimSpace(h)
		}
	} else {
		data = append(data, strings.TrimSpace(input))
	}
	return data
}
