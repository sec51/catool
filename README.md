### CATool
CATool is an opinionated command line utility which simplifies the creation of a certificate  
authority and signing of certificates.  

CATool supports both RSA 4096 and Elliptic Curve ECDSA with curve P256.  
In addition it uses SHA-2 hasing algorithms

Finally CATool allows to pass additional host names and ip addresses via the command flags

### Build

Build from a MacOS: `go build`  
Cross compile for Linux: `env GOOS=linux GOARCH=amd64 GOARM=7 go build`  

### WARNING
This tool automatically overwrite the files for the certificate authority and certificates in general, without asking!

### RSA Example

1. Create a certificate authority

```
catool ca -rsa=true -common-names ca.sec51.com
```

2. Create and sign a certificate

```
# From the same directory where the CA certificate and private keys are located

catool cert -rsa=true -name server1.sec51.com -common-names server1,server1.dc1 -ip 127.0.0.1
```

### ECDSA Example

1. Create a certificate authority

```
catool ca -common-names ca.sec51.com
```

2. Create and sign a certificate

```
# From the same directory where the CA certificate and private keys are located

catool cert -name server1.sec51.com -common-names server1,server1.dc1 -ip 127.0.0.1
```


