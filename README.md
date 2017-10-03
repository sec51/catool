### CATool
CATool is an opinionated command line utility which simplifies the creation of a self-signed certificate  
authority and self-signed certificates.  

CATool supports both RSA 4096 bit and Elliptic Curve ECDSA with curve P256.  
In addition it uses SHA-2 hashing algorithms.  

Finally CATool allows to pass additional common names and ip addresses via the command flags.

### Build

Build: `go build`  
Cross compile for Linux (in case you are in MacOS): `env GOOS=linux GOARCH=amd64 GOARM=7 go build`  

### WARNING
This tool automatically overwrite the files for the certificate authority and certificates in general, without asking!

### Usage
There are two main commands:

1. `./catool ca`
2. `./catool cert`

When executed they print additional possible command line flags.  
The first one is used to create a certificate authority.  
The second one to sign a certificate from the previously generated certificate authority.  

### RSA Example

1. Create a certificate authority

```
catool ca -rsa=true -org "Sec51 Root CA" -years 1 -common-names ca.sec51.com
```

2. Create and sign a certificate

```
# From the same directory where the CA certificate and private keys are located

catool cert -rsa=true -org "Sec51 Root CA" -years 1 -name server1.sec51.com -common-names server1,server1.dc1 -ip 127.0.0.1
```

### ECDSA Example

1. Create a certificate authority

```
catool ca -org "Sec51 Root CA" -years 1 -common-names ca.sec51.com
```

2. Create and sign a certificate

```
# From the same directory where the CA certificate and private keys are located

catool cert -org "Sec51 Root CA" -years 1 -name server1.sec51.com -common-names server1,server1.dc1 -ip 127.0.0.1
```

---

LICENSE

Copyright (c) 2015-2017 Sec51.com info@sec51.com

Permission to use, copy, modify, and distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
