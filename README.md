# MidCert

🪪 A Go CLI that detects man-in-the-middle (MitM) deep packet inspection (DPI) proxies, and extracts the CA certs used to sign their certs as PEM files.

It's really meant to facilitate finding and adding those trusted certificates to Java programs that can't directly access the operating system's trusted certificates.

## Features

* Detects MitM deep packet inspection proxies, such as ZScaler and Palo Alto Firewalls.
* Extracts the CA cert chain that the proxy requires for cert validation.
* Outputs the cert chain as a PEM file, or to standard out.
* Works on Windows, MacOS, and Linux

## Running MidCert

`midcert` detects whether there is an SSL decrypting proxy in the environment, and reports some details about it.

`midcert -o midcerts.pem` optonally outputs the signing CA cert chain as a PEM file.

`midcert -o -` optionally outputs the cert chain to std-out.
