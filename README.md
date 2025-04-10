# MidCert

🪪 A Go CLI that detects man-in-the-middle (MitM) deep packet inspection (DPI) proxies, and extracts the CA certs used to sign their certs as PEM files.

It's really meant to facilitate finding and adding those trusted certificates to Java programs that can't directly access the operating system's trusted certificates.

## Features

* Detects MitM deep packet inspection proxies, such as ZScaler and Palo Alto Firewalls.
* Extracts the CA cert chain that the proxy requires for cert validation.
* Outputs the cert chain as a PEM file, or to standard out.
* Works on Windows, MacOS, and Linux

## Running MidCert

### Basic Usage

`midcert` detects whether there is an SSL decrypting proxy in the environment by checking www.google.com, and reports some details about it.

```bash
# Just check for MitM proxy
midcert

# Save CA certificates to a file
midcert -o midcerts.pem

# Output certificates to stdout
midcert -o -

# Check a specific URL
midcert -url https://example.com
```

### Command Line Options

* `-o <file>`: Output file for the CA certificates (use `-` for stdout)
* `-url <url>`: Target URL to check (default: https://www.google.com)

### Example Output

```
Certificate chain for https://www.google.com:

Certificate 1:
  Subject: www.google.com
  Issuer:  GTS CA 1C3
  Valid:   2024-02-13 08:58:33 +0000 UTC to 2024-05-07 08:58:32 +0000 UTC
  ℹ️  Leaf certificate (not checked against trust store)

Certificate 2:
  Subject: GTS CA 1C3
  Issuer:  Google Trust Services LLC
  Valid:   2020-08-13 00:00:00 +0000 UTC to 2027-09-30 00:00:00 +0000 UTC
  ✓ CA certificate found in Mozilla trust store

⚠️  MitM proxy detected! Found 1 unknown CA certificates.
```

## Comparison with OpenSSL

While OpenSSL can be used to view certificate chains, MidCert provides a more focused solution for MitM proxy detection:

```bash
# OpenSSL equivalent (shows all certificates)
openssl s_client -connect www.google.com:443 -showcerts
```

Key differences:

* MidCert automatically detects MitM proxies by checking against Mozilla's trust store
* MidCert only extracts the CA certificates, not the leaf certificate
* MidCert provides a more user-friendly output format
* MidCert can be easily integrated into scripts and CI/CD pipelines

## Downloading Pre-built Binaries

Pre-built executables are available for:

* Linux (amd64)
* Windows (amd64)
* macOS (amd64)
* macOS (arm64)

Download the appropriate executable from the [releases page](https://github.com/aprilogic/midcert/releases).
