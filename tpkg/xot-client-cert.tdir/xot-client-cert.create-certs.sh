#!/bin/sh

# Cleanup old stuff
#
rm -f *.key *.csr *.crt *.chain.pem *.serial

# Create CA:
#
openssl genrsa -out xot-client-cert.ca.key 4096
openssl req -key xot-client-cert.ca.key -new -x509 -days 36500 -sha256 \
	-extensions v3_ca -out xot-client-cert.ca.crt \
	-subj "/CN=ca.test"

# Create key and certificate for the primary:
#
openssl genrsa -out xot-client-cert.primary.key 2048
openssl req -new -key xot-client-cert.primary.key \
	-out xot-client-cert.primary.csr -subj "/CN=primary.test" \
	-addext "subjectAltName=DNS:primary.test,IP:127.0.0.1"
openssl x509 -req -days 32850 -CA xot-client-cert.ca.crt \
	-CAkey xot-client-cert.ca.key -copy_extensions copyall \
	-CAcreateserial -CAserial xot-client-cert.ca.serial \
	-in xot-client-cert.primary.csr \
	-out xot-client-cert.primary.crt

# Create key and certificate for the secondary:
#
openssl genrsa -out xot-client-cert.secondary.key 2048
openssl req -new -key xot-client-cert.secondary.key \
	-out xot-client-cert.secondary.csr -subj "/CN=for-your-eyes-only.test" \
	-addext "subjectAltName=DNS:for-your-eyes-only.test"
openssl x509 -req -days 32850 -CA xot-client-cert.ca.crt \
	-CAkey xot-client-cert.ca.key -CAserial xot-client-cert.ca.serial \
	-copy_extensions copyall \
	-in xot-client-cert.secondary.csr \
	-out xot-client-cert.secondary.crt

# Create key and certificate for the secondary (with wrong name):
#
openssl req -new -key xot-client-cert.secondary.key \
	-out xot-client-cert.wrong-name.csr -subj "/CN=for-my-eyes-too.test" \
	-addext "subjectAltName=DNS:for-my-eyes-too.test"
openssl x509 -req -days 32850 -CA xot-client-cert.ca.crt \
	-CAkey xot-client-cert.ca.key -CAserial xot-client-cert.ca.serial \
	-copy_extensions copyall \
	-in xot-client-cert.wrong-name.csr \
	-out xot-client-cert.wrong-name.crt

# Create different CA:
#
openssl genrsa -out xot-client-cert.different-ca.key 4096
openssl req -key xot-client-cert.different-ca.key -new -x509 -days 36500 -sha256 \
	-extensions v3_ca -out xot-client-cert.different-ca.crt \
	-subj "/CN=different-ca.test"

# Create certificate for the secondary signed by a different CA:
#
openssl x509 -req -days 32850 -CA xot-client-cert.different-ca.crt \
	-CAkey xot-client-cert.different-ca.key \
	-copy_extensions copyall \
	-in xot-client-cert.secondary.csr \
	-out xot-client-cert.different-ca-secondary.crt

# Create rogue CA:
#
openssl genrsa -out xot-client-cert.rogue-ca.key 4096
openssl req -key xot-client-cert.rogue-ca.key -new -x509 -days 36500 -sha256 \
	-extensions v3_ca -out xot-client-cert.rogue-ca.crt \
	-subj "/CN=rogue-ca.test"

# Client certificate: correct name, but signed by an untrusted CA:
#
openssl x509 -req -days 32850 -CA xot-client-cert.rogue-ca.crt \
	-CAkey xot-client-cert.rogue-ca.key \
	-copy_extensions copyall \
	-in xot-client-cert.secondary.csr \
	-out xot-client-cert.wrong-ca.crt

cat xot-client-cert.ca.crt xot-client-cert.different-ca.crt > xot-client-cert.ca-bundle.pem
