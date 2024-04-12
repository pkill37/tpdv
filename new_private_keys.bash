#! /bin/bash

KEY=Enclave1/Enclave1_private_key.pem
rm -f $KEY
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -pkeyopt rsa_keygen_pubexp:3 >$KEY
chmod 400 $KEY
echo new private key stored in $KEY

KEY=Enclave2/Enclave2_private_key.pem
rm -f $KEY
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -pkeyopt rsa_keygen_pubexp:3 >$KEY
chmod 400 $KEY
echo new private key stored in $KEY
