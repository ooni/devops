#!/bin/bash

source ~/.hsmcredentials

if [ -z $HSM_CREDENTIALS ];then
   echo "please configure HSM_CREDENTIALS inside ~/.hsmcredentials"
   exit 1
fi

if [ "$#" -ne 2 ];then
  echo "Usage: $0 [in.exe] [out.exe]"
  exit 1
fi

osslsigncode sign \
    -pass $HSM_CREDENTIALS \
    -pkcs11engine /usr/lib/x86_64-linux-gnu/engines-3/pkcs11.so \
    -pkcs11module /opt/cloudhsm/lib/libcloudhsm_pkcs11.so \
    -certs Cert_bundle.pem \
    -key "pkcs11:token=hsm1;object={{ hsm_token_name }}" \
    -in $1 \
    -out $2
