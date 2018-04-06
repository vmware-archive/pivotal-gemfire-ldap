#!/bin/bash

PRG="$0"
# Need this for relative symlinks.
while [ -h "$PRG" ] ; do
    ls=`ls -ld "$PRG"`
    link=`expr "$ls" : '.*-> \(.*\)$'`
    if expr "$link" : '/.*' > /dev/null; then
        PRG="$link"
    else
        PRG=`dirname "$PRG"`"/$link"
    fi
done
SAVED="`pwd`"
cd "`dirname \"$PRG\"`/.." >&-
APP_HOME="`pwd -P`"
cd "$SAVED" >&-

if [ "$#" -ne 1 ]
then
  echo "Usage: $PRG <name of the certs>"
  exit 1
fi

mkdir -p ${APP_HOME}/certs
cd   ${APP_HOME}/certs

openssl  req  -passout pass:changeit -new  -x509  -keyout  ${1}-ca-key.pem.txt -out  ${1}-ca-certificate.pem.txt  -days  365 << EOF
changeit
changeit
US
CA
CA Test
The Testing CA
Tester CA
localhost
ca@foo.bar
EOF



cd ${APP_HOME}/certs

keytool -genkey -alias testing -keystore ${1}.jks -keyalg RSA -sigalg SHA1withRSA << EOF
changeit
changeit
localhost
Test OU
Test OU Name
Testing City
Unit Test
US
yes
changeit
changeit
EOF


keytool -list -v -keystore ${1}.jks -storepass changeit

# Generate the Signing Request
keytool -keystore ${1}.jks -certreq -alias testing -keyalg rsa  -file ${1}.csr -storepass changeit



# sign it
openssl  x509  -req  -passin pass:changeit -CA ${1}-ca-certificate.pem.txt -CAkey ${1}-ca-key.pem.txt -in ${1}.csr -out ${1}.cer  -days 365  -CAcreateserial

keytool -import -keystore ${1}.jks -file ${1}-ca-certificate.pem.txt -alias testtrustca -storepass changeit << EOF
y
EOF

keytool -import -keystore ${1}.jks -file ${1}.cer -alias testing -storepass changeit

keytool -list -v -keystore ${1}.jks -storepass changeit

cd "$SAVED" >&-