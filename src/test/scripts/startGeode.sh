#!/bin/bash

# Attempt to set APP_HOME
# Resolve links: $0 may be a link
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
cd "`dirname \"$PRG\"`/../../.." >&-
APP_HOME="`pwd -P`"
cd "$SAVED" >&-

DEFAULT_LOCATOR_MEMORY="--initial-heap=128m --max-heap=128m"

DEFAULT_SERVER_MEMORY="--initial-heap=2g --max-heap=2g"

DEFAULT_JVM_OPTS=" --J=-XX:+UseParNewGC"
DEFAULT_JVM_OPTS="$DEFAULT_JVM_OPTS --J=-XX:+UseConcMarkSweepGC"
DEFAULT_JVM_OPTS="$DEFAULT_JVM_OPTS --J=-XX:CMSInitiatingOccupancyFraction=50"
DEFAULT_JVM_OPTS="$DEFAULT_JVM_OPTS --J=-XX:+CMSParallelRemarkEnabled"
DEFAULT_JVM_OPTS="$DEFAULT_JVM_OPTS --J=-XX:+UseCMSInitiatingOccupancyOnly"
DEFAULT_JVM_OPTS="$DEFAULT_JVM_OPTS --J=-XX:+ScavengeBeforeFullGC"
DEFAULT_JVM_OPTS="$DEFAULT_JVM_OPTS --J=-XX:+CMSScavengeBeforeRemark"
DEFAULT_JVM_OPTS="$DEFAULT_JVM_OPTS --J=-XX:+UseCompressedOops"
DEFAULT_JVM_OPTS="$DEFAULT_JVM_OPTS --mcast-port=0"
DEFAULT_JVM_OPTS="$DEFAULT_JVM_OPTS  --classpath=${APP_HOME}/build/libs/pivotal-gemfire-ldap-0.0.1-SNAPSHOT.jar"

DEFAULT_JVM_OPTS="$DEFAULT_JVM_OPTS --J=-Dgf-ldap-ssl-keystore=${APP_HOME}/certs/ldap.jks"
DEFAULT_JVM_OPTS="$DEFAULT_JVM_OPTS --J=-Dgf-ldap-ssl-truststore=${APP_HOME}/certs/ldap.jks"
DEFAULT_JVM_OPTS="$DEFAULT_JVM_OPTS --J=-Dgemfire.ssl-truststore=${APP_HOME}/certs/gemfire.jks"
DEFAULT_JVM_OPTS="$DEFAULT_JVM_OPTS --J=-Dgemfire.ssl-keystore=${APP_HOME}/certs/gemfire.jks"
DEFAULT_JVM_OPTS="$DEFAULT_JVM_OPTS --J=-Dssl-truststore=${APP_HOME}/certs/gemfire.jks"
DEFAULT_JVM_OPTS="$DEFAULT_JVM_OPTS --J=-Dssl-keystore=${APP_HOME}/certs/gemfire.jks"
DEFAULT_JVM_OPTS="${DEFAULT_JVM_OPTS} --J=-Dgf-ldap-shiro-ini-file=${APP_HOME}/src/test/resources/gf-ldap-shiro.ini"
DEFAULT_JVM_OPTS="${DEFAULT_JVM_OPTS} --J=-Dgf-ldap-security-file=${APP_HOME}/src/test/resources/gf-ldap-security.properties"
DEFAULT_JVM_OPTS="${DEFAULT_JVM_OPTS} --locators=localhost[10334]"

STD_SERVER_ITEMS="--server-port=0  --locator-wait-time=5 --rebalance --security-properties-file=${APP_HOME}/src/test/resources/gfsecurity-server.properties"

rm -rf ${APP_HOME}/data/*

mkdir -p ${APP_HOME}/data/locator1
mkdir -p ${APP_HOME}/data/locator2
mkdir -p ${APP_HOME}/data/server1
mkdir -p ${APP_HOME}/data/server2
mkdir -p ${APP_HOME}/data/server3


gfsh -e "start locator ${DEFAULT_LOCATOR_MEMORY} ${DEFAULT_JVM_OPTS} --name=locator1 --port=10334 --dir=${APP_HOME}/data/locator1 --security-properties-file=${APP_HOME}/src/test/resources/gfsecurity-locator.properties" &

wait

start_server(){
    local serverName=server${1}
    gfsh -e "start server ${DEFAULT_SERVER_MEMORY} ${DEFAULT_JVM_OPTS} --name=${serverName} --dir=${APP_HOME}/data/${serverName} ${STD_SERVER_ITEMS}" &
}

start_server 1

wait

gfsh -e "connect --locator=localhost[10334] --key-store=${APP_HOME}/certs/gemfire.jks --key-store-password=changeit --trust-store=${APP_HOME}/certs/gemfire.jks --trust-store-password=changeit --security-properties-file=${APP_HOME}/src/test/resources/gfsecurity-server.properties --user=cblack --password=password1234 --use-ssl=true --ciphers=any --protocols=any" -e "create region --name=test --type=PARTITION" -e "list memebers"
