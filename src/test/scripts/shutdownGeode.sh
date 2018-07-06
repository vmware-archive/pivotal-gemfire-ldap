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



# --J=-Dlog4j.configurationFile=${APP_HOME}/etc/log4j.xml


gfsh -e "connect --locator=localhost[10334] --key-store=${APP_HOME}/certs/gemfire.jks --key-store-password=changeit --trust-store=${APP_HOME}/certs/gemfire.jks --trust-store-password=changeit --security-properties-file=${APP_HOME}/src/test/resources/gfsecurity-server.properties --user=clusterManage --password=password1234 --use-ssl=true --ciphers=any --protocols=any" -e "shutdown --include-locators=true"

#rm -rf ${APP_HOME}/data/*
