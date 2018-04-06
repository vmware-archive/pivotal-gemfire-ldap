/*
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *
 */

package io.pivotal.gemfire.ldap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.SocketFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyStore;
import java.util.Properties;

public class SSLConfigSocketFactory extends SocketFactory {


    private static final Logger log = LoggerFactory.getLogger(SSLConfigSocketFactory.class);

    private static SocketFactory instance;

    private SSLContext context;
    private SSLSocketFactory sslSocketFactory;

    public SSLConfigSocketFactory() throws Exception {
        context = SSLContext.getInstance("TLS");

        Properties properties = ToolBox.loadGFLDAPProperties();

        String keyStore = properties.getProperty(ToolBox.GF_LDAP_SSL_KEYSTORE);
        String trustStore = properties.getProperty(ToolBox.GF_LDAP_SSL_TRUSTSTORE);
        String keyStorePassword = properties.getProperty(ToolBox.GF_LDAP_SSL_KEYSTORE_PASSWORD);
        String trustStorePassword = properties.getProperty(ToolBox.GF_LDAP_SSL_TRUSTSTORE_PASSWORD);

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());

        KeyStore ks = KeyStore.getInstance("JKS");
        try (InputStream inputStream = new FileInputStream(keyStore)) {
            ks.load(inputStream, keyStorePassword.toCharArray());
        }
        kmf.init(ks, keyStorePassword.toCharArray());

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        KeyStore ts = KeyStore.getInstance("JKS");
        try (InputStream inputStream = new FileInputStream(trustStore)) {
            ts.load(inputStream, trustStorePassword.toCharArray());
        }
        tmf.init(ts);

        context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        sslSocketFactory = context.getSocketFactory();
    }

    public static synchronized SocketFactory getDefault() {
        if(instance == null) {
            try {
                instance = new SSLConfigSocketFactory();
            } catch (Exception e) {
                log.error("Could not instantiate the SSL Socket Factory - this is bad.", e);
                throw new RuntimeException("Could not instantiate the SSL Socket Factory - this is bad.", e);
            }
        }
        return instance;
    }

    @Override
    public Socket createSocket() throws IOException {
        return sslSocketFactory.createSocket();
    }

    @Override
    public Socket createSocket(String s, int i) throws IOException, UnknownHostException {
        return sslSocketFactory.createSocket(s, i);
    }

    @Override
    public Socket createSocket(String s, int i, InetAddress inetAddress, int i1) throws IOException, UnknownHostException {
        return sslSocketFactory.createSocket(s, i, inetAddress, i1);
    }

    @Override
    public Socket createSocket(InetAddress inetAddress, int i) throws IOException {
        return sslSocketFactory.createSocket(inetAddress, i);
    }

    @Override
    public Socket createSocket(InetAddress inetAddress, int i, InetAddress inetAddress1, int i1) throws IOException {
        return sslSocketFactory.createSocket(inetAddress, i, inetAddress1, i1);
    }
}
