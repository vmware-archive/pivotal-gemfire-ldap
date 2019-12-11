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

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.Properties;

class ToolBox {
    public static final String GF_LDAP_SECURITY_PROPERTIES = "gf-ldap-security.properties";
    public static final String GF_LDAP_SSL_FILE = System.getProperty("gf-ldap-security-file");
    public static final String GF_LDAP_SSL_KEYSTORE = "gf-ldap-ssl-keystore";
    public static final String GF_LDAP_SSL_TRUSTSTORE = "gf-ldap-ssl-truststore";
    public static final String GF_LDAP_SSL_KEYSTORE_PASSWORD = "gf-ldap-ssl-keystore-password";
    public static final String GF_LDAP_SSL_TRUSTSTORE_PASSWORD = "gf-ldap-ssl-truststore-password";
    public static final String GF_LDAP_SHIRO_INI_FILE = "gf-ldap-shiro-ini-file";
    private static final Logger log = LoggerFactory.getLogger(SSLConfigSocketFactory.class);

    private ToolBox() {
    }

    public static SecurityManager setupShiro(String iniResourcePath) {
        IniSecurityManagerFactory factory = new IniSecurityManagerFactory(iniResourcePath);
        SecurityManager securityManager = factory.getInstance();
        factory.getBeans().forEach((name, realm) -> {
            if (realm instanceof InitializeIniSection) {
                ((InitializeIniSection) realm).initialize(factory.getIni().getSection(name));
            }
        });
        SecurityUtils.setSecurityManager(securityManager);
        return securityManager;
    }

    public static Properties loadGFLDAPProperties() throws IOException {
        return loadPropertiesFromCommonLocations(GF_LDAP_SSL_FILE, GF_LDAP_SECURITY_PROPERTIES);
    }

    private static Properties loadPropertiesFromCommonLocations(String userOverRide, String defaultFileName) throws IOException {
        Properties properties = new Properties();
        if (userOverRide != null && !userOverRide.isEmpty() && new File(userOverRide).exists()) {
            log.debug("using user provided file");
            properties = new Properties();
            try (FileInputStream fileInputStream = new FileInputStream(userOverRide)) {
                properties.load(fileInputStream);
            }
        } else if (new File(defaultFileName).exists()) {
            log.debug("using CWD properties");
            properties = new Properties();
            try (FileInputStream fileInputStream = new FileInputStream(defaultFileName)) {
                properties.load(fileInputStream);
            }
        } else if (new File(System.getProperty("user.home") + "/" + defaultFileName).exists()) {
            log.debug("using user home properties");
            properties = new Properties();
            try (FileInputStream fileInputStream = new FileInputStream(System.getProperty("user.home") + "/" + defaultFileName)) {
                properties.load(fileInputStream);
            }
        } else {
            log.debug("loading from classpath");
            URL url = ToolBox.class.getResource("/" + defaultFileName);
            if (url != null) {
                properties = new Properties();
                try (InputStream inputStream = url.openStream()) {
                    properties.load(inputStream);
                }
            }
        }
        overwriteIfSet(properties, GF_LDAP_SSL_KEYSTORE);
        overwriteIfSet(properties, GF_LDAP_SSL_TRUSTSTORE);
        overwriteIfSet(properties, GF_LDAP_SSL_KEYSTORE_PASSWORD);
        overwriteIfSet(properties, GF_LDAP_SSL_TRUSTSTORE_PASSWORD);
        overwriteIfSet(properties, GF_LDAP_SHIRO_INI_FILE);

        return properties;
    }

    private static void overwriteIfSet(Properties properties, String propertyName) {
        if (System.getProperty(propertyName) != null) {
            properties.setProperty(propertyName, System.getProperty(propertyName));
        }
    }
}
