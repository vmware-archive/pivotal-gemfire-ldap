/*
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package io.pivotal.gemfire.ldap;

import org.apache.directory.server.annotations.CreateLdapServer;
import org.apache.directory.server.annotations.CreateTransport;
import org.apache.directory.server.core.annotations.ApplyLdifFiles;
import org.apache.directory.server.core.annotations.CreateDS;
import org.apache.directory.server.core.annotations.CreatePartition;
import org.apache.directory.server.core.api.DirectoryService;
import org.apache.directory.server.core.integ.FrameworkRunner;
import org.apache.directory.server.kerberos.kdc.KdcServer;
import org.apache.directory.server.ldap.LdapServer;
import org.apache.geode.cache.Region;
import org.apache.geode.cache.client.ClientCache;
import org.apache.geode.cache.client.ClientCacheFactory;
import org.apache.geode.cache.client.ClientRegionShortcut;
import org.apache.geode.cache.client.ServerOperationException;
import org.apache.geode.security.ResourcePermission;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.Control;
import javax.naming.ldap.LdapContext;
import javax.naming.ldap.SortControl;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Field;
import java.util.Hashtable;
import java.util.Properties;

import static org.apache.geode.management.internal.security.ResourceConstants.PASSWORD;
import static org.apache.geode.management.internal.security.ResourceConstants.USER_NAME;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;

@RunWith(FrameworkRunner.class)
@CreateLdapServer(certificatePassword = "changeit",
        transports = {@CreateTransport(protocol = "LDAPS", port = 17001)},
        keyStore = "certs/ldap.jks"
)
@CreateDS(allowAnonAccess = true, partitions = {
        @CreatePartition(name = "Example Partition", suffix = "dc=example,dc=com")})
@ApplyLdifFiles("sample.ldif")
public class LdapApplicationTests {

    public static DirectoryService service;
    public static LdapServer ldapServer;
    public static KdcServer kdcServer;
    Object lock = new Object();
    private ClientCache clientCache;

    public static DirectoryService getService() {
        return service;
    }

    public static void setService(DirectoryService service) {
        LdapApplicationTests.service = service;
    }

    public static LdapServer getLdapServer() {
        return ldapServer;
    }

    public static void setLdapServer(LdapServer ldapServer) {
        LdapApplicationTests.ldapServer = ldapServer;
    }

    public static KdcServer getKdcServer() {
        return kdcServer;
    }

    public static void setKdcServer(KdcServer kdcServer) {
        LdapApplicationTests.kdcServer = kdcServer;
    }

    @BeforeClass
    public static void setup() throws InterruptedException, IOException {
        runScript(System.getProperty("user.dir") + "/src/test/scripts/startGeode.sh");
    }

    @AfterClass
    public static void shutdown() throws IOException, InterruptedException {
        runScript(System.getProperty("user.dir") + "/src/test/scripts/shutdownGeode.sh");
    }

    public static void runScript(String command) throws IOException, InterruptedException {
        Process process = new ProcessBuilder(command).start();
        new Thread(new StreamGobbler(process.getInputStream())).start();
        new Thread(new StreamGobbler(process.getErrorStream())).start();
        process.waitFor();
    }

    @Test
    public void testJNDI() throws Exception {
        setupLDAPCerts();

        LdapContext ctx = (LdapContext) new InitialDirContext(createCommonJNDIEnv()).lookup("ou=Users,dc=example,dc=com");
        ctx.setRequestControls(new Control[]{new SortControl("cn", Control.CRITICAL)});

        NamingEnumeration<SearchResult> res = ctx.search("", "(objectClass=person)", new SearchControls());
        assertThat(res.hasMore(), equalTo(true));
        SearchResult searchResult = res.next();
        assertThat(searchResult.getName(), equalTo("uid=cblack"));
    }

    private void setupLDAPCerts() {
        System.setProperty(ToolBox.GF_LDAP_SSL_KEYSTORE, "certs/ldap.jks");
        System.setProperty(ToolBox.GF_LDAP_SSL_TRUSTSTORE, "certs/ldap.jks");
        System.setProperty(ToolBox.GF_LDAP_SSL_KEYSTORE_PASSWORD, "changeit");
        System.setProperty(ToolBox.GF_LDAP_SSL_TRUSTSTORE_PASSWORD, "changeit");
    }

    @Test
    public void testJNDILoadFromProperties() throws Exception {

        clearLDAPCertEnv();

        Hashtable env = createCommonJNDIEnv();

        LdapContext ctx = (LdapContext) new InitialDirContext(env).lookup("ou=groups,dc=example,dc=com");

        NamingEnumeration<SearchResult> res = ctx.search("", "(cn=GemFireDeveloper)", new SearchControls());
        assertThat(res.hasMore(), equalTo(true));
        SearchResult searchResult = res.next();
        assertThat(searchResult.getName(), equalTo("cn=GemFireDeveloper"));

    }

    @Before
    public void beforeTests() {
        clearLDAPCertEnv();
        resetSSLConfigSocketFactory();
    }

    private void clearLDAPCertEnv() {
        System.getProperties().remove(ToolBox.GF_LDAP_SSL_KEYSTORE);
        System.getProperties().remove(ToolBox.GF_LDAP_SSL_TRUSTSTORE);
        System.getProperties().remove(ToolBox.GF_LDAP_SSL_KEYSTORE_PASSWORD);
        System.getProperties().remove(ToolBox.GF_LDAP_SSL_TRUSTSTORE_PASSWORD);
    }

    @Test(expected = javax.naming.CommunicationException.class)
    public void testMixingSSLCerts() throws Exception {

        resetSSLConfigSocketFactory();
        try {
            System.setProperty(ToolBox.GF_LDAP_SSL_KEYSTORE, "certs/gemfire.jks");
            System.setProperty(ToolBox.GF_LDAP_SSL_TRUSTSTORE, "certs/gemfire.jks");
            System.setProperty(ToolBox.GF_LDAP_SSL_KEYSTORE_PASSWORD, "changeit");
            System.setProperty(ToolBox.GF_LDAP_SSL_TRUSTSTORE_PASSWORD, "changeit");

            LdapContext ctx = (LdapContext) new InitialDirContext(createCommonJNDIEnv()).lookup("ou=Users,dc=example,dc=com");

        } finally {
            resetSSLConfigSocketFactory();
        }
    }

    private void resetSSLConfigSocketFactory() {
        try {
            Field f = SSLConfigSocketFactory.class.getDeclaredField("instance");
            f.setAccessible(true);
            f.set(SSLConfigSocketFactory.class, null);
        } catch (NoSuchFieldException e) {
            e.printStackTrace();
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        }
    }

    private Hashtable createCommonJNDIEnv() {
        Hashtable env = new Hashtable();

        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, "ldaps://localhost:17001/");
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, "uid=admin,ou=system");
        env.put(Context.SECURITY_CREDENTIALS, "secret");
        env.put(Context.SECURITY_PROTOCOL, "ssl");
        env.put("java.naming.ldap.factory.socket", "io.pivotal.gemfire.ldap.SSLConfigSocketFactory");
        return env;
    }

    @Test
    public void shiroAdminAndDevUserTest() {
        SecurityManager securityManager = ToolBox.setupShiro("classpath:gf-ldap-shiro.ini");

        UsernamePasswordToken token = new UsernamePasswordToken("cblack", "password1234");
        Subject currentUser = SecurityUtils.getSubject();

        currentUser.login(token);
        assertThat(currentUser.hasRole("GemFireDeveloper"), equalTo(true));
        assertThat(currentUser.isPermitted("CLUSTER:MANAGE:GATEWAY"), equalTo(true));
    }

    @Test
    public void shiroNegativeTest() {
        SecurityManager securityManager = ToolBox.setupShiro("classpath:gf-ldap-shiro.ini");

        UsernamePasswordToken token = new UsernamePasswordToken("operson", "password1234");
        Subject currentUser = SecurityUtils.getSubject();

        currentUser.login(token);
        assertThat(currentUser.hasRole("GemFireDeveloper"), equalTo(false));
        assertThat(currentUser.isPermitted("CLUSTER:MANAGE:GATEWAY"), equalTo(false));
    }

    @Test
    public void gemfireTest() {
        GemFireLDAPSecurityManager gemFireLDAPSecurityManager = new GemFireLDAPSecurityManager();
        gemFireLDAPSecurityManager.init(new Properties());

        Properties properties = new Properties();
        properties.setProperty(UserPasswordAuthInit.USER_NAME, "cblack");
        properties.setProperty(UserPasswordAuthInit.PASSWORD, "password1234");

        Object principal = gemFireLDAPSecurityManager.authenticate(properties);
        assertThat(gemFireLDAPSecurityManager.authorize(principal, new ResourcePermission(ResourcePermission.Resource.CLUSTER, ResourcePermission.Operation.MANAGE, ResourcePermission.Target.GATEWAY)), equalTo(true));
    }

    @Test
    public void gemfireIntegrationTest() throws InterruptedException, IOException {
        setUpCache();
        Properties properties = new Properties();
        properties.setProperty(USER_NAME, "cblack");
        properties.setProperty(PASSWORD, "password1234");
        Region test = clientCache.createAuthenticatedView(properties).getRegion("test");
        System.out.println("test.get(1) = " + test.get(1));
        test.put(1, "foo");
    }

    @Test(expected = ServerOperationException.class)
    public void gemfireIntegrationTestFailNoPermissions() throws InterruptedException, IOException {
        // The operson has a role - but the roles aren't in the roles to permissions mapping.
        setUpCache();
        Properties properties = new Properties();
        properties.setProperty(USER_NAME, "operson");
        properties.setProperty(PASSWORD, "password1234");
        Region test = clientCache.createAuthenticatedView(properties).getRegion("test");
        System.out.println("test.get(1) = " + test.get(1));
        test.put(1, "foo");
    }

    @Test(expected = ServerOperationException.class)
    public void gemfireIntegrationTestFailUnknowUser() throws InterruptedException, IOException {
        setUpCache();
        Properties properties = new Properties();
        properties.setProperty(USER_NAME, "cblack");
        properties.setProperty(PASSWORD, "password1234");
        Region test = clientCache.createAuthenticatedView(properties).getRegion("test");
        System.out.println("test.get(1) = " + test.get(1));
        test.put(1, "foo");
        System.out.println("LdapApplicationTests.gemfireIntegrationTestFailUnknowUser");
        properties.setProperty(USER_NAME, "fflintstone");
        properties.setProperty(PASSWORD, "password1234");
        test = clientCache.createAuthenticatedView(properties).getRegion("test");
        System.out.println("test.get(1) = " + test.get(1));
        test.put(1, "foo");
    }

    private synchronized void setUpCache() {
        if (clientCache == null) {
            System.setProperty("gemfireSecurityPropertyFile", "src/test/resources/gfsecurity-locator.properties");
            clientCache = new ClientCacheFactory()
                    .set("log-level", "warning")
                    .addPoolLocator("localhost", 10334)
                    .setPoolMultiuserAuthentication(true)
                    .setPoolRetryAttempts(1)
                    .create();

            if (clientCache.getRegion("test") == null) {
                clientCache.createClientRegionFactory(ClientRegionShortcut.PROXY).create("test");
            }
        }
    }

    private static class StreamGobbler implements Runnable {

        BufferedReader stream;

        public StreamGobbler(InputStream stream) {
            this.stream = new BufferedReader(new InputStreamReader(stream));
        }

        @Override
        public void run() {
            try {
                String line;
                while ((line = stream.readLine()) != null) {
                    System.out.println(line);
                }
                stream.close();
            } catch (Exception e) {
                System.out.println("e = " + e);
            }
        }
    }
}