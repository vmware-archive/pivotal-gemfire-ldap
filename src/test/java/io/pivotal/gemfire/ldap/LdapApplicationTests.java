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
import org.apache.geode.cache.execute.FunctionException;
import org.apache.geode.cache.execute.FunctionService;
import org.apache.geode.cache.execute.ResultCollector;
import org.apache.geode.security.ResourcePermission;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
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
import javax.naming.NamingException;
import javax.naming.directory.*;
import javax.naming.ldap.Control;
import javax.naming.ldap.LdapContext;
import javax.naming.ldap.SortControl;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Field;
import java.util.Collection;
import java.util.Hashtable;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

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
        SecurityManager securityManager = ToolBox.setupShiro("classpath:inprocess-ldap-shiro.ini");

        UsernamePasswordToken token = new UsernamePasswordToken("cblack", "password1234");
        Subject currentUser = SecurityUtils.getSubject();

        currentUser.login(token);
        assertThat(currentUser.hasRole("GemFireDeveloper"), equalTo(true));
        assertThat(currentUser.isPermitted("CLUSTER:MANAGE:GATEWAY"), equalTo(true));
    }

    @Test
    public void checkForClusterManage() {
        SecurityManager securityManager = ToolBox.setupShiro("classpath:inprocess-ldap-shiro.ini");

        UsernamePasswordToken token = new UsernamePasswordToken("clusterManage", "password1234");
        Subject currentUser = SecurityUtils.getSubject();
        currentUser.login(token);
        ResourcePermission resourcePermission = new ResourcePermission("CLUSTER", "MANAGE");
        assertThat(currentUser.hasRole("GemFireClusterManage"), equalTo(true));
        assertThat(currentUser.isPermitted(resourcePermission), equalTo(true));
    }

    @Test(expected = AuthenticationException.class)
    public void shiroNegativeTest() {
        SecurityManager securityManager = ToolBox.setupShiro("classpath:inprocess-ldap-shiro.ini");

        UsernamePasswordToken token = new UsernamePasswordToken("operson", "password1234");
        Subject currentUser = SecurityUtils.getSubject();

        currentUser.login(token);
        assertThat(currentUser.hasRole("GemFireDeveloper"), equalTo(false));
        assertThat(currentUser.isPermitted("CLUSTER:MANAGE"), equalTo(false));
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
    public void specialGroupNameTest() {
        setUpCache();
        Properties properties = new Properties();
        properties.setProperty(USER_NAME, "specialgroupname");
        properties.setProperty(PASSWORD, "password1234");
        Region test = clientCache.createAuthenticatedView(properties).getRegion("test");
        System.out.println("test.get(1) = " + test.get(1));
        test.put(1, "foo");
    }

    @Test
    public void specialGroupNameTestInProc() {
        GemFireLDAPSecurityManager gemFireLDAPSecurityManager = new GemFireLDAPSecurityManager();
        gemFireLDAPSecurityManager.init(new Properties());

        Properties properties = new Properties();
        properties.setProperty(UserPasswordAuthInit.USER_NAME, "specialgroupname");
        properties.setProperty(UserPasswordAuthInit.PASSWORD, "password1234");

        Object principal = gemFireLDAPSecurityManager.authenticate(properties);
        assertThat(gemFireLDAPSecurityManager.authorize(principal, new ResourcePermission(ResourcePermission.Resource.DATA, ResourcePermission.Operation.READ)), equalTo(true));
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
    public void gemfireIntegrationTestFailCachedView() throws InterruptedException, IOException {
        // The operson has a role - but the roles aren't in the roles to permissions mapping.
        setUpCache();
        Properties properties = new Properties();
        properties.setProperty(USER_NAME, "cblack");
        properties.setProperty(PASSWORD, "password1234");
        Region test = clientCache.createAuthenticatedView(properties).getRegion("test");
        System.out.println("test.get(1) = " + test.get(1));
        test.put(1, "foo");
        properties.setProperty(PASSWORD, "fail_password");
        test = clientCache.createAuthenticatedView(properties).getRegion("test");
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

    @Test
    public void addGroup() throws NamingException {

        clearLDAPCertEnv();
        Hashtable env = createCommonJNDIEnv();
        LdapContext ctx = (LdapContext) new InitialDirContext(env).lookup("ou=groups,dc=example,dc=com");

        SecurityManager securityManager = ToolBox.setupShiro("classpath:inprocess-ldap-shiro.ini");

        UsernamePasswordToken token = new UsernamePasswordToken("switchRoles", "password1234");
        Subject currentUser = SecurityUtils.getSubject();

        try {
            currentUser.login(token);
            assertThat(currentUser.hasRole("GemFireDeveloper"), equalTo(false));
        } catch (AuthenticationException e) {
            System.out.println("This is ok - " + e.getMessage());
        }

        ModificationItem[] mods = new ModificationItem[1];
        mods[0] = new ModificationItem(DirContext.ADD_ATTRIBUTE,
                new BasicAttribute("uniquemember", "uid=switchRoles,ou=Users,dc=example,dc=com"));
        ctx.modifyAttributes("cn=GemFireDeveloper", mods);

        currentUser.login(token);
        assertThat(currentUser.hasRole("GemFireDeveloper"), equalTo(true));

        mods[0] = new ModificationItem(DirContext.REMOVE_ATTRIBUTE,
                new BasicAttribute("uniquemember", "uid=switchRoles,ou=Users,dc=example,dc=com"));
        ctx.modifyAttributes("cn=GemFireDeveloper", mods);

        try {
            currentUser.login(token);
            assertThat(currentUser.hasRole("GemFireDeveloper"), equalTo(false));
        } catch (AuthenticationException e) {
            System.out.println("This is ok - " + e.getMessage());
        }
    }

    @Test
    public void addGroupTestCaching() throws NamingException {
        setUpCache();
        clearLDAPCertEnv();
        Hashtable env = createCommonJNDIEnv();
        LdapContext ctx = (LdapContext) new InitialDirContext(env).lookup("ou=groups,dc=example,dc=com");

        ModificationItem[] mods = new ModificationItem[1];

        try {
            mods[0] = new ModificationItem(DirContext.REMOVE_ATTRIBUTE,
                    new BasicAttribute("uniquemember", "uid=switchRoles,ou=Users,dc=example,dc=com"));
            ctx.modifyAttributes("cn=GemFireDeveloper", mods);
        } catch (NamingException e) {
            System.out.println("Make sure the user doesn't have permissions in LDAP");
        }

        Properties properties = new Properties();
        properties.setProperty(USER_NAME, "switchRoles");
        properties.setProperty(PASSWORD, "password1234");
        Region test = null;
        try {
            test = clientCache.createAuthenticatedView(properties).getRegion("test");
            System.out.println("test.get(1) = " + test.get(1));
            test.put(1, "foo");
            Integer foo;

        } catch (Exception e) {
            System.out.println("should fail since the user doesn't have permission");
        }
        try {
            // I don't like timing test - but not sure how to get the event that the data has been evicted from the "internal" regions.
            // check the gf-ldap-shiro.ini file for eviction time I am just doing +1 to make sure the entry has been removed
            Thread.sleep(TimeUnit.SECONDS.toMillis(2));
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        mods[0] = new ModificationItem(DirContext.ADD_ATTRIBUTE,
                new BasicAttribute("uniquemember", "uid=switchRoles,ou=Users,dc=example,dc=com"));
        ctx.modifyAttributes("cn=GemFireDeveloper", mods);

        try {
            //don't wrap in a try catch because we should be authenticated
            test = clientCache.createAuthenticatedView(properties).getRegion("test");
            System.out.println("test.get(1) = " + test.get(1));
            test.put(1, "foo");
            try {
                //this is just so I can see the output that the get will miss
                Thread.sleep(TimeUnit.SECONDS.toMillis(2));
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            System.out.println("test.get(1) = " + test.get(1));
        } finally {
            mods[0] = new ModificationItem(DirContext.REMOVE_ATTRIBUTE,
                    new BasicAttribute("uniquemember", "uid=switchRoles,ou=Users,dc=example,dc=com"));
            ctx.modifyAttributes("cn=GemFireDeveloper", mods);
        }
    }

    @Test
    public void tryAFunctionWithPermission() {
        setUpCache();

        Properties properties = new Properties();
        properties.setProperty(USER_NAME, "cblack");
        properties.setProperty(PASSWORD, "password1234");
        Region test = clientCache.createAuthenticatedView(properties).getRegion("test");
        ResultCollector collector = FunctionService.onRegion(test).execute(TestFunction.ID);
        Collection results = (Collection) collector.getResult();
    }

    @Test(expected = FunctionException.class)
    public void tryAFunctionWithoutPermission() {
        setUpCache();

        Properties properties = new Properties();
        properties.setProperty(USER_NAME, "readOnly");
        properties.setProperty(PASSWORD, "password1234");
        Region test = clientCache.createAuthenticatedView(properties).getRegion("test");
        ResultCollector collector = FunctionService.onRegion(test).execute(TestFunction.ID);
        Collection results = (Collection) collector.getResult();
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