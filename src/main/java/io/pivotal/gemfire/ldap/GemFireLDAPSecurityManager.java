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

import org.apache.geode.distributed.DistributedSystem;
import org.apache.geode.internal.logging.LogService;
import org.apache.geode.security.AuthenticationFailedException;
import org.apache.geode.security.ResourcePermission;
import org.apache.geode.security.SecurityManager;
import org.apache.logging.log4j.Logger;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.config.Ini;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.support.DelegatingSubject;

import java.io.IOException;
import java.util.Properties;

public class GemFireLDAPSecurityManager implements SecurityManager {

    private static final Logger logger = LogService.getLogger();

    private org.apache.shiro.mgt.SecurityManager securityManager;

    public GemFireLDAPSecurityManager() {

    }

    /**
     * Initialize the SecurityManager. This is invoked when a cache is created
     *
     * @param securityProps the security properties obtained using a call to
     *                      {@link DistributedSystem#getSecurityProperties}
     * @throws AuthenticationFailedException if some exception occurs during the initialization
     */
    @Override
    public void init(Properties securityProps) {

        try {
            Properties properties = ToolBox.loadGFLDAPProperties();
            String shiroIniFile = properties.getProperty(ToolBox.GF_LDAP_SHIRO_INI_FILE);
            logger.error("GemFire LDAP Shiro file is = " + shiroIniFile);
            if (logger.isDebugEnabled()) {
                logger.debug("GemFire LDAP Shiro file is = " + shiroIniFile);
            }
            securityManager = ToolBox.setupShiro(shiroIniFile);
        } catch (IOException e) {
            logger.error("Could not instantiate security subsystem.", e);
            throw new AuthenticationFailedException("Could not instanciate security subsystem.", e);
        }
    }
    /**
     * Verify the credentials provided in the properties
     *
     * @param credentials it contains the security-username and security-password as keys of the
     *                    properties
     * @return a serializable principal object
     * @throws AuthenticationFailedException
     */
    @Override
    public Object authenticate(Properties credentials) throws AuthenticationFailedException {
        final String userName = credentials.getProperty(UserPasswordAuthInit.USER_NAME);
        try {
            if (userName == null) {
                throw new AuthenticationFailedException("LdapUserAuthenticator: user name property ["
                        + UserPasswordAuthInit.USER_NAME + "] not provided");
            }

            String password = credentials.getProperty(UserPasswordAuthInit.PASSWORD);
            if (password == null) {
                password = "";
            }
            UsernamePasswordToken token = new UsernamePasswordToken(userName, password);
            DelegatingSubject subject = new DelegatingSubject(securityManager);
            subject.login(token);
            return subject.getPrincipals();
        } catch (Exception e) {
            logger.error("Could not authenticate : ", e);
            throw new AuthenticationFailedException("Could not authenticate '" + userName + "'");
        }
    }


    /**
     * Authorize the ResourcePermission for a given Principal
     *
     * @param principal  The principal that's requesting the permission
     * @param permission The permission requested
     * @return true if authorized, false if not
     */
    @Override
    public boolean authorize(Object principal, ResourcePermission permission) {
        PrincipalCollection principalCollection = (PrincipalCollection) principal;
        return securityManager.isPermitted(principalCollection, permission);
    }

    /**
     * Close any resources used by the SecurityManager, called when a cache is closed.
     */
    @Override
    public void close() {

    }
}
