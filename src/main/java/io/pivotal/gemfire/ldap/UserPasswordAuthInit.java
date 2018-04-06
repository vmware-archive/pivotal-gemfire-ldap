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

import org.apache.geode.LogWriter;
import org.apache.geode.distributed.DistributedMember;
import org.apache.geode.distributed.DistributedSystem;
import org.apache.geode.security.AuthInitialize;
import org.apache.geode.security.AuthenticationFailedException;

import java.util.Properties;

/**
 * An {@link AuthInitialize} implementation that obtains the user name and password as the
 * credentials from the given set of properties.
 *
 * To use this class the {@code security-client-auth-init} property should be set to the fully
 * qualified name the static {@code create} method viz.
 * {@code org.apache.geode.security.templates.UserPasswordAuthInit.create}
 *
 * @since GemFire 5.5
 */
public class UserPasswordAuthInit implements AuthInitialize {

    public static final String USER_NAME = "security-username";
    public static final String PASSWORD = "security-password";

    public static AuthInitialize create() {
        return new UserPasswordAuthInit();
    }

    /**
     * Initialize the callback for a client/peer. This is invoked when a new connection from a
     * client/peer is created with the host.
     *
     * @param systemLogger   {@link LogWriter} for system logs
     * @param securityLogger {@link LogWriter} for security logs
     * @throws AuthenticationFailedException if some exception occurs during the initialization
     * @deprecated since Geode 1.0, use init()
     */
    @Override
    public void init(LogWriter systemLogger, LogWriter securityLogger) throws AuthenticationFailedException {

    }

    /**
     * Initialize with the given set of security properties and return the credentials for the
     * peer/client as properties.
     * <p>
     * This method can modify the given set of properties. For example it may invoke external agents
     * or even interact with the user.
     * <p>
     * Normally it is expected that implementations will filter out <i>security-*</i> properties that
     * are needed for credentials and return only those.
     *
     * @param securityProps the security properties obtained using a call to
     *                      {@link DistributedSystem#getSecurityProperties} that will be used for obtaining the
     *                      credentials
     * @param server        the {@link DistributedMember} object of the server/group-coordinator to which
     *                      connection is being attempted
     * @param isPeer        true when this is invoked for peer initialization and false when invoked for
     *                      client initialization
     * @return the credentials to be used for the given <code>server</code>
     * <p>
     * When using Integrated security, all members, peer/client will use the same credentials.
     * but we still need to use these params to support the old authenticator
     * @throws AuthenticationFailedException in case of failure to obtain the credentials
     */
    @Override
    public Properties getCredentials(Properties securityProps, DistributedMember server, boolean isPeer) throws AuthenticationFailedException {

        return getCredentials(securityProps);
    }


    /**
     * @param securityProperties
     * @return the credentials to be used. It needs to contain "security-username" and
     * "security-password"
     * @deprecated As of Geode 1.3, please implement getCredentials(Properties, DistributedMember,
     * boolean)
     */
    @Override
    public Properties getCredentials(Properties securityProperties) {
        String userName = securityProperties.getProperty(USER_NAME);
        if (userName == null) {
            throw new AuthenticationFailedException(
                    "UserPasswordAuthInit: user name property [" + USER_NAME + "] not set.");
        }

        String password = securityProperties.getProperty(PASSWORD);
        if (password == null) {
            password = "";
        }

        Properties securityPropertiesCopy = new Properties();
        securityPropertiesCopy.setProperty(USER_NAME, userName);
        securityPropertiesCopy.setProperty(PASSWORD, password);
        return securityPropertiesCopy;
    }

    @Override
    public void close() {}
}
