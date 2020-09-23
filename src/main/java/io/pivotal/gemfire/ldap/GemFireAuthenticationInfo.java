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

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;

import java.io.Serializable;
import java.util.Objects;

public class GemFireAuthenticationInfo implements AuthenticationInfo, Serializable {
    private static final long serialVersionUID = 1;
    protected PrincipalCollection principals;
    protected Object credentials;

    // Used this AuthenticationInfo implementation so when we cache the authorization the "password" is taken into
    // account.   The default key impl SimpleAuthenticationInfo doesn't include credentials in the equals or hash.
    public GemFireAuthenticationInfo(Object principal, Object credentials, String realmName) {
        this.principals = new SimplePrincipalCollection(principal, realmName);
        this.credentials = credentials;
    }

    @Override
    public PrincipalCollection getPrincipals() {
        return principals;
    }

    @Override
    public Object getCredentials() {
        return credentials;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        GemFireAuthenticationInfo that = (GemFireAuthenticationInfo) o;

        return this.getPrincipals() != null &&
                that.getPrincipals() != null &&
                Objects.equals(principals, that.principals) &&
                Objects.equals(credentials, that.credentials);
    }

    @Override
    public int hashCode() {
        return Objects.hash(principals, credentials);
    }

    @Override
    public String toString() {
        return "GemFireAuthenticationInfo{" +
                "principals=" + principals +
                '}';
    }
}
