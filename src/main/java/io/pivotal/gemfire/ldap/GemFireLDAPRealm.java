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

import org.apache.geode.internal.logging.LogService;
import org.apache.logging.log4j.Logger;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.credential.AllowAllCredentialsMatcher;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.Permission;
import org.apache.shiro.authz.permission.WildcardPermission;
import org.apache.shiro.config.Ini;
import org.apache.shiro.realm.activedirectory.ActiveDirectoryRealm;
import org.apache.shiro.realm.ldap.LdapContextFactory;
import org.apache.shiro.realm.ldap.LdapUtils;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.StringUtils;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapContext;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class GemFireLDAPRealm extends ActiveDirectoryRealm implements InitializeIniSection {

    public static final String REALM_NAME = "GemFireLDAPRealm";
    private static final Logger logger = LogService.getLogger();
    private static final String USERDN_SUBSTITUTION_TOKEN = "{0}";
    private String userDnPrefix;
    private String userDnSuffix;
    private String groupNameAttribute = "cn";
    private String userTemplate = "uid={0},ou=users,dc=example,dc=com";
    private String groupTemplate = "(&(objectClass=*)(uid={0})";
    private String roleNamesDelimiter = ",";
    private Map<String, Collection<Permission>> rolesToPermission;

    public GemFireLDAPRealm() {
        setCredentialsMatcher(new AllowAllCredentialsMatcher());
        setAuthenticationTokenClass(AuthenticationToken.class);
        setRolePermissionResolver(roleString -> rolesToPermission.get(roleString));
    }

    @Override
    public String getName() {
        return REALM_NAME;
    }


    public String getGroupNameAttribute() {
        return groupNameAttribute;
    }

    public void setGroupNameAttribute(String groupNameAttribute) {
        this.groupNameAttribute = groupNameAttribute;
    }

    public String getUserTemplate() {
        return userTemplate;
    }

    public void setUserTemplate(String template) throws IllegalArgumentException {

        if (!StringUtils.hasText(template)) {
            String msg = "User DN template cannot be null or empty.";
            throw new IllegalArgumentException(msg);
        }
        int index = template.indexOf(USERDN_SUBSTITUTION_TOKEN);
        if (index < 0) {
            String msg = "User DN template must contain the '" +
                    USERDN_SUBSTITUTION_TOKEN + "' replacement token to understand where to " +
                    "insert the runtime authentication principal.";
            throw new IllegalArgumentException(msg);
        }
        String prefix = template.substring(0, index);
        String suffix = template.substring(prefix.length() + USERDN_SUBSTITUTION_TOKEN.length());
        if (logger.isDebugEnabled()) {
            logger.debug("Determined user DN prefix [" + prefix + "] and suffix [" + suffix + "]");
        }
        userTemplate = template;
        this.userDnPrefix = prefix;
        this.userDnSuffix = suffix;
    }

    public String getRoleNamesDelimiter() {
        return roleNamesDelimiter;
    }

    public void setRoleNamesDelimiter(String roleNamesDelimiter) {
        this.roleNamesDelimiter = roleNamesDelimiter;
    }

    public String getGroupTemplate() {
        return groupTemplate;
    }

    public void setGroupTemplate(String groupTemplate) {
        this.groupTemplate = groupTemplate;
    }

    @Override
    protected AuthenticationInfo queryForAuthenticationInfo(AuthenticationToken token, LdapContextFactory ldapContextFactory) throws NamingException {
        Object principal = token.getPrincipal();
        Object credentials = token.getCredentials();

        logger.debug("Authenticating user '" + principal + "' through LDAP");

        principal = getLdapPrincipal(token);

        LdapContext ctx = null;
        try {
            ctx = ldapContextFactory.getLdapContext(principal, credentials);
            //context was opened successfully, which means their credentials were valid.  Return the AuthenticationInfo:
            Collection<String> roles = getRoleNamesForUser((String) token.getPrincipal(), ctx);
            if ((roles == null || roles.isEmpty()) && !Collections.disjoint(roles, rolesToPermission.keySet())) {
                logger.info("A user has attempted to log in and their user doesn't have the correct roles '" + principal + "'");
                throw new AuthenticationException("User has been authenticated, however doesn't have any GemFire roles - user -'" + principal + "'");
            }
            return createAuthenticationInfo(token, principal, credentials, ctx);
        } finally {
            LdapUtils.closeContext(ctx);
        }
    }

    protected AuthenticationInfo createAuthenticationInfo(AuthenticationToken token, Object ldapPrincipal,
                                                          Object ldapCredentials, LdapContext ldapContext)
            throws NamingException {
        return new SimpleAuthenticationInfo(token.getPrincipal(), token.getCredentials(), getName());
    }

    protected Object getLdapPrincipal(AuthenticationToken token) {
        Object principal = token.getPrincipal();
        if (principal instanceof String) {
            String sPrincipal = (String) principal;
            return getUserDn(sPrincipal);
        }
        return principal;
    }

    protected String getUserDn(String principal) throws IllegalArgumentException, IllegalStateException {
        if (!StringUtils.hasText(principal)) {
            throw new IllegalArgumentException("User principal cannot be null or empty for User DN construction.");
        }
        String prefix = getUserDnPrefix();
        String suffix = getUserDnSuffix();
        if (prefix == null && suffix == null) {
            logger.debug("userTemplate property has not been configured, indicating the submitted " +
                    "AuthenticationToken's principal is the same as the User DN.  Returning the method argument " +
                    "as is.");
            return principal;
        }

        int prefixLength = prefix != null ? prefix.length() : 0;
        int suffixLength = suffix != null ? suffix.length() : 0;
        StringBuilder sb = new StringBuilder(prefixLength + principal.length() + suffixLength);
        if (prefixLength > 0) {
            sb.append(prefix);
        }
        sb.append(principal);
        if (suffixLength > 0) {
            sb.append(suffix);
        }
        return sb.toString();
    }

    protected String getUserDnPrefix() {
        return userDnPrefix;
    }

    protected String getUserDnSuffix() {
        return userDnSuffix;
    }

    @Override
    protected AuthorizationInfo queryForAuthorizationInfo(PrincipalCollection principals, LdapContextFactory ldapContextFactory) throws NamingException {

        String username = (String) getAvailablePrincipal(principals);

        // Perform context search
        LdapContext ldapContext = ldapContextFactory.getSystemLdapContext();

        Set<String> roleNames;

        try {
            roleNames = getRoleNamesForUser(username, ldapContext);
        } finally {
            LdapUtils.closeContext(ldapContext);
        }

        return buildAuthorizationInfo(roleNames);
    }

    private Set<String> getRoleNamesForUser(String username, LdapContext ldapContext) throws NamingException {
        Set<String> roleNames;
        roleNames = new LinkedHashSet<>();

        SearchControls searchCtls = new SearchControls();
        searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);

        String userPrincipalName = username;
        if (principalSuffix != null) {
            userPrincipalName += principalSuffix;
        }

        //SHIRO-115 - prevent potential code injection:
        Object[] searchArguments = new Object[]{userPrincipalName};

        NamingEnumeration answer = ldapContext.search(searchBase, groupTemplate, searchArguments, searchCtls);

        while (answer.hasMoreElements()) {
            SearchResult sr = (SearchResult) answer.next();

            if (logger.isDebugEnabled()) {
                logger.debug("Retrieving group names for user [" + sr.getName() + "]");
            }

            Attributes attrs = sr.getAttributes();

            if (attrs != null) {
                Collection<String> groupNames = LdapUtils.getAllAttributeValues(attrs.get(groupNameAttribute));
                roleNames.addAll(groupNames);
            }
        }
        return roleNames;
    }

    @Override
    public void initialize(Ini.Section section) {
        Map<String, Collection<Permission>> mapping = new ConcurrentHashMap<>();

        section.entrySet().forEach(e -> {
            List<String> split = Arrays.asList(e.getValue().split(roleNamesDelimiter));
            ArrayList<Permission> permissions = new ArrayList<>();
            split.forEach(s -> permissions.add(new WildcardPermission(s)));
            mapping.put(e.getKey(), permissions);
        });
        this.rolesToPermission = mapping;
    }
}
