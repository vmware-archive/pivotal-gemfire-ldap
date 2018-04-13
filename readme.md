# Yet Another GemFire Implementation for LDAP

[![Build Status](https://travis-ci.org/Pivotal-Field-Engineering/pivotal-gemfire-ldap.svg?branch=master)](https://travis-ci.org/Pivotal-Field-Engineering/pivotal-gemfire-ldap) [![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

YAG-LDAP or YAGI-LDAP - if you have a better name lets use it.

**Why** - I was looking around for an LDAP GemFire implementation that allowed some level of customization and did not drag in a bunch of dependencies.   If we look at the dependency tree I think this project has hit the nail on the head - only GemFire.

For the customization I did try.   

## Customization
### SSL
For SSL I provide a SSL socket factory implementation that allows the user to separate the concerns of the LDAP from GemFire and its apps.   My thinking was LDAP would governed by an enterprise standards body and the database and its apps could be governed by yet another enterprise standards body.

Since customization is the keyword here you don't have to use the SSL implementation I have provided.

###LDAP

For LDAP and the configuration I took my lead from Apache Shiro, which happens to be  GemFire's internal security mechanism.    I extended the Shiro ActiveDirectoryRealm to enable my implementation to map LDAP roles to Geode Permissions.  

Hopefully you find this project useful.

## Setup

It all starts with the shiro securty manager that is going to be doing the work.   To get Shiro to work it needs to be configured, and that is done through an INI file.

Both INI files and Shiro are well documented so I will rely on those communities to help out with get an understanding of this project over and above what I can comminicate.

Lets walk through the test file which can be seen in it entirety at : [Example INI used in TEST](src/test/resources/gf-ldap-shiro.ini).

### Setup up the LDAP Connection

In the following snippet we setup the Shiro implementation for JNDI.   The first line is basically saying instanciate this class and then set all of the these properties.

Awesome - so now Java Doc comes in real handy.  So I there is some cool Shiro has or you would like to extend the Shiro docs and community should help out.

Most of the settings should be familar with, URL for LDAP, the system login and password for queries that aren't just authentication.   Pooling is one that I read about and the Shrio docs say that pooling does not help since the reuse of connections are low.  I can see LDAP connections going down if caching was turned on.

The biggest item to note is the ``io.pivotal.gemfire.ldap.SSLConfigSocketFactory`` I will go over that in another section.   That SSL Socket Factory has its own properties that can be loaded from disk.

```
[main]
contextFactory = org.apache.shiro.realm.ldap.JndiLdapContextFactory
contextFactory.url = ldaps://localhost:17001
contextFactory.systemUsername = uid=admin,ou=system
contextFactory.systemPassword = secret
contextFactory.authenticationMechanism = SIMPLE
contextFactory.poolingEnabled=false
contextFactory.environment[java.naming.ldap.factory.socket] = io.pivotal.gemfire.ldap.SSLConfigSocketFactory
contextFactory.environment[java.naming.security.protocol] = ssl
```
### Setting up the GemFire Realm
The next section is setting up how to authenticate users on your LDAP and the implemention that we are going to use ``io.pivotal.gemfire.ldap.GemFireLDAPRealm``.   That bit of code is an extention of the Shiro ``ActiveDirectoryRealm``.   I extended that class since the ``ActiveDirectoryRealm`` had a concept of groups and mapped permissions to those groups.

* searchBase - the distingished name where the search begins
* userDnTemplate - the {0} gets replaced for finding the user.   Example to authenitcate a user id of ``cblack`` the code will query for ``uid=cblack,ou=Users,dc=example,dc=com``
* groupMemberAttribute - This indicates the attribute to search for the user id
* groupNameAttribute - This is the attribute the group name would be under - the default is ``cn``

````
gemfireRealm = io.pivotal.gemfire.ldap.GemFireLDAPRealm
gemfireRealm.ldapContextFactory = $contextFactory
gemfireRealm.searchBase = dc=example,dc=com
gemfireRealm.userDnTemplate = uid={0},ou=Users,dc=example,dc=com
gemfireRealm.groupMemberAttribute=uniquemember
````
It might make sense to see how above matches to how I setup the LDAP for the tests.   If you have another LDIF file that we should test out submit a ticket and we can work it in there.

[Example LDIF used in TEST](src/test/resources/sample.ldif)

#### Example Group LDIF
```$ldif
dn: cn=GemFireDeveloper,ou=groups,dc=example,dc=com
objectClass: groupOfUniqueNames
objectClass: top
ou: groups
description: GemFire developers can read and write regions
uniquemember: uid=cblack, ou=Users, dc=example,dc=com
cn: GemFireDeveloper
```
#### Example User LDIF

```$ldif
dn: uid=cblack,ou=Users,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
cn: Charlie Black
sn: Black
uid: cblack
userPassword: password1234

```
### Role to Permission map

The remainder of the ``INI`` file has the LDAP roles to permissions mapping.

The INI Section name maps back to the name of the Shiro Realm.   I have added an extra interface tags Realms that need their Section to finish initialize.
```
;;; Below is the mapping of the LDAP Roles to permissions in GemFire
;;; Feel free to get creative - check out all of the various permissions in the docs:
;;;
;;; http://gemfire.docs.pivotal.io/geode/managing/security/implementing_authorization.html

[gemfireRealm]
GemFireAdmin = *:*
GemFireDeveloper = data:read,data:write
GemFireReadOnly = data:read
GemFireGatewayManager = CLUSTER:MANAGE:GATEWAY
```
[Example INI used in test ](src/test/resources/gf-ldap-shiro.ini)

# How to build

## SSL Key store and Trust stores

Initially I was thinking about binding the servers to something other than local hosts - so I scripted the generation of the certs.   So that needs to run first on all hosts that are going to run the tests.   We need to generate certs for ``ldap`` and ``gemfire``.

```
<project home>/scripts/generateCerts.sh ldap
<project home>/scripts/generateCerts.sh gemfire

```

The script will make a ``CA`` and sign a cert so it will closely emulate what I have seen at customer sites.

The only thing I did that isn't common is I placed the key and trust in the same store.

[The script to generate the certs](scripts/generateCerts.sh)

##  Build & Test

Since this is just an integration of two components I only made integration tests.

When the test starts up it launches an LDAP server with a configuration that is known.    Then starts up GemFire configured to use that LDAP server and schema. At the end of the test everything is brought down.   

Note the GemFire logs etc are not cleaned up so they can inspected.   Those artifacts are located in ``<project home>/data``.

### The scripts to start GemFire for test


* [Start GemFire and configure a region](src/test/scripts/startGeode.sh)
* [Shutdown GemFire](src/test/scripts/shutdownGeode.sh)

TIP: When powering off a GemFire system it is bad practice to stop each node independently.   In practice this emulates what failure actually looks as 1 by 1 is stopped and the other nodes are still running.   Now each node in the system will have a different "view" on who was in the distributed system so starting up is a pain.   

It is best to ``shutdown`` the GemFire system using the ``gfsh shutdown`` command.    This will gracefully cause the GemFire systems to shutdown and will beable to accelerate start up because quorum can be established easily.

### Build commands 
```
cd <project home>
./gradlew clean build
```

After that the build artifacts that are needed are located in  ``<project home>/build/libs``.

```
Overall Coverage Summary 

Package	      Class, %      Method, %         Line, %
all classes	  100% (5/ 5)   73.5% (36/ 49)    75.9% (180/ 237)
```
