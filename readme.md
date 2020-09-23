# Yet Another GemFire Implementation for LDAP

[![Build Status](https://travis-ci.org/Pivotal-Field-Engineering/pivotal-gemfire-ldap.svg?branch=master)](https://travis-ci.org/Pivotal-Field-Engineering/pivotal-gemfire-ldap) [![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

YAG-LDAP or YAGI-LDAP - if you have a better name lets use it.

**Why** - I was looking around for an LDAP GemFire implementation that allowed some level of customization and did not drag in a bunch of dependencies.   If we look at the dependency tree I think this project has hit the nail on the head - only GemFire.

For the customization I did try.   

## Customization
### SSL
For SSL I provide a SSL socket factory implementation that allows the user to separate the concerns of the LDAP from GemFire and its apps.   My thinking was LDAP would governed by an enterprise standards body and the database and its apps could be governed by yet another enterprise standards body.

Since customization is the keyword here you don't have to use the SSL implementation I have provided.

### LDAP

For LDAP and the configuration I took my lead from Apache Shiro, which happens to be  GemFire's internal security mechanism.    I extended the Shiro ActiveDirectoryRealm to enable my implementation to map LDAP roles to Geode Permissions.  

Hopefully you find this project useful.

## Setup

It all starts with the shiro securty manager that is going to be doing the work.   To get Shiro to work it needs to be configured, and that is done through an INI file.

Both INI files and Shiro are well documented so I will rely on those communities to help out with get an understanding of this project over and above what I can comminicate.

Lets walk through the test file which can be seen in it entirety at : [Example INI used in TEST](src/test/resources/gf-ldap-shiro.ini).

NOTE: It is highly recommended to use TLS/SSL since the passwords are going to go over the network.

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
* userTemplate - the {0} gets replaced for finding the user.   Example to authenitcate a user id of ``cblack`` the code will authenticate for ``uid=cblack,ou=Users,dc=example,dc=com``
* groupNameAttribute - This is the attribute the group name would be under - the default is ``cn``
* groupTemplate - the principal gets added in as the parameter to the template.   Example to authorize a "user" if of ``cblack`` the code will use the template and pass in a parameter of ``cblack`` to the search for the group the user belongs to.

````
gemfireRealm = io.pivotal.gemfire.ldap.GemFireLDAPRealm
gemfireRealm.ldapContextFactory = $contextFactory
gemfireRealm.searchBase = "dc=example,dc=com"
gemfireRealm.userTemplate = uid={0},ou=Users,dc=example,dc=com
gemfireRealm.groupTemplate = (&(objectClass=*)(uniquemember=uid={0},ou=Users,dc=example,dc=com))
gemfireRealm.groupNameAttribute=cn
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
### Adding Caching To GemFire Realm

Having the system use a LDAP server for every authorization and authentication operation the overall GemFire performance will take a hit.   To alleviate this performance burden there is a Shiro cache implementation backed by GemFire.    

The cached LDAP information  is stored in a replicated region so the client can use any server and take advantage of the cached LDAP decision.    The storage for this information is in special management regions which are not accessible by users. 

To configure Shiro we make the following changes to the `shiro.ini` file:

```

cacheManager = io.pivotal.gemfire.ldap.GemFireShiroCacheManager

;;; entryTimeToLiveSeconds takes precedence over entryIdleTimeoutSeconds
;;; Time is entered in seconds.  

;;; entryTimeToLiveSeconds - The eviction timer starts as soon as the entry is placed into memory. 
cacheManager.entryTimeToLiveSeconds = 500

;;; entryIdleTimeoutSeconds - The eviction timer starts on last access time.
;;;cacheManager.entryIdleTimeoutSeconds = 0

;;; Set the cache manager on the Shiro Security Manager
securityManager.cacheManager = $cacheManager
...
;;; Then we inform the gemfire realm that it will cache AA infomrmation.   
gemfireRealm.authenticationCachingEnabled=true
gemfireRealm.authorizationCachingEnabled=true
```
 
### Role to Permission map

The remainder of the ``INI`` file has the LDAP roles to permissions mapping.

The INI Section name maps back to the name of the Shiro Realm.   I have added an extra interface tags Realms that need their Section to finish initialize.

**Note:** Names are case sensitive.  
```
;;; Below is the mapping of the LDAP Roles to permissions in GemFire
;;; Feel free to get creative - check out all of the various permissions in the docs:
;;;
;;; http://gemfire.docs.pivotal.io/geode/managing/security/implementing_authorization.html

[gemfireRealm]
GemFireAdmin = *:*
GemFireDeveloper = DATA:READ,DATA:WRITE
GemFireReadOnly = DATA:READ
GemFireGatewayManager = CLUSTER:MANAGE:GATEWAY
```
[Example INI used in test ](src/test/resources/gf-ldap-shiro.ini)

# How to build

The build makes some assumtions about the build machine since it uses scripts to create SSL certs or start up other processes.   At this time the build needs to be executed on a linux or mac.  

## SSL Key store and Trust stores

As the test runs it generates certs.   Generatation of those certs can be seen in the following file:

[The script to generate the certs](scripts/generateCerts.sh)

The script will detect if a jks file exists and not regenerate the certs.   So if you need the certs to be regenerated then just remove the <project home>/certs directory.

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

## Discussion about tests

The tests utilize a feature in GemFire called authenticated view.   It allows the developer run operations as a separate and distinct user then the application as a whole.   This allows the the application to establish a connection pool as the application, then the application can delegate authorization of the application user to GemFire.   

Since we are testing authentication/authorization I thought authenticated views would be a great feature to use vs setting up and tearing down the connection pool for every test.   This way the developer can test many users in a given test and also allows the tests to complete faster since each test doesn't include the tear down and setup of the connection pool.
 
# Looking for support

This driver is supported by people like you **The GemFire community** and is not part of the GemFire product.    It is an extension that the services team uses at several customer installations.   If you would ike to use it feel free to review and deploy at your own risk and GemFire support does not include this extension.
  
If you are you are looking for something more our services team is here to help.   Just ask your account exectuve that you need services help getting GemFire to work with your LDAP and they will connect you to the right team member.
