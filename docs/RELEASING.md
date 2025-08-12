# Releasing to Maven Central

## For Yellowbrick Maintainers

At this time releases of the JDBC driver are strictly handled by Yellowbrick Data engineering.
This document is for the release engineering team.

## Introduction

The maven build is setup to build and compile the JDBC driver.
Releasing to maven central involves setup of a GPG signing key,
and setup of maven central api key.

See: [Maven Central Portal](https://central.sonatype.org/publish/publish-portal-maven/)


## Setup

### Import the GPG signing key from vault


- **Step 1**: save the vault gpg signing key to local file: `gpg.privatekey.pem`
- **Step 2**: import the key:
```
gpg --import  gpg.privatekey.pem
```
- **Step 3**: extraact the keyname to env var:
```
% gpg --list-keys|grep -C 1 'Yellowbrick Data, Inc. <gpginfo@yellowbrick.com>'
      <REDACTED-GPG_KEYNAME>
uid           [ unknown] Yellowbrick Data, Inc. <gpginfo@yellowbrick.com>
sub   rsa4096 2024-03-25 [E] [expires: 2028-03-25]
```
- **Step 4**: copy the gpg key passphrase from vault to clipboard/other for env var below


### Add GPG information to ~/.m2/settings.xml


```
<settings>
  <profiles>
    <profile>
      <id>release</id>
      <properties>
        <gpg.keyname>${env.GPG_KEYNAME}</gpg.keyname>
        <gpg.passphrase>${env.GPG_PASSPHRASE}</gpg.passphrase>
      </properties>
    </profile>
  </profiles>
</settings>
```

### Set GPG signing environment variables

Export these variables as `GPG_KEYNAME` and `GPG_PASSPHRASE`


```
export GPG_KEYNAME=<key-name>
export GPG_PASSPHRASE=<key-password>
```

### Create a maven central API signing key

In the maven central portal, authenticate to the io.yellowbrick namespace,
and create an API key.

See: [Generating a Portal Token for Publishing](https://central.sonatype.org/publish/generate-portal-token/)

### Add Maven Central API key to ~/.m2/settings.xml

```
<settings>
  <servers>
    <server>
      <id>central</id>
      <username>${env.MAVEN_PUBLISH_USERNAME}</username>
      <password>${env.env.MAVEN_PUBLISH_PASSWORD}</password>
    </server>
  </servers>
</settings>
```

### Set maven central account environment variables


Export these variables as `MAVEN_PUBLISH_USERNAME` and `MAVEN_PUBLISH_PASSWORD`

```
export MAVEN_PUBLISH_USERNAME=<api-key-username>
export MAVEN_PUBLISH_PASSWORD=<api-key-password>
```


## Publish

Run maven build.

```
mvn clean deploy -Prelease
```

## Release

If all goes well, you will be able to visit the sonatype publishing portal
and trigger the final release from staging.

See [Publishing](https://central.sonatype.com/publishing)
