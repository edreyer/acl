# Releasing

This project is configured to publish its Maven artifacts to Maven Central through the Central Publisher Portal.

## Prerequisites

Before the first release, make sure all of the following are true:

- the `io.liquidsoftware` namespace is available in your account at `https://central.sonatype.com`
- you have generated a Central Portal user token
- you have a working GPG key for signing artifacts
- your public GPG key has been uploaded to a public keyserver

Central docs:

- `https://central.sonatype.org/register/namespace/`
- `https://central.sonatype.org/publish/generate-portal-token/`
- `https://central.sonatype.org/publish/requirements/`
- `https://central.sonatype.org/publish/requirements/gpg/`
- `https://central.sonatype.org/publish/publish-portal-maven/`

## Maven Credentials

Create or update `~/.m2/settings.xml` with your Central token:

```xml
<settings>
  <servers>
    <server>
      <id>central</id>
      <username><!-- Central token username --></username>
      <password><!-- Central token password --></password>
    </server>
  </servers>
</settings>
```

The server id must stay `central` because that is what the root POM uses.

## GPG

Sanity checks:

```bash
gpg --list-secret-keys --keyid-format LONG
gpg --keyserver keyserver.ubuntu.com --send-keys YOUR_KEY_ID
```

If your key is protected by a passphrase, make sure `gpg-agent` is available before running Maven.

## Release Steps

1. Ensure the working tree is clean.
2. Confirm the root project version is the intended release version.
3. Run a full local verification build:

```bash
mvn clean verify
```

4. Create the release tag that matches the POM SCM metadata:

```bash
git tag v0.1.0
git push origin v0.1.0
```

5. Publish the release bundle to Central:

```bash
mvn -Pcentral-publish deploy
```

The current configuration uses:

- `autoPublish=false`
- `waitUntil=VALIDATED`

That means Maven uploads and validates the release bundle, but does not publish it automatically. Finish the release in the Central Portal UI after validation succeeds.

## What Gets Published

Each module is published independently under `io.liquidsoftware`:

- `acl-core`
- `acl-arrow`
- `acl-ktor`
- `acl-spring-security`
- `acl-spring-security-arrow`

The root `acl` artifact is published as a parent/aggregator `pom`.
