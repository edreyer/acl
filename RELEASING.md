# Releasing

This project is configured to publish its Maven artifacts to Maven Central through Sonatype's Central Publisher Portal using Gradle and the `com.gradleup.nmcp` plugin.

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
- `https://central.sonatype.org/publish/publish-portal-gradle/`

## Maven Credentials

Create or update `~/.gradle/gradle.properties` with your Central Portal token:

```properties
centralPortalUsername=...
centralPortalPassword=...
signingInMemoryKey=...
signingInMemoryKeyPassword=...
```

## GPG

Sanity checks:

```bash
gpg --list-secret-keys --keyid-format LONG
gpg --keyserver keyserver.ubuntu.com --send-keys YOUR_KEY_ID
```

If your key is protected by a passphrase, make sure the signing key password is configured before running Gradle.

## Release Steps

1. Ensure the working tree is clean.
2. Confirm `CHANGELOG.md` reflects the release, including any compatibility notes.
3. Confirm the root project version is the intended release version.
4. Run a full local verification build:

```bash
./gradlew clean test
```

5. Create the release tag that matches the POM SCM metadata:

```bash
git tag v0.2.0
git push origin v0.2.0
```

6. Publish the release bundle to Central:

```bash
./gradlew publishAllPublicationsToCentralPortal
```

The current configuration uses the Central Portal plugin with automatic publication enabled. If the upload validates successfully, Sonatype will complete the release flow automatically.

## What Gets Published

The current project publishes a single `acl` artifact under `io.liquidsoftware`.
