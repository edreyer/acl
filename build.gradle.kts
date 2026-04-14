import org.gradle.internal.impldep.org.apache.commons.compress.harmony.pack200.PackingUtils.config

plugins {
  kotlin("jvm") version "2.3.10"
  id("com.vanniktech.maven.publish") version "0.36.0"
  id("dev.detekt") version "2.0.0-alpha.2"
}

group = "io.liquidsoftware"
version = "0.3.0"

repositories {
  mavenCentral()
}

dependencies {
  testImplementation(kotlin("test"))
}

kotlin {
  jvmToolchain(21)
}

tasks.test {
  useJUnitPlatform()
}

detekt {
  toolVersion = "2.0.0-alpha.2"
  config.setFrom(files("$rootDir/detekt.yml"))
  buildUponDefaultConfig = true
}

mavenPublishing {
  publishToMavenCentral()

  pom {
    name.set("ACL")
    description.set("Kotlin ACL library for answering whether subject A can access resource B.")
    url.set("https://github.com/edreyer/acl")

    licenses {
      license {
        name.set("MIT License")
        url.set("https://opensource.org/license/mit")
        distribution.set("repo")
      }
    }

    developers {
      developer {
        id.set("edreyer")
        name.set("Erik Dreyer")
        url.set("https://github.com/edreyer")
      }
    }

    scm {
      connection.set("scm:git:https://github.com/edreyer/acl.git")
      developerConnection.set("scm:git:ssh://git@github.com/edreyer/acl.git")
      url.set("https://github.com/edreyer/acl")
    }
  }
}
