import org.gradle.api.tasks.bundling.Jar

plugins {
  kotlin("jvm") version "2.3.10"
  id("org.jetbrains.dokka") version "2.1.0"
  id("org.jetbrains.dokka-javadoc") version "2.1.0"
  id("com.gradleup.nmcp") version "0.0.7"
  `maven-publish`
  signing
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

java {
  withSourcesJar()
}

tasks.register<Jar>("javadocJar") {
  val dokkaJavadoc = tasks.named("dokkaGenerate")
  dependsOn(dokkaJavadoc)
  archiveClassifier.set("javadoc")
  from(dokkaJavadoc.map { it.outputs.files })
}

tasks.test {
  useJUnitPlatform()
}

detekt {
  toolVersion = "2.0.0-alpha.2"
  config.setFrom(files("$rootDir/detekt.yml"))
  buildUponDefaultConfig = true
}

publishing {
  publications {
    create<MavenPublication>("mavenJava") {
      artifactId = "acl"
      from(components["java"])
      artifact(tasks.named("javadocJar"))

      pom {
        name.set("acl")
        description.set("A Kotlin ACL library for answering whether subject A can access resource B.")
        url.set("https://github.com/edreyer/acl")

        licenses {
          license {
            name.set("MIT License")
            url.set("https://opensource.org/licenses/MIT")
          }
        }

        developers {
          developer {
            name.set("Erik Dreyer")
          }
        }

        scm {
          url.set("https://github.com/edreyer/acl")
          connection.set("scm:git:git://github.com/edreyer/acl.git")
          developerConnection.set("scm:git:ssh://github.com/edreyer/acl.git")
        }
      }
    }
  }
}

signing {
  sign(publishing.publications["mavenJava"])
}

nmcp {
  publishAllPublications {
    username = providers.gradleProperty("centralPortalUsername")
    password = providers.gradleProperty("centralPortalPassword")
    publicationType = "AUTOMATIC"
  }
}
