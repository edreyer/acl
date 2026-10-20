import org.gradle.api.tasks.bundling.Jar
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
  kotlin("jvm") version "2.3.10"
  id("org.jetbrains.dokka") version "2.1.0"
  id("org.jetbrains.dokka-javadoc") version "2.1.0"
  `maven-publish`
  signing
  id("dev.detekt") version "2.0.0-alpha.6"
}

group = "io.liquidsoftware"
version = "0.4.0"

repositories {
  mavenCentral()
}

dependencies {
  testImplementation(kotlin("test"))
}

// Build with JDK 21, but publish bytecode and Gradle metadata that JDK 17 consumers can use.
val minimumJdk = 17

kotlin {
  jvmToolchain(21)
  explicitApi()
  compilerOptions {
    jvmTarget.set(JvmTarget.fromTarget(minimumJdk.toString()))
    freeCompilerArgs.add("-Xjdk-release=$minimumJdk")
  }

  // Fails the build when the public API changes without an updated api/ dump.
  @OptIn(org.jetbrains.kotlin.gradle.dsl.abi.ExperimentalAbiValidation::class)
  abiValidation {
    enabled.set(true)
  }
}

tasks.withType<JavaCompile>().configureEach {
  options.release.set(minimumJdk)
}

java {
  withSourcesJar()
}

tasks.register<Jar>("javadocJar") {
  archiveClassifier.set("javadoc")
  from(tasks.named("dokkaGeneratePublicationJavadoc"))
}

tasks.check {
  dependsOn("checkLegacyAbi")
}

tasks.withType<Test>().configureEach {
  useJUnitPlatform()
}

// Runs the tests on the oldest supported JDK. CI runs it; it isn't part of `check`, so local builds only need JDK 21.
tasks.register<Test>("testMinimumJdk") {
  description = "Runs the tests on JDK $minimumJdk."
  group = "verification"
  testClassesDirs = sourceSets.test.get().output.classesDirs
  classpath = sourceSets.test.get().runtimeClasspath
  javaLauncher.set(javaToolchains.launcherFor { languageVersion.set(JavaLanguageVersion.of(minimumJdk)) })
}

detekt {
  toolVersion = "2.0.0-alpha.6"
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
  // Signing is only required for Maven Central, so publishToMavenLocal works without a GPG key.
  setRequired {
    gradle.taskGraph.allTasks.any { it.name.contains("CentralPortal") || it.name.contains("Nmcp") }
  }
  sign(publishing.publications["mavenJava"])
}
