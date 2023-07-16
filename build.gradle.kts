import com.vanniktech.maven.publish.SonatypeHost
import org.jetbrains.kotlin.gradle.ExperimentalKotlinGradlePluginApi

plugins {
  kotlin("multiplatform") version "1.8.21"
  id("com.squareup.wire") version "4.7.0"
  id("com.vanniktech.maven.publish") version "0.25.3"
}

group = "com.carlonzo.ukey2"
version = "1.0"

repositories {
  mavenCentral()
  mavenLocal()
}

@OptIn(ExperimentalKotlinGradlePluginApi::class)
kotlin {
  targetHierarchy.default()

  jvm {
    jvmToolchain(11)
    withJava()
    testRuns["test"].executionTask.configure {
      useJUnitPlatform()
    }
  }

  iosArm64()
  iosSimulatorArm64()
  macosArm64()


  sourceSets {
    val commonMain by getting {
      dependencies {
        implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.7.2")
        implementation("com.carlonzo.ecdsa:ecdsa:0.1.0")
        implementation("org.kotlincrypto:secure-random:0.1.0")
        implementation("com.diglol.crypto:cipher:0.1.4")
      }
    }


    val commonTest by getting {
      dependencies {
        implementation(kotlin("test"))
      }
    }
    val jvmMain by getting
    val jvmTest by getting
    val nativeMain by getting
    val nativeTest by getting
  }
}

wire {
  kotlin {
  }
}

mavenPublishing {
  publishToMavenCentral(SonatypeHost.S01)

  signAllPublications()

  pom {
    name.set("ukey2-kmp")
    description.set("UKey2 port for Kotlin Multiplatform")
    inceptionYear.set("2023")
    url.set("https://github.com/carlonzo/ukey2-kmp")
    developers {
      developer {
        id.set("carlonzo")
        name.set("Carlo Marinangeli")
        url.set("https://github.com/carlonzo")
      }
    }
    licenses {
      license {
        name.set("MIT License")
        url.set("https://opensource.org/licenses/MIT")
        distribution.set("repo")
      }
    }
    scm {
      url.set("https://github.com/carlonzo/ukey2-kmp")
      connection.set("scm:git:git://github.com/carlonzo/ukey2-kmp.git")
      developerConnection.set("scm:git:ssh://git@github.com/carlonzo/ukey2-kmp.git")
    }
  }
}