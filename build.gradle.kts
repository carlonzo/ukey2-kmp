plugins {
  kotlin("multiplatform") version "2.4.10"
  id("com.squareup.wire") version "6.4.7"
  id("com.vanniktech.maven.publish") version "0.37.0"
}

group = "com.carlonzo.ukey2"
version = "1.0"

kotlin {
  jvmToolchain(11)
  jvm()

  iosArm64()
  iosSimulatorArm64()
  macosArm64()

  sourceSets {
    commonMain.dependencies {
      implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.11.0")
      implementation("com.carlonzo.ecdsa:ecdsa:0.1.0")
      implementation("org.kotlincrypto.random:crypto-rand:0.6.0")
      implementation("com.diglol.crypto:cipher:0.2.0")
    }
    commonTest.dependencies {
      implementation(kotlin("test"))
    }
  }
}

wire {
  kotlin {
  }
}

mavenPublishing {
  publishToMavenCentral()
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
