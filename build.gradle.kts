import org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget
import org.jetbrains.kotlin.konan.target.Family

plugins {
  kotlin("multiplatform") version "2.4.20"
  id("com.squareup.wire") version "7.0.4"
  id("com.vanniktech.maven.publish") version "0.37.0"
}

group = "com.carlonzo.ukey2"

kotlin {
  jvmToolchain(11)
  jvm()

  linuxX64()
  linuxArm64()

  iosArm64()
  iosSimulatorArm64()
  macosArm64()

  targets.withType<KotlinNativeTarget>().matching { it.konanTarget.family == Family.LINUX }.configureEach {
    binaries.all {
      linkerOpts("-Wl,--as-needed")
    }
  }

  sourceSets {
    commonMain.dependencies {
      implementation("dev.whyoleg.cryptography:cryptography-core:0.6.0")
      implementation("dev.whyoleg.cryptography:cryptography-random:0.6.0")
      implementation("dev.whyoleg.cryptography:cryptography-provider-optimal:0.6.0")
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
  if (project.hasProperty("signingInMemoryKey")) {
    signAllPublications()
  }

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
