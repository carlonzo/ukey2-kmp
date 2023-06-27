import org.jetbrains.kotlin.gradle.ExperimentalKotlinGradlePluginApi

plugins {
  kotlin("multiplatform") version "1.8.21"
  id("com.squareup.wire") version "4.7.0"
  id("com.vanniktech.maven.publish") version "0.25.2"
}

group = "com.carlom"
version = "1.0-SNAPSHOT"

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
        implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.7.1")
        implementation("com.carterharrison:ecdsa:0.1.0-beta1")
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