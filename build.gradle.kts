plugins {
  kotlin("multiplatform") version "1.8.21"
  id("com.squareup.wire") version "4.7.0"
}

group = "ukey2"
version = "1.0-SNAPSHOT"

repositories {
  mavenCentral()
  mavenLocal()
}

kotlin {
  jvm {
    jvmToolchain(11)
    withJava()
    testRuns["test"].executionTask.configure {
      useJUnitPlatform()
    }
  }
  val hostOs = System.getProperty("os.name")
  val isMingwX64 = hostOs.startsWith("Windows")
  val nativeTarget = when {
    hostOs == "Mac OS X" -> macosArm64("native")
    hostOs == "Linux" -> linuxX64("native")
    isMingwX64 -> mingwX64("native")
    else -> throw GradleException("Host OS is not supported in Kotlin/Native.")
  }


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