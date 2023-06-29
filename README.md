# Ukey2 for KMP
This is a port of [google/ukey2](https://github.com/google/ukey2) library to support Kotlin Multiplatform

Handshake and Device to Device communication is ported and tested against the C++ test from the original library

## Integration

You can add the dependency to your project by adding the following lines to your Gradle build file.

The library is available on Maven Central and you can add the coordinates to your commonMain source set.

### Gradle
```kotlin
repositories {
    mavenCentral()
}

dependencies {
    implementation("com.carlonzo.ukey2:ukey2-kmp:<latest version>")
}
```

### Supported platforms
The project currently supports the following platforms:
* JVM
* iOS (iosArm64, iosSimulatorArm64)
* macosArm64

## Usage
To create a new handshake session, use the following code:

### Client
```kotlin
  val client = Ukey2Handshake.forInitiator(HandshakeCipher.P256_SHA512)

  // Message 1 (Client Init)
  var handshakeMessage = client.getNextHandshakeMessage()
  sendMessageToServer(handshakeMessage)

  // Message 2 (Server Init)
  handshakeMessage = receiveMessageFromServer()
  client.parseHandshakeMessage(handshakeMessage)

  // Message 3 (Client Finish)
  handshakeMessage = client.getNextHandshakeMessage()
  sendMessageToServer(handshakeMessage)


  // Get the auth string to show to the user for confirmation
  val clientAuthString = client.getVerificationString(STRING_LENGTH)
  showStringToUser(clientAuthString)  
  
  // Once verified using a different channel, finish the handshake
  client.verifyHandshake()
  
  // Retrieve the connection context used to encrypt messages between client and server
  val connection = client.toConnectionContext()
```

### Server
```kotlin
  val server = Ukey2Handshake.forResponder(HandshakeCipher.P256_SHA512)
  
  // Message 1 (Client Init)
  var handshakeMessage = receiveMessageFromClient()
  server.parseHandshakeMessage(handshakeMessage)
  
  // Message 2 (Server Init)
  handshakeMessage = server.getNextHandshakeMessage()
  sendMessageToServer(handshakeMessage)
  
  // Message 3 (Client Finish)
  handshakeMessage = receiveMessageFromClient()
  server.parseHandshakeMessage(handshakeMessage)
  
  // Get the auth string
  val serverAuthString = server.getVerificationString(STRING_LENGTH)
  showStringToUser(serverAuthString)
  
  // Using out-of-band channel, verify auth string, then call:
  server.verifyHandshake()

  // Retrieve the connection context used to encrypt messages between client and server
  val connection = server.toConnectionContext()
```