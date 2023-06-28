// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import com.carlonzo.ukey2.Ukey2Handshake
import com.carlonzo.ukey2.Ukey2Handshake.AlertException
import com.carlonzo.ukey2.Ukey2Handshake.HandshakeCipher
import com.carlonzo.ukey2.d2d.D2DConnectionContext
import com.carlonzo.ukey2.d2d.D2DConnectionContextV1
import com.google.security.cryptauth.lib.securegcm.Ukey2ClientFinished
import com.google.security.cryptauth.lib.securegcm.Ukey2ClientInit
import com.google.security.cryptauth.lib.securegcm.Ukey2HandshakeCipher
import com.google.security.cryptauth.lib.securegcm.Ukey2Message
import com.google.security.cryptauth.lib.securegcm.Ukey2ServerInit
import okio.ByteString.Companion.toByteString
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.fail


/**
 * Android compatible tests for the [Ukey2Handshake] class.
 */
class Ukey2HandshakeTest {


  /**
   * Tests correct use
   */

  @Test
  fun testHandshake() {

    val client = Ukey2Handshake.forInitiator(HandshakeCipher.P256_SHA512)
    val server = Ukey2Handshake.forResponder(HandshakeCipher.P256_SHA512)
    assertEquals(Ukey2Handshake.State.IN_PROGRESS, client.getHandshakeState())
    assertEquals(Ukey2Handshake.State.IN_PROGRESS, server.getHandshakeState())

    // Message 1 (Client Init)
    var handshakeMessage: ByteArray = client.getNextHandshakeMessage()
    server.parseHandshakeMessage(handshakeMessage)
    assertEquals(Ukey2Handshake.State.IN_PROGRESS, client.getHandshakeState())
    assertEquals(Ukey2Handshake.State.IN_PROGRESS, server.getHandshakeState())

    // Message 2 (Server Init)
    handshakeMessage = server.getNextHandshakeMessage()
    client.parseHandshakeMessage(handshakeMessage)
    assertEquals(Ukey2Handshake.State.IN_PROGRESS, client.getHandshakeState())
    assertEquals(Ukey2Handshake.State.IN_PROGRESS, server.getHandshakeState())

    // Message 3 (Client Finish)
    handshakeMessage = client.getNextHandshakeMessage()
    server.parseHandshakeMessage(handshakeMessage)
    assertEquals(Ukey2Handshake.State.VERIFICATION_NEEDED, client.getHandshakeState())
    assertEquals(Ukey2Handshake.State.VERIFICATION_NEEDED, server.getHandshakeState())

    // Get the auth string
    val clientAuthString = client.getVerificationString(MAX_AUTH_STRING_LENGTH)
    val serverAuthString = server.getVerificationString(MAX_AUTH_STRING_LENGTH)
    assertContentEquals(clientAuthString, serverAuthString)
    assertEquals(Ukey2Handshake.State.VERIFICATION_IN_PROGRESS, client.getHandshakeState())
    assertEquals(Ukey2Handshake.State.VERIFICATION_IN_PROGRESS, server.getHandshakeState())

    // Verify the auth string
    client.verifyHandshake()
    server.verifyHandshake()

    assertEquals(Ukey2Handshake.State.FINISHED, client.getHandshakeState())
    assertEquals(Ukey2Handshake.State.FINISHED, server.getHandshakeState())


    // Make a context
    val clientContext = client.toConnectionContext()
    val serverContext = server.toConnectionContext()
    assertContextsCompatible(clientContext, serverContext)

    assertEquals(Ukey2Handshake.State.ALREADY_USED, client.getHandshakeState())
    assertEquals(Ukey2Handshake.State.ALREADY_USED, server.getHandshakeState())
  }

  /**
   * Verify enums for ciphers match the proto values
   */
  @Test
  fun testCipherEnumValuesCorrect() {
    assertEquals(
      1, HandshakeCipher.values().size, "You added a cipher, but forgot to change the test"
    )
    assertEquals(
      Ukey2HandshakeCipher.P256_SHA512,
      HandshakeCipher.P256_SHA512.value
    )
  }

  /**
   * Tests incorrect use by callers (client and servers accidentally sending the wrong message at
   * the wrong time)
   */
  @Test
  fun testHandshakeClientAndServerSendRepeatedOutOfOrderMessages() {


    // Client sends ClientInit (again) instead of ClientFinished
    var client = Ukey2Handshake.forInitiator(HandshakeCipher.P256_SHA512)
    var server = Ukey2Handshake.forResponder(HandshakeCipher.P256_SHA512)
    var handshakeMessage = client.getNextHandshakeMessage()
    server.parseHandshakeMessage(handshakeMessage)
    server.getNextHandshakeMessage() // do this to avoid illegal state
    try {
      server.parseHandshakeMessage(handshakeMessage)
      fail("Expected Alert for client sending ClientInit twice")
    } catch (e: Exception) {
      // success
    }
    assertEquals(Ukey2Handshake.State.ERROR, server.getHandshakeState())

    // Server sends ClientInit back to client instead of ServerInit
    client = Ukey2Handshake.forInitiator(HandshakeCipher.P256_SHA512)
    server = Ukey2Handshake.forResponder(HandshakeCipher.P256_SHA512)
    handshakeMessage = client.getNextHandshakeMessage()
    try {
      client.parseHandshakeMessage(handshakeMessage)
      fail("Expected Alert for server sending ClientInit back to client")
    } catch (e: AlertException) {
      // success
    }
    assertEquals(Ukey2Handshake.State.ERROR, client.getHandshakeState())

    // Clients sends ServerInit back to client instead of ClientFinished
    client = Ukey2Handshake.forInitiator(HandshakeCipher.P256_SHA512)
    server = Ukey2Handshake.forResponder(HandshakeCipher.P256_SHA512)
    handshakeMessage = client.getNextHandshakeMessage()
    server.parseHandshakeMessage(handshakeMessage)
    handshakeMessage = server.getNextHandshakeMessage()
    try {
      server.parseHandshakeMessage(handshakeMessage)
      fail("Expected Alert for client sending ServerInit back to server")
    } catch (e: Exception) {
      // success
    }
    assertEquals(Ukey2Handshake.State.ERROR, server.getHandshakeState())
  }

  /**
   * Tests that verification codes are different for different handshake runs. Also tests a full
   * man-in-the-middle attack.
   */
  @Test
  fun testVerificationCodeUniqueToSession() {
    // Client 1 and Server 1
    val client1 = Ukey2Handshake.forInitiator(HandshakeCipher.P256_SHA512)
    val server1 = Ukey2Handshake.forResponder(HandshakeCipher.P256_SHA512)
    var handshakeMessage = client1.getNextHandshakeMessage()
    server1.parseHandshakeMessage(handshakeMessage)
    handshakeMessage = server1.getNextHandshakeMessage()
    client1.parseHandshakeMessage(handshakeMessage)
    handshakeMessage = client1.getNextHandshakeMessage()
    server1.parseHandshakeMessage(handshakeMessage)
    val client1AuthString = client1.getVerificationString(MAX_AUTH_STRING_LENGTH)
    val server1AuthString = server1.getVerificationString(MAX_AUTH_STRING_LENGTH)
    assertContentEquals(client1AuthString, server1AuthString)

    // Client 2 and Server 2
    val client2 = Ukey2Handshake.forInitiator(HandshakeCipher.P256_SHA512)
    val server2 = Ukey2Handshake.forResponder(HandshakeCipher.P256_SHA512)
    handshakeMessage = client2.getNextHandshakeMessage()
    server2.parseHandshakeMessage(handshakeMessage)
    handshakeMessage = server2.getNextHandshakeMessage()
    client2.parseHandshakeMessage(handshakeMessage)
    handshakeMessage = client2.getNextHandshakeMessage()
    server2.parseHandshakeMessage(handshakeMessage)
    val client2AuthString = client2.getVerificationString(MAX_AUTH_STRING_LENGTH)
    val server2AuthString = server2.getVerificationString(MAX_AUTH_STRING_LENGTH)
    assertContentEquals(client2AuthString, server2AuthString)

    // Make sure the verification strings differ

    assertFalse((client1AuthString.contentEquals(client2AuthString)))
  }

  /**
   * Test an attack where the adversary swaps out the public key in the final message (i.e.,
   * commitment doesn't match public key)
   */
  @Test
  fun testPublicKeyDoesntMatchCommitment() {
    // Run handshake as usual, but stop before sending client finished
    val client1 = Ukey2Handshake.forInitiator(HandshakeCipher.P256_SHA512)
    val server1 = Ukey2Handshake.forResponder(HandshakeCipher.P256_SHA512)
    var handshakeMessage = client1.getNextHandshakeMessage()
    server1.parseHandshakeMessage(handshakeMessage)
    handshakeMessage = server1.getNextHandshakeMessage()

    // Run another handshake and get the final client finished
    val client2 = Ukey2Handshake.forInitiator(HandshakeCipher.P256_SHA512)
    val server2 = Ukey2Handshake.forResponder(HandshakeCipher.P256_SHA512)
    handshakeMessage = client2.getNextHandshakeMessage()
    server2.parseHandshakeMessage(handshakeMessage)
    handshakeMessage = server2.getNextHandshakeMessage()
    client2.parseHandshakeMessage(handshakeMessage)
    handshakeMessage = client2.getNextHandshakeMessage()

    // Now use the client finished from second handshake in first handshake (simulates where an
    // attacker switches out the last message).
    try {
      server1.parseHandshakeMessage(handshakeMessage)
      fail("Expected server to catch mismatched ClientFinished")
    } catch (e: Exception) {
      // success
    }
    assertEquals(Ukey2Handshake.State.ERROR, server1.getHandshakeState())

    // Make sure caller can't actually do anything with the server now that an error has occurred
    try {
      server1.getVerificationString(MAX_AUTH_STRING_LENGTH)
      fail("Server allows operations post error")
    } catch (e: IllegalStateException) {
      // success
    }
    try {
      server1.verifyHandshake()
      fail("Server allows operations post error")
    } catch (e: IllegalStateException) {
      // success
    }
  }

  /**
   * Test commitment having unsupported version
   */
  @Test
  fun testClientInitUnsupportedVersion() {
    // Get ClientInit and modify the version to be too big
    var client = Ukey2Handshake.forInitiator(HandshakeCipher.P256_SHA512)
    var server = Ukey2Handshake.forResponder(HandshakeCipher.P256_SHA512)
    var handshakeMessage = client.getNextHandshakeMessage()
    var message = Ukey2Message.ADAPTER.decode(handshakeMessage)

    var clientInit = Ukey2ClientInit.ADAPTER.decode(message.message_data!!)
    clientInit = clientInit.copy(Ukey2Handshake.VERSION + 1)

    handshakeMessage = message.copy(message_data = clientInit.encodeByteString()).encode()
    try {
      server.parseHandshakeMessage(handshakeMessage)
      fail("Server did not catch unsupported version (too big) in ClientInit")
    } catch (e: AlertException) {
      // success
    }
    assertEquals(Ukey2Handshake.State.ERROR, server.getHandshakeState())

    // Get ClientInit and modify the version to be too small
    client = Ukey2Handshake.forInitiator(HandshakeCipher.P256_SHA512)
    server = Ukey2Handshake.forResponder(HandshakeCipher.P256_SHA512)
    handshakeMessage = client.getNextHandshakeMessage()
    message = Ukey2Message.ADAPTER.decode(handshakeMessage)

    clientInit = Ukey2ClientInit.ADAPTER.decode(message.message_data!!)
    clientInit = clientInit.copy(0)

    handshakeMessage = message.copy(message_data = clientInit.encodeByteString()).encode()
    try {
      server.parseHandshakeMessage(handshakeMessage)
      fail("Server did not catch unsupported version (too small) in ClientInit")
    } catch (e: AlertException) {
      // success
    }
    assertEquals(Ukey2Handshake.State.ERROR, server.getHandshakeState())
  }

  /**
   * Tests that server catches wrong number of random bytes in ClientInit
   */
  @Test
  fun testWrongNonceLengthInClientInit() {
    // Get ClientInit and modify the nonce
    val client = Ukey2Handshake.forInitiator(HandshakeCipher.P256_SHA512)
    val server = Ukey2Handshake.forResponder(HandshakeCipher.P256_SHA512)
    var handshakeMessage = client.getNextHandshakeMessage()
    var message = Ukey2Message.ADAPTER.decode(handshakeMessage)

    val clientInit =
      Ukey2ClientInit.ADAPTER.decode(message.message_data!!).let {
        it.copy(random = it.random?.substring(0, 31)) /* as per go/ukey2, nonces must be 32 bytes long */
      }

    message = message.copy(message_data = clientInit.encodeByteString())
    handshakeMessage = message.encode()
    try {
      server.parseHandshakeMessage(handshakeMessage)
      fail("Server did not catch nonce being too short in ClientInit")
    } catch (e: AlertException) {
      // success
    }
    assertEquals(Ukey2Handshake.State.ERROR, server.getHandshakeState())
  }

  /**
   * Test that server catches missing commitment in ClientInit message
   */

  @Test
  fun testServerCatchesMissingCommitmentInClientInit() {
    // Get ClientInit and modify the commitment
    val client = Ukey2Handshake.forInitiator(HandshakeCipher.P256_SHA512)
    val server = Ukey2Handshake.forResponder(HandshakeCipher.P256_SHA512)
    var handshakeMessage = client.getNextHandshakeMessage()
    var message = Ukey2Message.ADAPTER.decode(handshakeMessage)

    val clientInit = Ukey2ClientInit.ADAPTER.decode(message.message_data!!)

    val badClientInit = Ukey2ClientInit(
      version = clientInit.version,
      random = clientInit.random,
      cipher_commitments = emptyList()
    )

    message = message.copy(message_data = badClientInit.encodeByteString())
    handshakeMessage = message.encode()
    try {
      server.parseHandshakeMessage(handshakeMessage)
      fail("Server did not catch missing commitment in ClientInit")
    } catch (e: AlertException) {
      // success
    }
  }

  /**
   * Test that client catches invalid version in ServerInit
   */

  @Test
  fun testServerInitUnsupportedVersion() {
    // Get ClientInit and modify the version to be too big
    var client = Ukey2Handshake.forInitiator(HandshakeCipher.P256_SHA512)
    var server = Ukey2Handshake.forResponder(HandshakeCipher.P256_SHA512)
    var handshakeMessage = client.getNextHandshakeMessage()
    server.parseHandshakeMessage(handshakeMessage)
    handshakeMessage = server.getNextHandshakeMessage()

    var message = Ukey2Message.ADAPTER.decode(handshakeMessage)

    var serverInit = Ukey2ServerInit.ADAPTER.decode(message.message_data!!)
    serverInit = serverInit.copy(Ukey2Handshake.VERSION + 1)

    handshakeMessage = message.copy(message_data = serverInit.encodeByteString()).encode()
    try {
      client.parseHandshakeMessage(handshakeMessage)
      fail("Client did not catch unsupported version (too big) in ClientInit")
    } catch (e: AlertException) {
      // success
    }
    assertEquals(Ukey2Handshake.State.ERROR, client.getHandshakeState())

    // Get ClientInit and modify the version to be too small
    client = Ukey2Handshake.forInitiator(HandshakeCipher.P256_SHA512)
    server = Ukey2Handshake.forResponder(HandshakeCipher.P256_SHA512)
    handshakeMessage = client.getNextHandshakeMessage()
    server.parseHandshakeMessage(handshakeMessage)
    handshakeMessage = server.getNextHandshakeMessage()

    message = Ukey2Message.ADAPTER.decode(handshakeMessage)

    serverInit = Ukey2ServerInit.ADAPTER.decode(message.message_data!!)
    serverInit = serverInit.copy(0)

    handshakeMessage = message.copy(message_data = serverInit.encodeByteString()).encode()
    try {
      client.parseHandshakeMessage(handshakeMessage)
      fail("Client did not catch unsupported version (too small) in ClientInit")
    } catch (e: AlertException) {
      // success
    }
    assertEquals(Ukey2Handshake.State.ERROR, client.getHandshakeState())
  }


  /**
   * Tests that client catches wrong number of random bytes in ServerInit
   */
  @Test
  fun testWrongNonceLengthInServerInit() {
    // Get ServerInit and modify the nonce
    val client = Ukey2Handshake.forInitiator(HandshakeCipher.P256_SHA512)
    val server = Ukey2Handshake.forResponder(HandshakeCipher.P256_SHA512)
    var handshakeMessage = client.getNextHandshakeMessage()
    server.parseHandshakeMessage(handshakeMessage)
    handshakeMessage = server.getNextHandshakeMessage()
    var message = Ukey2Message.ADAPTER.decode(handshakeMessage)

    val serverInit = Ukey2ServerInit.ADAPTER.decode(message.message_data!!).let {
      it.copy(random = it.random?.substring(0, 31)) /* as per go/ukey2, nonces must be 32 bytes long */
    }

    message = message.copy(message_data = serverInit.encodeByteString())
    handshakeMessage = message.encode()
    try {
      client.parseHandshakeMessage(handshakeMessage)
      fail("Client did not catch nonce being too short in ServerInit")
    } catch (e: AlertException) {
      // success
    }
    assertEquals(Ukey2Handshake.State.ERROR, client.getHandshakeState())
  }

  //  TODO will finish the conversion


  /**
   * Test that client catches missing or incorrect handshake cipher in serverInit
   */
  @Test
  fun testMissingOrIncorrectHandshakeCipherInServerInit() {
    // Get ServerInit
    var client = Ukey2Handshake.forInitiator(HandshakeCipher.P256_SHA512)
    var server = Ukey2Handshake.forResponder(HandshakeCipher.P256_SHA512)
    var handshakeMessage = client.getNextHandshakeMessage()
    server.parseHandshakeMessage(handshakeMessage)
    handshakeMessage = server.getNextHandshakeMessage()
    var message = Ukey2Message.ADAPTER.decode(handshakeMessage)
    var serverInit = Ukey2ServerInit.ADAPTER.decode(message.message_data!!)

    // remove handshake cipher
    var badServerInit = Ukey2ServerInit(
      public_key = (serverInit.public_key),
      random = (serverInit.random),
      version = (serverInit.version)
    )
    message = message.copy(message_data = badServerInit.encodeByteString())
    handshakeMessage = message.encode()
    try {
      client.parseHandshakeMessage(handshakeMessage)
      fail("Client did not catch missing handshake cipher in ServerInit")
    } catch (e: AlertException) {
      // success
    }
    assertEquals(Ukey2Handshake.State.ERROR, client.getHandshakeState())

    // Get ServerInit
    client = Ukey2Handshake.forInitiator(HandshakeCipher.P256_SHA512)
    server = Ukey2Handshake.forResponder(HandshakeCipher.P256_SHA512)
    handshakeMessage = client.getNextHandshakeMessage()
    server.parseHandshakeMessage(handshakeMessage)
    handshakeMessage = server.getNextHandshakeMessage()
    message = Ukey2Message.ADAPTER.decode(handshakeMessage)
    serverInit = Ukey2ServerInit.ADAPTER.decode(message.message_data!!)

    // put in a bad handshake cipher
    badServerInit = Ukey2ServerInit(
      public_key = (serverInit.public_key),
      random = (serverInit.random),
      version = (serverInit.version),
      handshake_cipher = (Ukey2HandshakeCipher.RESERVED)
    )
    message = message.copy(message_data = badServerInit.encodeByteString())
    handshakeMessage = message.encode()

    try {
      client.parseHandshakeMessage(handshakeMessage)
      fail("Client did not catch bad handshake cipher in ServerInit")
    } catch (e: AlertException) {
      // success
    }
    assertEquals(Ukey2Handshake.State.ERROR, client.getHandshakeState())
  }

  /**
   * Test that client catches missing or incorrect public key in serverInit
   */
  @Test
  fun testMissingOrIncorrectPublicKeyInServerInit() {
    // Get ServerInit
    var client = Ukey2Handshake.forInitiator(HandshakeCipher.P256_SHA512)
    var server = Ukey2Handshake.forResponder(HandshakeCipher.P256_SHA512)
    var handshakeMessage = client.getNextHandshakeMessage()
    server.parseHandshakeMessage(handshakeMessage)
    handshakeMessage = server.getNextHandshakeMessage()
    var message = Ukey2Message.ADAPTER.decode(handshakeMessage)
    var serverInit: Ukey2ServerInit = Ukey2ServerInit.ADAPTER.decode(message.message_data!!)

    // remove public key
    var badServerInit: Ukey2ServerInit = Ukey2ServerInit(
      random = (serverInit.random),
      version = (serverInit.version),
      handshake_cipher = (serverInit.handshake_cipher)
    )
    message = message.copy(message_data = badServerInit.encodeByteString())
    handshakeMessage = message.encode()
    try {
      client.parseHandshakeMessage(handshakeMessage)
      fail("Client did not catch missing public key in ServerInit")
    } catch (e: AlertException) {
      // success
    }
    assertEquals(Ukey2Handshake.State.ERROR, client.getHandshakeState())

    // Get ServerInit
    client = Ukey2Handshake.forInitiator(HandshakeCipher.P256_SHA512)
    server = Ukey2Handshake.forResponder(HandshakeCipher.P256_SHA512)
    handshakeMessage = client.getNextHandshakeMessage()
    server.parseHandshakeMessage(handshakeMessage)
    handshakeMessage = server.getNextHandshakeMessage()
    message = Ukey2Message.ADAPTER.decode(handshakeMessage)
    serverInit = Ukey2ServerInit.ADAPTER.decode(message.message_data!!)

    // put in a bad public key
    badServerInit = Ukey2ServerInit(
      public_key = byteArrayOf(42, 12, 1).toByteString(),
      random = (serverInit.random),
      version = (serverInit.version),
      handshake_cipher = (serverInit.handshake_cipher)
    )
    message = message.copy(message_data = badServerInit.encodeByteString())
    handshakeMessage = message.encode()
    try {
      client.parseHandshakeMessage(handshakeMessage)
      fail("Client did not catch bad public key in ServerInit")
    } catch (e: Exception) {
      // success
    }
    assertEquals(Ukey2Handshake.State.ERROR, client.getHandshakeState())
  }

  /**
   * Test that client catches missing or incorrect public key in clientFinished
   */
  @Test
  fun testMissingOrIncorrectPublicKeyInClientFinished() {
    // Get ClientFinished
    var client = Ukey2Handshake.forInitiator(HandshakeCipher.P256_SHA512)
    var server = Ukey2Handshake.forResponder(HandshakeCipher.P256_SHA512)
    var handshakeMessage = client.getNextHandshakeMessage()
    server.parseHandshakeMessage(handshakeMessage)
    handshakeMessage = server.getNextHandshakeMessage()
    client.parseHandshakeMessage(handshakeMessage)
    handshakeMessage = client.getNextHandshakeMessage()
    var message = Ukey2Message.ADAPTER.decode(handshakeMessage)

    // remove public key
    var badClientFinished = Ukey2ClientFinished()

    message = message.copy(message_data = badClientFinished.encodeByteString())
    handshakeMessage = message.encode()
    try {
      server.parseHandshakeMessage(handshakeMessage)
      fail("Server did not catch missing public key in ClientFinished")
    } catch (e: Exception) {
      // success
    }
    assertEquals(Ukey2Handshake.State.ERROR, server.getHandshakeState())

    // Get ClientFinished
    client = Ukey2Handshake.forInitiator(HandshakeCipher.P256_SHA512)
    server = Ukey2Handshake.forResponder(HandshakeCipher.P256_SHA512)
    handshakeMessage = client.getNextHandshakeMessage()
    server.parseHandshakeMessage(handshakeMessage)
    handshakeMessage = server.getNextHandshakeMessage()
    client.parseHandshakeMessage(handshakeMessage)
    handshakeMessage = client.getNextHandshakeMessage()
    message = Ukey2Message.ADAPTER.decode(handshakeMessage)

    // remove public key
    badClientFinished = Ukey2ClientFinished(
      public_key = byteArrayOf(42, 12, 1).toByteString()
    )
    message = message.copy(message_data = badClientFinished.encodeByteString())
    handshakeMessage = message.encode()
    try {
      server.parseHandshakeMessage(handshakeMessage)
      fail("Server did not catch bad public key in ClientFinished")
    } catch (e: Exception) {
      // success
    }
    assertEquals(Ukey2Handshake.State.ERROR, server.getHandshakeState())
  }

  /**
   * Tests that items (nonces, commitments, public keys) that should be random are at least
   * different on every run.
   */

  fun testRandomItemsDifferentOnEveryRun() {

    val numberOfRuns = 50

    // Search for collisions
    val commitments: MutableSet<Int> = mutableSetOf()
    val clientNonces: MutableSet<Int> = mutableSetOf()
    val serverNonces: MutableSet<Int> = mutableSetOf()
    val serverPublicKeys: MutableSet<Int> = mutableSetOf()
    val clientPublicKeys: MutableSet<Int> = mutableSetOf()
    for (i in 0 until numberOfRuns) {
      var client: Ukey2Handshake? = Ukey2Handshake.forInitiator(HandshakeCipher.P256_SHA512)
      var server: Ukey2Handshake? = Ukey2Handshake.forResponder(HandshakeCipher.P256_SHA512)
      var handshakeMessage: ByteArray? = client!!.getNextHandshakeMessage()
      var message: Ukey2Message? = Ukey2Message.ADAPTER.decode(handshakeMessage!!)
      val clientInit: Ukey2ClientInit = Ukey2ClientInit.ADAPTER.decode(message?.message_data!!)
      server!!.parseHandshakeMessage(handshakeMessage)
      handshakeMessage = server.getNextHandshakeMessage()
      message = Ukey2Message.ADAPTER.decode(handshakeMessage)
      val serverInit: Ukey2ServerInit = Ukey2ServerInit.ADAPTER.decode(message.message_data!!)
      client.parseHandshakeMessage(handshakeMessage)
      handshakeMessage = client.getNextHandshakeMessage()
      message = Ukey2Message.ADAPTER.decode(handshakeMessage)
      val clientFinished: Ukey2ClientFinished = Ukey2ClientFinished.ADAPTER.decode(message.message_data!!)

      // Clean up to save some memory (b/32054837)
      client = null
      server = null
      handshakeMessage = null
      message = null

      // ClientInit randomness
      var nonceHash: Int = clientInit.random.hashCode()
      if (clientNonces.contains(nonceHash) || serverNonces.contains(nonceHash)) {
        fail("Nonce in ClientINit has repeated!")
      }
      clientNonces.add(nonceHash)
      var commitmentHash = 0
      for (commitement in clientInit.cipher_commitments) {
        commitmentHash += commitement.hashCode()
      }
      if (commitments.contains(nonceHash)) {
        fail("Commitment has repeated!")
      }
      commitments.add(commitmentHash)

      // ServerInit randomness
      nonceHash = serverInit.random.hashCode()
      if (serverNonces.contains(nonceHash) || clientNonces.contains(nonceHash)) {
        fail("Nonce in ServerInit repeated!")
      }
      serverNonces.add(nonceHash)
      var publicKeyHash: Int = serverInit.public_key.hashCode()
      if (serverPublicKeys.contains(publicKeyHash) || clientPublicKeys.contains(publicKeyHash)) {
        fail("Public Key in ServerInit repeated!")
      }
      serverPublicKeys.add(publicKeyHash)

      // Client Finished randomness
      publicKeyHash = clientFinished.public_key.hashCode()
      if (serverPublicKeys.contains(publicKeyHash) || clientPublicKeys.contains(publicKeyHash)) {
        fail("Public Key in ClientFinished repeated!")
      }
      clientPublicKeys.add(publicKeyHash)
    }
  }

  /**
   * Tests that [Ukey2Handshake.getVerificationString] enforces sane verification string
   * lengths.
   */
  @Test
  fun testGetVerificationEnforcesSaneLengths() {
    // Run the protocol
    val client = Ukey2Handshake.forInitiator(HandshakeCipher.P256_SHA512)
    val server = Ukey2Handshake.forResponder(HandshakeCipher.P256_SHA512)
    var handshakeMessage = client.getNextHandshakeMessage()
    server.parseHandshakeMessage(handshakeMessage)
    handshakeMessage = server.getNextHandshakeMessage()
    client.parseHandshakeMessage(handshakeMessage)
    handshakeMessage = client.getNextHandshakeMessage()
    server.parseHandshakeMessage(handshakeMessage)

    // Try to get too short verification string
    try {
      client.getVerificationString(0)
      fail("Too short verification string allowed")
    } catch (e: IllegalArgumentException) {
      // success
    }

    // Try to get too long verification string
    try {
      server.getVerificationString(MAX_AUTH_STRING_LENGTH + 1)
      fail("Too long verification string allowed")
    } catch (e: IllegalArgumentException) {
      // success
    }
  }

  /**
   * Asserts that the given client and server contexts are compatible
   */
  private fun assertContextsCompatible(
    clientContext: D2DConnectionContext, serverContext: D2DConnectionContext
  ) {
    assertNotNull(clientContext)
    assertNotNull(serverContext)
    assertEquals(D2DConnectionContextV1.PROTOCOL_VERSION, clientContext.protocolVersion)
    assertEquals(D2DConnectionContextV1.PROTOCOL_VERSION, serverContext.protocolVersion)
    assertContentEquals(clientContext.encodeKey, serverContext.decodeKey)
    assertContentEquals(clientContext.decodeKey, serverContext.encodeKey)
    assertFalse(clientContext.encodeKey.contentEquals(clientContext.decodeKey))
    assertEquals(0, clientContext.sequenceNumberForEncoding)
    assertEquals(0, clientContext.sequenceNumberForDecoding)
    assertEquals(0, serverContext.sequenceNumberForEncoding)
    assertEquals(0, serverContext.sequenceNumberForDecoding)
  }

  companion object {
    private const val MAX_AUTH_STRING_LENGTH = 32
  }
}
