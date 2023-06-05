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
@file:OptIn(ExperimentalUnsignedTypes::class)

package com.google.security.cryptauth.lib.securegcm

import com.carterharrison.ecdsa.EcDhKeyAgreement
import com.carterharrison.ecdsa.EcKeyGenerator
import com.carterharrison.ecdsa.EcKeyPair
import com.carterharrison.ecdsa.EcPoint
import com.carterharrison.ecdsa.curves.Secp256r1
import com.carterharrison.ecdsa.hash.EcSha256
import com.carterharrison.ecdsa.hash.EcSha512
import com.google.security.cryptauth.lib.securegcm.*
import com.google.security.cryptauth.lib.securegcm.Ukey2Alert.AlertType.*
import com.google.security.cryptauth.lib.securegcm.Ukey2Handshake.HandshakeRole.*
import com.google.security.cryptauth.lib.securegcm.Ukey2Message.Type.*
import com.google.security.cryptauth.lib.securemessage.*
import d2d.D2DConnectionContext
import d2d.D2DConnectionContextV1
import d2d.D2DCryptoOps.d2dSalt
import hkdf
import okio.ByteString.Companion.toByteString
import org.kotlincrypto.SecureRandom


/**
 * Implements UKEY2 and produces a [D2DConnectionContext].
 *
 *
 * Client Usage:
 * `
 * try {
 * Ukey2Handshake client = Ukey2Handshake.forInitiator(HandshakeCipher.P256_SHA512);
 * byte[] handshakeMessage;
 *
 * // Message 1 (Client Init)
 * handshakeMessage = client.getNextHandshakeMessage();
 * sendMessageToServer(handshakeMessage);
 *
 * // Message 2 (Server Init)
 * handshakeMessage = receiveMessageFromServer();
 * client.parseHandshakeMessage(handshakeMessage);
 *
 * // Message 3 (Client Finish)
 * handshakeMessage = client.getNextHandshakeMessage();
 * sendMessageToServer(handshakeMessage);
 *
 * // Get the auth string
 * byte[] clientAuthString = client.getVerificationString(STRING_LENGTH);
 * showStringToUser(clientAuthString);
 *
 * // Using out-of-band channel, verify auth string, then call:
 * client.verifyHandshake();
 *
 * // Make a connection context
 * D2DConnectionContext clientContext = client.toConnectionContext();
 * } catch (AlertException e) {
 * log(e.getMessage);
 * sendMessageToServer(e.getAlertMessageToSend());
 * } catch (HandshakeException e) {
 * log(e);
 * // terminate handshake
 * }
` *
 *
 *
 * Server Usage:
 * `
 * try {
 * Ukey2Handshake server = Ukey2Handshake.forResponder(HandshakeCipher.P256_SHA512);
 * byte[] handshakeMessage;
 *
 * // Message 1 (Client Init)
 * handshakeMessage = receiveMessageFromClient();
 * server.parseHandshakeMessage(handshakeMessage);
 *
 * // Message 2 (Server Init)
 * handshakeMessage = server.getNextHandshakeMessage();
 * sendMessageToServer(handshakeMessage);
 *
 * // Message 3 (Client Finish)
 * handshakeMessage = receiveMessageFromClient();
 * server.parseHandshakeMessage(handshakeMessage);
 *
 * // Get the auth string
 * byte[] serverAuthString = server.getVerificationString(STRING_LENGTH);
 * showStringToUser(serverAuthString);
 *
 * // Using out-of-band channel, verify auth string, then call:
 * server.verifyHandshake();
 *
 * // Make a connection context
 * D2DConnectionContext serverContext = server.toConnectionContext();
 * } catch (AlertException e) {
 * log(e.getMessage);
 * sendMessageToClient(e.getAlertMessageToSend());
 * } catch (HandshakeException e) {
 * log(e);
 * // terminate handshake
 * }
` *
 */
class Ukey2Handshake private constructor(state: InternalState, cipher: HandshakeCipher?) {
  /**
   * Handshake States. Meaning of states:
   *
   *  * IN_PROGRESS: The handshake is in progress, caller should use
   * [Ukey2Handshake.getNextHandshakeMessage] and
   * [Ukey2Handshake.parseHandshakeMessage] to continue the handshake.
   *  * VERIFICATION_NEEDED: The handshake is complete, but pending verification of the
   * authentication string. Clients should use [Ukey2Handshake.getVerificationString] to
   * get the verification string and use out-of-band methods to authenticate the handshake.
   *  * VERIFICATION_IN_PROGRESS: The handshake is complete, verification string has been
   * generated, but has not been confirmed. After authenticating the handshake out-of-band, use
   * [Ukey2Handshake.verifyHandshake] to mark the handshake as verified.
   *  * FINISHED: The handshake is finished, and caller can use
   * [Ukey2Handshake.toConnectionContext] to produce a [D2DConnectionContext].
   *  * ALREADY_USED: The handshake has already been used and should be discarded / garbage
   * collected.
   *  * ERROR: The handshake produced an error and should be destroyed.
   *
   */
  enum class State {
    IN_PROGRESS,
    VERIFICATION_NEEDED,
    VERIFICATION_IN_PROGRESS,
    FINISHED,
    ALREADY_USED,
    ERROR
  }

  /**
   * Currently implemented UKEY2 handshake ciphers. Each cipher is a tuple consisting of a key
   * negotiation cipher and a hash function used for a commitment. Currently, the ciphers are:
   * `
   * +-----------------------------------------------------+
   * | Enum        | Key negotiation       | Hash function |
   * +-------------+-----------------------+---------------+
   * | P256_SHA512 | ECDH using NIST P-256 | SHA512        |
   * +-----------------------------------------------------+
  ` *
   *
   *
   * Note that these should correspond to values in device_to_device_messages.proto.
   */
  enum class HandshakeCipher(val value: Ukey2HandshakeCipher) {
    P256_SHA512(Ukey2HandshakeCipher.P256_SHA512);
  }

  /**
   * If thrown, this exception contains information that should be sent on the wire. Specifically,
   * the [.getAlertMessageToSend] method returns a `byte[]` that communicates the
   * error to the other party in the handshake. Meanwhile, the [.getMessage] method can be
   * used to get a log-able error message.
   */
  class AlertException(alertMessageToLog: String?, alertMessageToSend: Ukey2Alert) : Exception(alertMessageToLog) {
    private val alertMessageToSend: Ukey2Alert

    init {
      this.alertMessageToSend = alertMessageToSend
    }

    /**
     * @return a message suitable for sending to other member of handshake.
     */
    fun getAlertMessageToSend(): ByteArray {
      return alertMessageToSend.encode()
    }
  }

  // Clients need to store a map of message 3's (client finishes) for each commitment.
  private val rawMessage3Map: MutableMap<HandshakeCipher, ByteArray> = mutableMapOf()
  private val handshakeCipher: HandshakeCipher?
  private val handshakeRole: HandshakeRole
  private var handshakeState: InternalState
  private val ourKeyPair: EcKeyPair
  private lateinit var theirPublicKey: EcPoint
  private lateinit var derivedSecretKey: ByteArray

  // Servers need to store client commitments.
  private var theirCommitment: ByteArray? = null

  // We store the raw messages sent for computing the authentication strings and next key.
  private lateinit var rawMessage1: ByteArray
  private lateinit var rawMessage2: ByteArray

  // Enums for internal state machinery
  private enum class InternalState {
    // Initiator/client state
    CLIENT_START,
    CLIENT_WAITING_FOR_SERVER_INIT,
    CLIENT_AFTER_SERVER_INIT,

    // Responder/server state
    SERVER_START,
    SERVER_AFTER_CLIENT_INIT,
    SERVER_WAITING_FOR_CLIENT_FINISHED,

    // Common completion state
    HANDSHAKE_VERIFICATION_NEEDED,
    HANDSHAKE_VERIFICATION_IN_PROGRESS,
    HANDSHAKE_FINISHED,
    HANDSHAKE_ALREADY_USED,
    HANDSHAKE_ERROR
  }

  // Helps us remember our role in the handshake
  private enum class HandshakeRole {
    CLIENT,
    SERVER
  }

  /**
   * Never invoked directly. Caller should use [.forInitiator] or
   * [.forResponder] instead.
   *
   * @throws HandshakeException if an unrecoverable error occurs and the connection should be shut
   * down.
   */
  init {
    if (cipher == null) {
      throwIllegalArgumentException("Invalid handshake cipher")
      throw HandshakeException("unreachable")
    }

    handshakeCipher = cipher
    handshakeRole = when (state) {
      InternalState.CLIENT_START -> CLIENT
      InternalState.SERVER_START -> SERVER
      else -> {
        throwIllegalStateException("Invalid handshake state")
        throw IllegalStateException("unreachable")
      }
    }
    handshakeState = state
    ourKeyPair = genKeyPair(cipher)
  }

  val nextHandshakeMessage: ByteArray
    /**
     * Get the next handshake message suitable for sending on the wire.
     *
     * @throws HandshakeException if an unrecoverable error occurs and the connection should be shut
     * down.
     */
    get() {
      when (handshakeState) {
        InternalState.CLIENT_START -> {
          rawMessage1 = makeUkey2Message(CLIENT_INIT, makeClientInitMessage())
          handshakeState = InternalState.CLIENT_WAITING_FOR_SERVER_INIT
          return rawMessage1
        }

        InternalState.SERVER_AFTER_CLIENT_INIT -> {
          rawMessage2 = makeUkey2Message(SERVER_INIT, makeServerInitMessage())
          handshakeState = InternalState.SERVER_WAITING_FOR_CLIENT_FINISHED
          return rawMessage2
        }

        InternalState.CLIENT_AFTER_SERVER_INIT -> {
          // Make sure we have a message 3 for the chosen cipher.

          val message = rawMessage3Map[handshakeCipher] ?: run {
            throwIllegalStateException(
              "Client state is CLIENT_AFTER_SERVER_INIT, and cipher is "
                  + handshakeCipher
                  + ", but no corresponding raw client finished message has been generated"
            )
            throw IllegalStateException("unreachable")
          }

          handshakeState = InternalState.HANDSHAKE_VERIFICATION_NEEDED
          return message
        }

        else -> {
          throwIllegalStateException("Cannot get next message in state: $handshakeState")
          throw IllegalStateException("unreachable")
        }
      }
    }

  /**
   * Returns an authentication string suitable for authenticating the handshake out-of-band. Note
   * that the authentication string can be short (e.g., a 6 digit visual confirmation code). Note:
   * this should only be called when the state returned byte [.getHandshakeState] is
   * [State.VERIFICATION_NEEDED], which means this can only be called once.
   *
   * @param byteLength length of output in bytes. Min length is 1; max length is 32.
   */
  fun getVerificationString(byteLength: Int): ByteArray {
    if (byteLength < 1 || byteLength > 32) {
      throwIllegalArgumentException("Minimum length is 1 byte, max is 32 bytes")
    }
    if (handshakeState != InternalState.HANDSHAKE_VERIFICATION_NEEDED) {
      throwIllegalStateException("Unexpected state: $handshakeState")
      throw IllegalStateException("unreachable")
    }

    try {
      derivedSecretKey = getSecretKeyAgreement(ourKeyPair, theirPublicKey)
    } catch (e: Exception) {
      // unreachable in practice
      throwHandshakeException(e)
      throw IllegalStateException("unreachable")
    }

    val info: ByteArray = rawMessage1 + rawMessage2
    val salt: ByteArray
    try {
      salt = "UKEY2 v1 auth".encodeToByteArray(throwOnInvalidSequence = true)
    } catch (e: CharacterCodingException) {
      // unreachable in practice
      throwHandshakeException(e)
      throw IllegalStateException("unreachable")
    }
    val authString = hkdf(derivedSecretKey, salt, info)

    handshakeState = InternalState.HANDSHAKE_VERIFICATION_IN_PROGRESS
    return authString.take(byteLength).toByteArray()
  }

  private fun getSecretKeyAgreement(ourKeyPair: EcKeyPair, theirPublicKey: EcPoint): ByteArray {
    //    TODO reduce public key to 32 bytes?
    val sharedSecretKey = EcDhKeyAgreement.keyAgreement(ourKeyPair, theirPublicKey)

    return EcSha256.hash(sharedSecretKey.xByteArray.takeLast(32).toByteArray())
  }

  /**
   * Invoked to let handshake state machine know that caller has validated the authentication
   * string obtained via [.getVerificationString]; Note: this should only be called when
   * the state returned byte [.getHandshakeState] is [State.VERIFICATION_IN_PROGRESS].
   */
  fun verifyHandshake() {
    if (handshakeState != InternalState.HANDSHAKE_VERIFICATION_IN_PROGRESS) {
      throwIllegalStateException("Unexpected state: $handshakeState")
    }
    handshakeState = InternalState.HANDSHAKE_FINISHED
  }

  /**
   * Parses the given handshake message.
   */
  fun parseHandshakeMessage(handshakeMessage: ByteArray) {
    when (handshakeState) {
      InternalState.SERVER_START -> {
        parseMessage1(handshakeMessage)
        handshakeState = InternalState.SERVER_AFTER_CLIENT_INIT
      }

      InternalState.CLIENT_WAITING_FOR_SERVER_INIT -> {
        parseMessage2(handshakeMessage)
        handshakeState = InternalState.CLIENT_AFTER_SERVER_INIT
      }

      InternalState.SERVER_WAITING_FOR_CLIENT_FINISHED -> {
        parseMessage3(handshakeMessage)
        handshakeState = InternalState.HANDSHAKE_VERIFICATION_NEEDED
      }

      else -> {
        throwIllegalStateException("Cannot parse message in state $handshakeState")
        throw IllegalStateException("unreachable")
      }
    }
  }

  /**
   * Returns the current state of the handshake. See [State].
   */
  fun getHandshakeState(): State {
    return when (handshakeState) {
      InternalState.CLIENT_START, InternalState.CLIENT_WAITING_FOR_SERVER_INIT, InternalState.CLIENT_AFTER_SERVER_INIT, InternalState.SERVER_START, InternalState.SERVER_WAITING_FOR_CLIENT_FINISHED, InternalState.SERVER_AFTER_CLIENT_INIT ->         // fallback intended -- these are all in-progress states
        State.IN_PROGRESS

      InternalState.HANDSHAKE_ERROR -> State.ERROR
      InternalState.HANDSHAKE_VERIFICATION_NEEDED -> State.VERIFICATION_NEEDED
      InternalState.HANDSHAKE_VERIFICATION_IN_PROGRESS -> State.VERIFICATION_IN_PROGRESS
      InternalState.HANDSHAKE_FINISHED -> State.FINISHED
      InternalState.HANDSHAKE_ALREADY_USED -> State.ALREADY_USED
    }
  }

  /**
   * Can be called to generate a [D2DConnectionContext]. Note: this should only be called
   * when the state returned byte [.getHandshakeState] is [State.FINISHED].
   *
   * @throws HandshakeException
   */
  @Throws(HandshakeException::class)
  fun toConnectionContext(): D2DConnectionContext {

    require(handshakeState == InternalState.HANDSHAKE_FINISHED) {
      throwIllegalStateException("Unexpected state: $handshakeState")
      "Unexpected state: $handshakeState"
    }

    require(::derivedSecretKey.isInitialized) {
      throwIllegalStateException("Unexpected state error: derived key is null")
      "Unexpected state error: derived key is null"
    }

    val info: ByteArray = rawMessage1 + rawMessage2
    val saltNext = "UKEY2 v1 next".encodeToByteArray()

    val nextProtocolKey = hkdf(derivedSecretKey, saltNext, info)

    val clientKey: ByteArray = hkdf(nextProtocolKey, d2dSalt, "client".encodeToByteArray(), 32)
    val serverKey: ByteArray = hkdf(nextProtocolKey, d2dSalt, "server".encodeToByteArray(), 32)

    handshakeState = InternalState.HANDSHAKE_ALREADY_USED

    return D2DConnectionContextV1(
      encodeKey = if (handshakeRole == CLIENT) clientKey else serverKey,
      decodeKey = if (handshakeRole == CLIENT) serverKey else clientKey,
      0,
      0
    )
  }

  /**
   * Generates the byte[] encoding of a [Ukey2ClientInit] message.
   *
   */
  private fun makeClientInitMessage(): ByteArray {
    val clientInit = Ukey2ClientInit(
      version = VERSION,
      random = generateRandomNonce().toByteString(),
      next_protocol = NEXT_PROTOCOL,
      cipher_commitments = listOf(generateP256SHA512Commitment())
    )

    return clientInit.encode()
  }

  /**
   * Generates the byte[] encoding of a [Ukey2ServerInit] message.
   */
  private fun makeServerInitMessage(): ByteArray {
    val publicKey = getGenericPublicKey(ourKeyPair)

    val serverInit = Ukey2ServerInit(
      version = VERSION,
      random = generateRandomNonce().toByteString(),
      handshake_cipher = handshakeCipher?.value,
      public_key = publicKey.encodeByteString()
    )

    return serverInit.encode()
  }

  /**
   * Generates a keypair for the provided handshake cipher. Currently only P256_SHA512 is
   * supported.
   *
   * @throws HandshakeException
   */
  @Throws(HandshakeException::class)
  private fun genKeyPair(cipher: HandshakeCipher): EcKeyPair {
    return when (cipher) {
      HandshakeCipher.P256_SHA512 -> EcKeyGenerator.newInstance(Secp256r1)
    }
  }

  /**
   * Attempts to parse message 1 (which is a wrapped [Ukey2ClientInit]). See go/ukey2 for
   * details.
   *
   * @throws AlertException if an error occurs
   */
  @Throws(AlertException::class, HandshakeException::class)
  private fun parseMessage1(handshakeMessage: ByteArray) {
    // Deserialize the protobuf; send a BAD_MESSAGE message if deserialization fails
    val message: Ukey2Message
    try {
      message = Ukey2Message.ADAPTER.decode(handshakeMessage)
    } catch (e: Exception) {
      throwAlertException(
        BAD_MESSAGE,
        "Can't parse message 1 " + e.message
      )
      throw IllegalStateException("unreachable")
    }

    // Verify that message_type == Type.CLIENT_INIT; send a BAD_MESSAGE_TYPE message if mismatch
    if (message.message_type != CLIENT_INIT) {
      throwAlertException(
        Ukey2Alert.AlertType.BAD_MESSAGE_TYPE,
        "Expected, but did not find ClientInit message type"
      )
      throw IllegalStateException("unreachable")
    }

    // Deserialize message_data as a ClientInit message; send a BAD_MESSAGE_DATA message if
    // deserialization fails
    if (message.message_data == null) {
      throwAlertException(
        Ukey2Alert.AlertType.BAD_MESSAGE_DATA,
        "Expected message data, but didn't find it"
      )
      throw IllegalStateException("unreachable")
    }

    val clientInit: Ukey2ClientInit
    try {
      clientInit = Ukey2ClientInit.ADAPTER.decode(message.message_data)
    } catch (e: Exception) {
      throwAlertException(
        Ukey2Alert.AlertType.BAD_MESSAGE_DATA,
        "Can't parse message data into ClientInit"
      )
      throw IllegalStateException("unreachable")
    }

    // Check that version == VERSION; send BAD_VERSION message if mismatch
    if (clientInit.version == null) {
      throwAlertException(Ukey2Alert.AlertType.BAD_VERSION, "ClientInit missing version")
    }

    if (clientInit.version != VERSION) {
      throwAlertException(Ukey2Alert.AlertType.BAD_VERSION, "ClientInit version mismatch")
      throw IllegalStateException("unreachable")
    }

    // Check that random is exactly NONCE_LENGTH_IN_BYTES bytes; send Alert.BAD_RANDOM message if
    // not.
    if (clientInit.random == null) {
      throwAlertException(Ukey2Alert.AlertType.BAD_RANDOM, "ClientInit missing random")
      throw IllegalStateException("unreachable")
    }

    if (clientInit.random.toByteArray().size != NONCE_LENGTH_IN_BYTES) {
      throwAlertException(Ukey2Alert.AlertType.BAD_RANDOM, "ClientInit has incorrect nonce length")
      throw IllegalStateException("unreachable")
    }

    // Check to see if any of the handshake_cipher in cipher_commitment are acceptable. Servers
    // should select the first handshake_cipher that it finds acceptable to support clients
    // signaling deprecated but supported HandshakeCiphers. If no handshake_cipher is acceptable
    // (or there are no HandshakeCiphers in the message), the server sends a BAD_HANDSHAKE_CIPHER
    //  message
    val commitments: List<Ukey2ClientInit.CipherCommitment> = clientInit.cipher_commitments
    if (commitments.isEmpty()) {
      throwAlertException(
        Ukey2Alert.AlertType.BAD_HANDSHAKE_CIPHER, "ClientInit is missing cipher commitments"
      )
    }
    for (commitment: Ukey2ClientInit.CipherCommitment in commitments) {
      if ((commitment.handshake_cipher == null || commitment.commitment == null)) {
        throwAlertException(
          Ukey2Alert.AlertType.BAD_HANDSHAKE_CIPHER,
          "ClientInit has improperly formatted cipher commitment"
        )
        throw IllegalStateException("unreachable")
      }

      // TODO(aczeskis): for now we only support one cipher, eventually support more
      if (commitment.handshake_cipher == handshakeCipher?.value) {
        theirCommitment = commitment.commitment.toByteArray()
      }
    }
    if (theirCommitment == null) {
      throwAlertException(
        Ukey2Alert.AlertType.BAD_HANDSHAKE_CIPHER,
        "No acceptable commitments found"
      )
      throw IllegalStateException("unreachable")
    }

    // Checks that next_protocol contains a protocol that the server supports. Send a
    // BAD_NEXT_PROTOCOL message if not. We currently only support one protocol
    if (NEXT_PROTOCOL != clientInit.next_protocol) {
      throwAlertException(Ukey2Alert.AlertType.BAD_NEXT_PROTOCOL, "Incorrect next protocol")
      throw IllegalStateException("unreachable")
    }

    // Store raw message for AUTH_STRING computation
    rawMessage1 = handshakeMessage
  }

  /**
   * Attempts to parse message 2 (which is a wrapped [Ukey2ServerInit]). See go/ukey2 for
   * details.
   */
  @Throws(AlertException::class, HandshakeException::class)
  private fun parseMessage2(handshakeMessage: ByteArray) {
    // Deserialize the protobuf; send a BAD_MESSAGE message if deserialization fails
    val message: Ukey2Message
    try {
      message = Ukey2Message.ADAPTER.decode(handshakeMessage)
    } catch (e: Exception) {
      throwAlertException(
        BAD_MESSAGE,
        "Can't parse message 2 " + e.message
      )
      throw IllegalStateException("unreachable")
    }

    // Verify that message_type == Type.SERVER_INIT; send a BAD_MESSAGE_TYPE message if mismatch

    if (message.message_type == null) {
      throwAlertException(
        Ukey2Alert.AlertType.BAD_MESSAGE_TYPE,
        "Expected, but did not find message type"
      )
      throw IllegalStateException("unreachable")
    }
    if (message.message_type == ALERT) {
      handshakeState = InternalState.HANDSHAKE_ERROR
      throwHandshakeMessageFromAlertMessage(message)
    }
    if (message.message_type != SERVER_INIT) {
      throwAlertException(
        Ukey2Alert.AlertType.BAD_MESSAGE_TYPE,
        "Expected, but did not find SERVER_INIT message type"
      )
      throw IllegalStateException("unreachable")
    }

    // Deserialize message_data as a ServerInit message; send a BAD_MESSAGE_DATA message if
    // deserialization fails
    if (message.message_data == null) {
      throwAlertException(
        Ukey2Alert.AlertType.BAD_MESSAGE_DATA,
        "Expected message data, but didn't find it"
      )
      throw IllegalStateException("unreachable")
    }
    val serverInit: Ukey2ServerInit
    try {
      serverInit = Ukey2ServerInit.ADAPTER.decode(message.message_data)
    } catch (e: Exception) {
      throwAlertException(
        Ukey2Alert.AlertType.BAD_MESSAGE_DATA,
        "Can't parse message data into ServerInit"
      )
      throw IllegalStateException("unreachable")
    }

    // Check that version == VERSION; send BAD_VERSION message if mismatch
    if (serverInit.version == null) {
      throwAlertException(Ukey2Alert.AlertType.BAD_VERSION, "ServerInit missing version")
      throw IllegalStateException("unreachable")
    }

    if (serverInit.version != VERSION) {
      throwAlertException(Ukey2Alert.AlertType.BAD_VERSION, "ServerInit version mismatch")
      throw IllegalStateException("unreachable")
    }

    // Check that random is exactly NONCE_LENGTH_IN_BYTES bytes; send Alert.BAD_RANDOM message if
    // not.
    if (serverInit.random == null) {
      throwAlertException(Ukey2Alert.AlertType.BAD_RANDOM, "ServerInit missing random")
      throw IllegalStateException("unreachable")
    }

    if (serverInit.random.toByteArray().size != NONCE_LENGTH_IN_BYTES) {
      throwAlertException(Ukey2Alert.AlertType.BAD_RANDOM, "ServerInit has incorrect nonce length")
      throw IllegalStateException("unreachable")
    }

    // Check that handshake_cipher matches a handshake cipher that was sent in
    // ClientInit.cipher_commitments. If not, send a BAD_HANDSHAKECIPHER message
    if (serverInit.handshake_cipher == null) {
      throwAlertException(Ukey2Alert.AlertType.BAD_HANDSHAKE_CIPHER, "No handshake cipher found")
      throw IllegalStateException("unreachable")
    }
    var serverCipher: HandshakeCipher? = null
    for (cipher: HandshakeCipher in HandshakeCipher.values()) {
      if (cipher.value == serverInit.handshake_cipher) {
        serverCipher = cipher
        break
      }
    }
    if (serverCipher == null || serverCipher != handshakeCipher) {
      throwAlertException(
        Ukey2Alert.AlertType.BAD_HANDSHAKE_CIPHER,
        "No acceptable handshake cipher found"
      )
      throw IllegalStateException("unreachable")
    }

    // Check that public_key parses into a correct public key structure. If not, send a
    // BAD_PUBLIC_KEY message.
    if (serverInit.public_key == null) {
      throwAlertException(Ukey2Alert.AlertType.BAD_PUBLIC_KEY, "No public key found in ServerInit")
      throw IllegalStateException("unreachable")
    }

    theirPublicKey = runCatching { parseP256PublicKey(serverInit.public_key.toByteArray()) }
      .onFailure { throwAlertException(Ukey2Alert.AlertType.BAD_PUBLIC_KEY, "Cant decrypt publickey in ServerInit") }
      .getOrThrow()

    // Store raw message for AUTH_STRING computation
    rawMessage2 = handshakeMessage
  }

  /**
   * Attempts to parse message 3 (which is a wrapped [Ukey2ClientFinished]). See go/ukey2 for
   * details.
   */
  @Throws(HandshakeException::class)
  private fun parseMessage3(handshakeMessage: ByteArray) {
    // Deserialize the protobuf; terminate the connection if deserialization fails.
    val message: Ukey2Message
    try {
      message = Ukey2Message.ADAPTER.decode(handshakeMessage)
    } catch (e: Exception) {
      throwHandshakeException("Can't parse message 3", e)
      throw IllegalStateException("unreachable")
    }

    // Verify that message_type == Type.CLIENT_FINISH; terminate connection if mismatch occurs
    if (message.message_type == null) {
      throw HandshakeException("Expected, but did not find message type")
    }
    if (message.message_type == ALERT) {
      throwHandshakeMessageFromAlertMessage(message)
    }
    if (message.message_type != CLIENT_FINISH) {
      throwHandshakeException("Expected, but did not find CLIENT_FINISH message type")
    }

    // Verify that the hash of the ClientFinished matches the expected commitment from ClientInit.
    // Terminate the connection if the expected match fails.
    verifyCommitment(handshakeMessage)

    // Deserialize message_data as a ClientFinished message; terminate the connection if
    // deserialization fails.
    if (message.message_data == null) {
      throwHandshakeException("Expected message data, but didn't find it")
      throw IllegalStateException("unreachable")
    }
    val clientFinished: Ukey2ClientFinished
    try {
      clientFinished = Ukey2ClientFinished.ADAPTER.decode(message.message_data)
    } catch (e: Exception) {
      throwHandshakeException(e)
      throw IllegalStateException("unreachable")
    }

    // Check that public_key parses into a correct public key structure. If not, terminate the
    // connection.
    if (clientFinished.public_key == null) {
      throwHandshakeException("No public key found in ClientFinished")
      throw IllegalStateException("unreachable")
    }
    try {
      theirPublicKey = parseP256PublicKey(clientFinished.public_key.toByteArray())
    } catch (e: AlertException) {
      // Wrap in a HandshakeException because error should not be sent on the wire.
      throwHandshakeException(e)
      throw IllegalStateException("unreachable")
    }
  }

  @Throws(HandshakeException::class)
  private fun verifyCommitment(handshakeMessage: ByteArray) {
    val actualClientFinishHash: ByteArray
    when (handshakeCipher) {
      HandshakeCipher.P256_SHA512 -> actualClientFinishHash = sha512(handshakeMessage)
      else -> {       // should be unreachable
        throwIllegalStateException("Unexpected handshakeCipher")
        throw IllegalStateException("unreachable")
      }
    }

    // Time constant after Java SE 6 Update 17
    // See http://www.oracle.com/technetwork/java/javase/6u17-141447.html
    if (!isEqualDigest(actualClientFinishHash, theirCommitment)) {
      throwHandshakeException("Commitment does not match")
    }
  }

  // Copied from MessageDigest.isEqual()
  private fun isEqualDigest(digesta: ByteArray?, digestb: ByteArray?): Boolean {
    if (digesta == null || digestb == null) {
      return false
    }
    val lenA = digesta.size
    val lenB = digestb.size
    if (lenB == 0) {
      return lenA == 0
    }
    var result = 0
    result = result or lenA - lenB

    // time-constant comparison
    for (i in 0 until lenA) {
      // If i >= lenB, indexB is 0; otherwise, i.
      val indexB = (i - lenB ushr 31) * i
      result = result or (digesta[i].toInt() xor digestb[indexB].toInt())
    }
    return result == 0
  }

  @Throws(HandshakeException::class)
  private fun throwHandshakeMessageFromAlertMessage(message: Ukey2Message?) {
    if (message?.message_data != null) {
      val alert: Ukey2Alert
      try {
        alert = Ukey2Alert.ADAPTER.decode(message.message_data)
      } catch (e: Exception) {
        throwHandshakeException("Cannot parse alert message", e)
        throw IllegalStateException("unreachable")
      }
      if (alert.type != null && alert.error_message != null) {
        throwHandshakeException(
          (("Received Alert message. Type: "
              + alert.type
              ) + " Error Message: "
              + alert.error_message)
        )
      } else if (alert.type != null) {
        throwHandshakeException("Received Alert message. Type: " + alert.type)
      }
    }
    throwHandshakeException("Received empty Alert Message")
  }

  /**
   * Parses an encoded public P256 key.
   */
  @Throws(AlertException::class, HandshakeException::class)
  private fun parseP256PublicKey(encodedPublicKey: ByteArray): EcPoint {

    val genericPublicKey = GenericPublicKey.ADAPTER.decode(encodedPublicKey)

    return when (genericPublicKey.type) {
      PublicKeyType.EC_P256 -> {
        val publicKey = genericPublicKey.ec_p256_public_key ?: throw IllegalStateException("key should not be null")
        EcPoint.parseFromByteArray(publicKey.x.toByteArray(), publicKey.y.toByteArray(), Secp256r1)
      }

      PublicKeyType.RSA2048 -> throw UnsupportedOperationException("RSA2048 not supported")
      PublicKeyType.DH2048_MODP -> throw UnsupportedOperationException("DH2048_MODP not supported")
    }
  }

  /**
   * Generates a [CipherCommitment] for the P256_SHA512 cipher.
   */
  @Throws(HandshakeException::class)
  private fun generateP256SHA512Commitment(): Ukey2ClientInit.CipherCommitment {
    // Generate the corresponding finished message if it's not done yet
    if (!rawMessage3Map.containsKey(HandshakeCipher.P256_SHA512)) {
      generateP256SHA512ClientFinished(ourKeyPair)
    }

    return Ukey2ClientInit.CipherCommitment(
      handshake_cipher = Ukey2HandshakeCipher.P256_SHA512,
      commitment = sha512(rawMessage3Map.getValue(HandshakeCipher.P256_SHA512)).toByteString()
    )
  }

  /**
   * Generates and records a [Ukey2ClientFinished] message for the P256_SHA512 cipher.
   */
  private fun generateP256SHA512ClientFinished(p256KeyPair: EcKeyPair): Ukey2ClientFinished {
    val encodedKey = getGenericPublicKey(p256KeyPair).encodeByteString()

    val clientFinished = Ukey2ClientFinished(
      public_key = encodedKey
    )

    rawMessage3Map[HandshakeCipher.P256_SHA512] = makeUkey2Message(CLIENT_FINISH, clientFinished.encode())
    return clientFinished
  }

  private fun getGenericPublicKey(keyPair: EcKeyPair): GenericPublicKey {
    return GenericPublicKey(
      type = PublicKeyType.EC_P256,
      ec_p256_public_key = EcP256PublicKey(
        x = keyPair.publicKey.xByteArray.toByteString(),
        y = keyPair.publicKey.yByteArray.toByteString(),
      )
    )
  }

  /**
   * Generates the serialized representation of a [Ukey2Message] based on the provided type
   * and data.
   */
  private fun makeUkey2Message(messageType: Ukey2Message.Type, messageData: ByteArray?): ByteArray {

    when (messageType) {
      ALERT, CLIENT_INIT, SERVER_INIT, CLIENT_FINISH -> {}
      else -> {
        throwIllegalArgumentException("Invalid message type: $messageType")
        throw IllegalStateException("unreachable")
      }
    }

    // Alerts a blank message data field
    if (messageType != ALERT) {
      if (messageData == null || messageData.isEmpty()) {
        throwIllegalArgumentException("Cannot send empty message data for non-alert messages")
        throw IllegalStateException("unreachable")
      }
    }

    return Ukey2Message(
      message_type = messageType,
      message_data = messageData?.toByteString()
    ).encode()
  }

  /**
   * Returns a [Ukey2Alert] message of given type and having the loggable additional data if
   * present.
   */
  @Throws(HandshakeException::class)
  private fun makeAlertMessage(
    alertType: Ukey2Alert.AlertType,
    loggableAdditionalData: String?
  ): Ukey2Alert {

    return Ukey2Alert(
      type = alertType,
      error_message = loggableAdditionalData
    )
  }

  /**
   * Handy wrapper to do SHA512.
   */
  @Throws(HandshakeException::class)
  private fun sha512(input: ByteArray): ByteArray {
    return EcSha512.hash(input)
  }

  // Exception wrappers that remember to set the handshake state to ERROR
  @Throws(AlertException::class, HandshakeException::class)
  private fun throwAlertException(alertType: Ukey2Alert.AlertType, alertLogStatement: String) {
    handshakeState = InternalState.HANDSHAKE_ERROR
    throw AlertException(alertLogStatement, makeAlertMessage(alertType, alertLogStatement))
  }

  @Throws(HandshakeException::class)
  private fun throwHandshakeException(logMessage: String) {
    handshakeState = InternalState.HANDSHAKE_ERROR
    throw HandshakeException(logMessage)
  }

  @Throws(HandshakeException::class)
  private fun throwHandshakeException(e: Exception) {
    handshakeState = InternalState.HANDSHAKE_ERROR
    throw HandshakeException(e)
  }

  @Throws(HandshakeException::class)
  private fun throwHandshakeException(logMessage: String, e: Exception) {
    handshakeState = InternalState.HANDSHAKE_ERROR
    throw HandshakeException(logMessage, e)
  }

  private fun throwIllegalStateException(logMessage: String) {
    handshakeState = InternalState.HANDSHAKE_ERROR
    throw IllegalStateException(logMessage)
  }

  private fun throwIllegalArgumentException(logMessage: String) {
    handshakeState = InternalState.HANDSHAKE_ERROR
    throw IllegalArgumentException(logMessage)
  }

  companion object {
    /**
     * Creates a [Ukey2Handshake] with a particular cipher that can be used by an initiator /
     * client.
     *
     * @throws HandshakeException
     */
    @Throws(HandshakeException::class)
    fun forInitiator(cipher: HandshakeCipher?): Ukey2Handshake {
      return Ukey2Handshake(InternalState.CLIENT_START, cipher)
    }

    /**
     * Creates a [Ukey2Handshake] with a particular cipher that can be used by an responder /
     * server.
     *
     * @throws HandshakeException
     */
    @Throws(HandshakeException::class)
    fun forResponder(cipher: HandshakeCipher?): Ukey2Handshake {
      return Ukey2Handshake(InternalState.SERVER_START, cipher)
    }

    // Maximum version of the handshake supported by this class.
    val VERSION = 1

    // Random nonce is fixed at 32 bytes (as per go/ukey2).
    private val NONCE_LENGTH_IN_BYTES = 32
    private val UTF_8 = "UTF-8"

    // Currently, we only support one next protocol.
    private const val NEXT_PROTOCOL = "AES_256_CBC-HMAC_SHA256"

    /**
     * Generates a cryptoraphically random nonce of NONCE_LENGTH_IN_BYTES bytes.
     */
    private fun generateRandomNonce(): ByteArray {
      return SecureRandom().nextBytesOf(NONCE_LENGTH_IN_BYTES)
    }
  }
}

private class HandshakeException : Exception {
  constructor(message: String) : super(message)
  constructor(message: String, cause: Throwable) : super(message, cause)
  constructor(cause: Throwable) : super(cause)
}