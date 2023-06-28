package com.carlonzo.ukey2.d2d

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
import com.google.security.cryptauth.lib.securegcm.DeviceToDeviceMessage
import okio.ByteString.Companion.toByteString


/**
 * The full context of a secure connection. This object has methods to encode and decode messages
 * that are to be sent to another device.
 *
 * Subclasses keep track of the keys shared with the other device, and of the sequence in which the
 * messages are expected.
 */
abstract class D2DConnectionContext protected constructor(
  /**
   * @return the version of the D2D protocol.
   */
  val protocolVersion: Int
) {

  /**
   * Once initiator and responder have exchanged public keys, use this method to encrypt and
   * sign a payload. Both initiator and responder devices can use this message.
   *
   * @param payload the payload that should be encrypted.
   */
  fun encodeMessageToPeer(payload: ByteArray): ByteArray {
    incrementSequenceNumberForEncoding()

    val message = createDeviceToDeviceMessage(
      message = payload,
      sequenceNumber = sequenceNumberForEncoding
    )

    return D2DCryptoOps.signcryptPayload(
      Payload(
        payloadType = PayloadType.DEVICE_TO_DEVICE_MESSAGE,
        message = message.encode()
      ),
      encodeKey,
      encodeKey
    )

  }

  /**
   * Encrypting/signing a string for transmission to another device.
   *
   * @see .encodeMessageToPeer
   * @param payload the payload that should be encrypted.
   */
  fun encodeMessageToPeer(payload: String): ByteArray {
    return encodeMessageToPeer(payload.encodeToByteArray())
  }

  /**
   * Once InitiatorHello and ResponderHello(AndPayload) are exchanged, use this method
   * to decrypt and verify a message received from the other device. Both initiator and
   * responder device can use this message.
   *
   * @param message the message that should be encrypted.
   * @throws SignatureException if the message from the remote peer did not pass verification
   */
  fun decodeMessageFromPeer(message: ByteArray): ByteArray {
    val payload: Payload = D2DCryptoOps.verifydecryptPayload(message, decodeKey)

    if (PayloadType.DEVICE_TO_DEVICE_MESSAGE != payload.payloadType) {
      throw IllegalStateException("wrong message type in device-to-device message")
    }

    val messageProto: DeviceToDeviceMessage = DeviceToDeviceMessage.ADAPTER.decode(payload.message)
    incrementSequenceNumberForDecoding()

    if (messageProto.sequence_number != sequenceNumberForDecoding) {
      throw IllegalStateException("Incorrect sequence number")
    }

    return messageProto.message?.toByteArray()!!
  }

  /**
   * Once InitiatorHello and ResponderHello(AndPayload) are exchanged, use this method
   * to decrypt and verify a message received from the other device. Both initiator and
   * responder device can use this message.
   *
   * @param message the message that should be encrypted.
   */
  fun decodeMessageFromPeerAsString(message: ByteArray): String {
    return message.decodeToString(throwOnInvalidSequence = true)
  }

  abstract val sessionUnique: ByteArray?

  /**
   * Increments the sequence number used for encoding messages.
   */
  protected abstract fun incrementSequenceNumberForEncoding()

  /**
   * Increments the sequence number used for decoding messages.
   */
  protected abstract fun incrementSequenceNumberForDecoding()

  abstract val sequenceNumberForEncoding: Int

  abstract val sequenceNumberForDecoding: Int

  abstract val encodeKey: ByteArray

  abstract val decodeKey: ByteArray

  /**
   * Creates a saved session that can later be used for resumption.  Note, this must be stored in a
   * secure location.
   *
   * @return the saved session, suitable for resumption.
   */
  abstract fun saveSession(): ByteArray?

  companion object {

    // package-private
    fun createDeviceToDeviceMessage(message: ByteArray, sequenceNumber: Int): DeviceToDeviceMessage {

      return DeviceToDeviceMessage(
        sequence_number = sequenceNumber,
        message = message.toByteString()
      )
    }

    /**
     * Parse a saved session info and attempt to construct a resumed context.
     * The first byte in a saved session info must always be the protocol version.
     * Note that an [IllegalArgumentException] will be thrown if the savedSessionInfo is not
     * properly formatted.
     *
     * @return a resumed context from a saved session.
     */
    fun fromSavedSession(savedSessionInfo: ByteArray): D2DConnectionContext {
      if (savedSessionInfo.isEmpty()) {
        throw IllegalArgumentException("savedSessionInfo null or too short")
      }

      when (val protocolVersion = savedSessionInfo[0].toInt() and 0xff) {
//        0 -> {
//          // Version 0 has a 1 byte protocol version, a 4 byte sequence number,
//          // and 32 bytes of AES key (1 + 4 + 32 = 37)
//          if (savedSessionInfo.size != 37) {
//            throw IllegalArgumentException(
//              "Incorrect data length (" + savedSessionInfo.size + ") for v0 protocol"
//            )
//          }
//          val sequenceNumber = bytesToSignedInt(savedSessionInfo.copyOfRange(1,5))
//          val sharedKey: javax.crypto.SecretKey = javax.crypto.spec.SecretKeySpec(java.util.Arrays.copyOfRange(savedSessionInfo, 5, 37), "AES")
//          return D2DConnectionContextV0(sharedKey, sequenceNumber)
//        }

        1 -> {
          // Version 1 has a 1 byte protocol version, two 4 byte sequence numbers,
          // and two 32 byte AES keys (1 + 4 + 4 + 32 + 32 = 73)

          // TODO save verification key?
          if (savedSessionInfo.size != 73) {
            throw IllegalArgumentException("Incorrect data length for v1 protocol")
          }
          val encodeSequenceNumber = bytesToSignedInt(savedSessionInfo.copyOfRange(1, 5))
          val decodeSequenceNumber = bytesToSignedInt(savedSessionInfo.copyOfRange(5, 9))
          val encodeKey = savedSessionInfo.copyOfRange(9, 41)
          val decodeKey = savedSessionInfo.copyOfRange(41, 73)

          return D2DConnectionContextV1(
            encodeKey, decodeKey, encodeSequenceNumber,
            decodeSequenceNumber
          )
        }

        else -> throw IllegalArgumentException(
          ("Cannot rebuild context, unkown protocol version: $protocolVersion")
        )
      }
    }

    /**
     * Convert 4 bytes in big-endian representation into a signed int.
     */
    private fun bytesToSignedInt(bytes: ByteArray): Int {
      if (bytes.size != 4) {
        throw IllegalArgumentException(
          ("Expected 4 bytes to encode int, but got: "
              + bytes.size + " bytes")
        )
      }
      return (((bytes[0].toInt() shl 24) and -0x1000000)
          or ((bytes[1].toInt() shl 16) and 0x00ff0000)
          or ((bytes[2].toInt() shl 8) and 0x0000ff00)
          or (bytes[3].toInt() and 0x000000ff))
    }

    /**
     * Convert a signed int into a 4 byte big-endian representation
     */
    internal fun signedIntToBytes(`val`: Int): ByteArray {
      val bytes = ByteArray(4)
      bytes[0] = ((`val` shr 24) and 0xff).toByte()
      bytes[1] = ((`val` shr 16) and 0xff).toByte()
      bytes[2] = ((`val` shr 8) and 0xff).toByte()
      bytes[3] = (`val` and 0xff).toByte()
      return bytes
    }
  }
}