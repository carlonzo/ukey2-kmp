//package com.google.security.cryptauth.lib.securegcm
//
//// Copyright 2020 Google LLC
////
//// Licensed under the Apache License, Version 2.0 (the "License");
//// you may not use this file except in compliance with the License.
//// You may obtain a copy of the License at
////
////     https://www.apache.org/licenses/LICENSE-2.0
////
//// Unless required by applicable law or agreed to in writing, software
//// distributed under the License is distributed on an "AS IS" BASIS,
//// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//// See the License for the specific language governing permissions and
//// limitations under the License.
//
//
///**
// * Implementation of [D2DConnectionContext] for version 1 of the D2D protocol. In this
// * version, communication is fully duplex, as separate keys and sequence nubmers are used for
// * encoding and decoding.
// */
//class D2DConnectionContextV1 internal constructor(
//  encodeKey: javax.crypto.SecretKey?,
//  decodeKey: javax.crypto.SecretKey?,
//  initialEncodeSequenceNumber: Int,
//  initialDecodeSequenceNumber: Int
//) : D2DConnectionContext(PROTOCOL_VERSION) {
//
//  private override val encodeKey: javax.crypto.SecretKey?
//  private override val decodeKey: javax.crypto.SecretKey?
//  override var sequenceNumberForEncoding: Int
//    private set
//  override var sequenceNumberForDecoding: Int
//    private set
//
//  /**
//   * Package private constructor. Should never be called directly except by the
//   * [D2DHandshakeContext]
//   *
//   * @param encodeKey
//   * @param decodeKey
//   * @param initialEncodeSequenceNumber
//   * @param initialDecodeSequenceNumber
//   */
//  init {
//    this.encodeKey = encodeKey
//    this.decodeKey = decodeKey
//    sequenceNumberForEncoding = initialEncodeSequenceNumber
//    sequenceNumberForDecoding = initialDecodeSequenceNumber
//  }
//
//  @get:Throws(java.security.NoSuchAlgorithmException::class)
//  override val sessionUnique: ByteArray
//    get() {
//      if (encodeKey == null || decodeKey == null) {
//        throw java.lang.IllegalStateException(
//          "Connection has not been correctly initialized; encode key or decode key is null"
//        )
//      }
//
//      // Ensure that the initator and responder keys are hashed in a deterministic order, so they have
//      // the same session unique code.
//      val encodeKeyBytes: ByteArray = encodeKey.getEncoded()
//      val decodeKeyBytes: ByteArray = decodeKey.getEncoded()
//      val encodeKeyHash: Int = java.util.Arrays.hashCode(encodeKeyBytes)
//      val decodeKeyHash: Int = java.util.Arrays.hashCode(decodeKeyBytes)
//      val firstKeyBytes = if (encodeKeyHash < decodeKeyHash) encodeKeyBytes else decodeKeyBytes
//      val secondKeyBytes = if (firstKeyBytes == encodeKeyBytes) decodeKeyBytes else encodeKeyBytes
//      val md: java.security.MessageDigest = java.security.MessageDigest.getInstance("SHA-256")
//      md.update(D2DCryptoOps.SALT)
//      md.update(firstKeyBytes)
//      md.update(secondKeyBytes)
//      return md.digest()
//    }
//
//  override fun incrementSequenceNumberForEncoding() {
//    sequenceNumberForEncoding++
//  }
//
//  override fun incrementSequenceNumberForDecoding() {
//    sequenceNumberForDecoding++
//  }
//
//  override fun getEncodeKey(): javax.crypto.SecretKey? {
//    return encodeKey
//  }
//
//  override fun getDecodeKey(): javax.crypto.SecretKey? {
//    return decodeKey
//  }
//
//  /**
//   * Structure of saved session is:
//   * +------------------------------------------------------------------------------------------+
//   * |     1 Byte       | 4 Bytes (big endian) | 4 Bytes (big endian) |  32 Bytes  |  32 Bytes  |
//   * +------------------------------------------------------------------------------------------+
//   * | Protocol Version |   encode seq number  |   decode seq number  | encode key | decode key |
//   * +------------------------------------------------------------------------------------------+
//   */
//  override fun saveSession(): ByteArray? {
//    val bytes: java.io.ByteArrayOutputStream = java.io.ByteArrayOutputStream()
//    try {
//      // Protocol version
//      bytes.write(1)
//
//      // Encode sequence number
//      bytes.write(signedIntToBytes(sequenceNumberForEncoding))
//
//      // Decode sequence number
//      bytes.write(signedIntToBytes(sequenceNumberForDecoding))
//
//      // Encode Key
//      bytes.write(encodeKey.getEncoded())
//
//      // Decode Key
//      bytes.write(decodeKey.getEncoded())
//    } catch (e: java.io.IOException) {
//      // should not happen
//      e.printStackTrace()
//      return null
//    }
//    return bytes.toByteArray()
//  }
//
//  companion object {
//    const val PROTOCOL_VERSION = 1
//  }
//}