package com.carlonzo.ukey2.d2d

import com.carterharrison.ecdsa.hash.EcSha256
import okio.Buffer
import okio.IOException

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


/**
 * Implementation of [D2DConnectionContext] for version 1 of the D2D protocol. In this
 * version, communication is fully duplex, as separate keys and sequence nubmers are used for
 * encoding and decoding.
 */
class D2DConnectionContextV1 internal constructor(
  override val encodeKey: ByteArray,
  override val decodeKey: ByteArray,
  private val initialEncodeSequenceNumber: Int,
  private val initialDecodeSequenceNumber: Int
) : D2DConnectionContext(PROTOCOL_VERSION) {

  override var sequenceNumberForEncoding: Int = initialEncodeSequenceNumber
  override var sequenceNumberForDecoding: Int = initialDecodeSequenceNumber

  override val sessionUnique: ByteArray
    get() {

      // Ensure that the initator and responder keys are hashed in a deterministic order, so they have
      // the same session unique code.
      val encodeKeyBytes: ByteArray = encodeKey
      val decodeKeyBytes: ByteArray = decodeKey
      val encodeKeyHash: Int = encodeKeyBytes.contentHashCode()
      val decodeKeyHash: Int = decodeKeyBytes.contentHashCode()
      val firstKeyBytes = if (encodeKeyHash < decodeKeyHash) encodeKeyBytes else decodeKeyBytes
      val secondKeyBytes = if (firstKeyBytes.contentEquals(encodeKeyBytes)) decodeKeyBytes else encodeKeyBytes

      return EcSha256.hash(
        D2DCryptoOps.d2dSalt + firstKeyBytes + secondKeyBytes
      )
    }

  override fun incrementSequenceNumberForEncoding() {
    sequenceNumberForEncoding += 1
  }

  override fun incrementSequenceNumberForDecoding() {
    sequenceNumberForDecoding += 1
  }

  /**
   * Structure of saved session is:
   * +------------------------------------------------------------------------------------------+
   * |     1 Byte       | 4 Bytes (big endian) | 4 Bytes (big endian) |  32 Bytes  |  32 Bytes  |
   * +------------------------------------------------------------------------------------------+
   * | Protocol Version |   encode seq number  |   decode seq number  | encode key | decode key |
   * +------------------------------------------------------------------------------------------+
   */
  override fun saveSession(): ByteArray? {
    val bytes = Buffer()
    try {
      // Protocol version
      bytes.writeInt(1)

      // Encode sequence number
      bytes.write(signedIntToBytes(sequenceNumberForEncoding))

      // Decode sequence number
      bytes.write(signedIntToBytes(sequenceNumberForDecoding))

      // Encode Key
      bytes.write(encodeKey)

      // Decode Key
      bytes.write(decodeKey)
    } catch (e: IOException) {
      // should not happen
      e.printStackTrace()
      return null
    }
    return bytes.readByteArray()
  }

  companion object {
    const val PROTOCOL_VERSION = 1
  }
}