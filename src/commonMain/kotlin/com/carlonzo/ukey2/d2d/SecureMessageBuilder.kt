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
package com.carlonzo.ukey2.d2d

import com.google.security.cryptauth.lib.securemessage.EncScheme
import com.google.security.cryptauth.lib.securemessage.Header
import com.google.security.cryptauth.lib.securemessage.HeaderAndBodyInternal
import com.google.security.cryptauth.lib.securemessage.SecureMessage
import com.google.security.cryptauth.lib.securemessage.SigScheme
import okio.ByteString
import okio.ByteString.Companion.toByteString
import org.kotlincrypto.random.CryptoRand

internal class SecureMessageBuilder {
  private var publicMetadata: ByteString? = null
  private var decryptionKeyId: ByteString? = null

  fun setPublicMetadata(publicMetadata: ByteArray): SecureMessageBuilder {
    this.publicMetadata = publicMetadata.toByteString()
    return this
  }

  fun setDecryptionKeyId(decryptionKeyId: ByteArray): SecureMessageBuilder {
    this.decryptionKeyId = decryptionKeyId.toByteString()
    return this
  }

  fun buildSignCryptedMessage(
    signingKey: ByteArray, encryptionKey: ByteArray, body: ByteArray
  ): SecureMessage {
    val iv = CryptoRand.Default.nextBytes(ByteArray(D2DCryptoOps.AES_BLOCK_SIZE))
    val header: ByteArray = buildHeader(iv).encode()

    val taggedBody = if (taggedPlaintextRequired(signingKey, encryptionKey)) {
      D2DCryptoOps.digest(header) + body
    } else {
      body
    }

    val encryptedBody: ByteArray = D2DCryptoOps.encrypt(encryptionKey, iv, taggedBody)
    val headerAndBody = serializeHeaderAndBody(header, encryptedBody)
    val sig: ByteArray = D2DCryptoOps.sign(signingKey, headerAndBody)

    return SecureMessage(
      header_and_body = headerAndBody.toByteString(),
      signature = sig.toByteString()
    )
  }

  private fun buildHeader(iv: ByteArray): Header {
    return Header(
      signature_scheme = SigScheme.HMAC_SHA256,
      encryption_scheme = EncScheme.AES_256_CBC,
      decryption_key_id = decryptionKeyId,
      public_metadata = publicMetadata,
      iv = iv.toByteString()
    )
  }

  private fun serializeHeaderAndBody(header: ByteArray, body: ByteArray): ByteArray {
    return HeaderAndBodyInternal(
      header_ = header.toByteString(),
      body = body.toByteString()
    ).encode()
  }

  companion object {
    fun taggedPlaintextRequired(signingKey: ByteArray, encryptionKey: ByteArray): Boolean {
      return !signingKey.contentEquals(encryptionKey)
    }
  }
}
