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

import com.google.security.cryptauth.lib.securemessage.Header
import com.google.security.cryptauth.lib.securemessage.HeaderAndBodyInternal
import com.google.security.cryptauth.lib.securemessage.SecureMessage
import okio.ByteString
import okio.ByteString.Companion.toByteString
import org.kotlincrypto.SecureRandom

/**
 * Builder for [SecureMessage] protos. Can be used to create either signed messages,
 * or "signcrypted" (encrypted then signed) messages that include a tight binding between the
 * ciphertext portion and a verification key identity.
 *
 * @see SecureMessageParser
 */
internal class SecureMessageBuilder {
  private var publicMetadata: ByteString? = null
  private var verificationKeyId: ByteString? = null
  private var decryptionKeyId: ByteString? = null

  /**
   * This data is never sent inside the protobufs, so the builder just saves it as a byte[].
   */
  private var associatedData: ByteArray? = null
  private var rng: SecureRandom = SecureRandom()

  /**
   * Resets this [SecureMessageBuilder] instance to a blank configuration (and returns it).
   */
  fun reset(): SecureMessageBuilder {
    publicMetadata = null
    verificationKeyId = null
    decryptionKeyId = null
    associatedData = null
    return this
  }

  /**
   * Optional metadata to be sent along with the header information in this [SecureMessage].
   *
   *
   * Note that this value will be sent *UNENCRYPTED* in all cases.
   *
   *
   * Can be used with either cleartext or signcrypted messages, but is intended primarily for use
   * with signcrypted messages.
   */
  fun setPublicMetadata(publicMetadata: ByteArray): SecureMessageBuilder {
    this.publicMetadata = publicMetadata.toByteString()
    return this
  }

  /**
   * The recipient of the [SecureMessage] should be able to uniquely determine the correct
   * verification key, given only this value.
   *
   *
   * Can be used with either cleartext or signcrypted messages. Setting this is mandatory for
   * signcrypted messages using a public key [SigType], in order to bind the encrypted
   * body to a specific verification key.
   *
   *
   * Note that this value is sent *UNENCRYPTED* in all cases.
   */
  fun setVerificationKeyId(verificationKeyId: ByteArray): SecureMessageBuilder {
    this.verificationKeyId = verificationKeyId.toByteString()
    return this
  }

  /**
   * To be used only with [.buildSignCryptedMessage],
   * this value is sent *UNENCRYPTED* as part of the header. It should be used by the
   * recipient of the [SecureMessage] to identify an appropriate key to use for decrypting
   * the message body.
   */
  fun setDecryptionKeyId(decryptionKeyId: ByteArray): SecureMessageBuilder {
    this.decryptionKeyId = decryptionKeyId.toByteString()
    return this
  }

  /**
   * Additional data is "associated" with this [SecureMessage], but will not be sent as
   * part of it. The recipient of the [SecureMessage] will need to provide the same data in
   * order to verify the message body. Setting this to `null` is equivalent to using an
   * empty array (unlike the behavior of `VerificationKeyId` and `DecryptionKeyId`).
   *
   *
   * Note that the *size* (length in bytes) of the associated data will be sent in the
   * *UNENCRYPTED* header information, even if you are using encryption.
   *
   *
   * If you will be using [.buildSignedCleartextMessage], then anyone
   * observing the [SecureMessage] may be able to infer this associated data via an
   * "offline dictionary attack". That is, when no encryption is used, you will not be hiding this
   * data simply because it is not being sent over the wire.
   */
  fun setAssociatedData(associatedData: ByteArray?): SecureMessageBuilder {
    this.associatedData = associatedData
    return this
  }

  /**
   * Generates a signed [SecureMessage] with the payload `body` left
   * *UNENCRYPTED*.
   *
   *
   * Note that if you have used [.setAssociatedData], the associated data will
   * be subject to offline dictionary attacks if you use a public key [SigType].
   *
   *
   * Doesn't currently support symmetric keys stored in a TPM (since we access the raw key).
   *
   * @see SecureMessageParser.parseSignedCleartextMessage
   */
  fun buildSignedCleartextMessage(signingKey: ByteArray, sigType: D2DCryptoOps.SigType, body: ByteArray): SecureMessage {

    if (decryptionKeyId != null) {
      throw IllegalStateException("Cannot set decryptionKeyId for a cleartext message")
    }
    val headerAndBody = serializeHeaderAndBody(
      buildHeader(sigType, D2DCryptoOps.EncType.NONE, null).encode(), body
    )
    return createSignedResult(signingKey, sigType, headerAndBody, associatedData)
  }

  /**
   * Generates a signed and encrypted [SecureMessage]. If the signature type requires a public
   * key, such as with ECDSA_P256_SHA256, then the caller *must* set a verification id using
   * the [.setVerificationKeyId] method. The verification key id will be bound to the
   * encrypted `body`, preventing attacks that involve stripping the signature and then
   * re-signing the encrypted `body` as if it was originally sent by the attacker.
   *
   *
   *
   * It is safe to re-use one [javax.crypto.SecretKey] as both `signingKey` and
   * `encryptionKey`, even if that key is also used for
   * [.buildSignedCleartextMessage]. In fact, the resulting output
   * encoding will be more compact when the same symmetric key is used for both.
   *
   *
   *
   * Note that PublicMetadata and other header fields are left *UNENCRYPTED*.
   *
   *
   *
   * Doesn't currently support symmetric keys stored in a TPM (since we access the raw key).
   *
   * @param encType *must not* be set to [EncType.NONE]
   * @see SecureMessageParser.parseSignCryptedMessage
   */
  fun buildSignCryptedMessage(
    signingKey: ByteArray, sigType: D2DCryptoOps.SigType, encryptionKey: ByteArray, encType: D2DCryptoOps.EncType, body: ByteArray
  ): SecureMessage {

    if (encType === D2DCryptoOps.EncType.NONE) {
      throw IllegalArgumentException("$encType not supported for encrypted messages")
    }

    if (sigType.publicKeyScheme && verificationKeyId == null) {
      throw IllegalStateException("Must set a verificationKeyId when using public key signature with encryption")
    }

    val iv = rng.nextBytesOf(encType.blockSize)
    val header: ByteArray = buildHeader(sigType, encType, iv).encode()

    // We may or may not need an extra tag in front of the plaintext body
    val taggedBody: ByteArray
    // We will only sign the associated data when we don't tag the plaintext body
    val associatedDataToBeSigned: ByteArray?
    if (taggedPlaintextRequired(signingKey, sigType, encryptionKey)) {
      // Place a "tag" in front of the the plaintext message containing a digest of the header
      taggedBody = D2DCryptoOps.concat( // Digest the header + any associated data, yielding a tag to be encrypted with the body.
        D2DCryptoOps.digest(D2DCryptoOps.concat(header, associatedData)),
        body
      )
      associatedDataToBeSigned = null // We already handled any associatedData via the tag
    } else {
      taggedBody = body
      associatedDataToBeSigned = associatedData
    }

    // Compute the encrypted body, which binds the tag to the message inside the ciphertext
    val encryptedBody: ByteArray = D2DCryptoOps.encrypt(encryptionKey, encType, iv, taggedBody)
    val headerAndBody = serializeHeaderAndBody(header, encryptedBody)
    return createSignedResult(signingKey, sigType, headerAndBody, associatedDataToBeSigned)
  }

  /**
   * @param iv IV or `null` if IV to be left unset in the Header
   */
  private fun buildHeader(
    sigType: D2DCryptoOps.SigType,
    encType: D2DCryptoOps.EncType,
    iv: ByteArray?
  ): Header {
    return Header(
      signature_scheme = sigType.sigType,
      encryption_scheme = encType.encScheme,
      verification_key_id = verificationKeyId,
      decryption_key_id = decryptionKeyId,
      public_metadata = publicMetadata,
      associated_data_length = associatedData?.size,
      iv = iv?.toByteString()
    )
  }

  /**
   * @param header a serialized representation of a [Header]
   * @param body arbitrary payload data
   * @return a serialized representation of a [SecureMessageProto.HeaderAndBody]
   */
  private fun serializeHeaderAndBody(header: ByteArray, body: ByteArray): ByteArray {
    return HeaderAndBodyInternal(
      header_ = header.toByteString(),
      body = body.toByteString()
    ).encode()
  }

  private fun createSignedResult(
    signingKey: ByteArray, sigType: D2DCryptoOps.SigType, headerAndBody: ByteArray, associatedData: ByteArray?
  ): SecureMessage {
    val sig: ByteArray = D2DCryptoOps.sign(sigType, signingKey, D2DCryptoOps.concat(headerAndBody, associatedData))

    return SecureMessage(
      header_and_body = headerAndBody.toByteString(),
      signature = sig.toByteString()
    )
  }

  companion object {
    /**
     * Indicates whether a "tag" is needed next to the plaintext body inside the ciphertext, to
     * prevent the same ciphertext from being reused with someone else's signature on it.
     */
    fun taggedPlaintextRequired(signingKey: ByteArray, sigType: D2DCryptoOps.SigType, encryptionKey: ByteArray): Boolean {
      // We need a tag if different keys are being used to "sign" vs. encrypt
      return (sigType.publicKeyScheme || !signingKey.contentEquals(encryptionKey))
    }
  }
}
