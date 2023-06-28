package com.carlonzo.ukey2.d2d

import com.carterharrison.ecdsa.hash.EcSha256
import com.google.security.cryptauth.lib.securegcm.GcmMetadata
import com.google.security.cryptauth.lib.securemessage.EncScheme
import com.google.security.cryptauth.lib.securemessage.Header
import com.google.security.cryptauth.lib.securemessage.HeaderAndBody
import com.google.security.cryptauth.lib.securemessage.HeaderAndBodyInternal
import com.google.security.cryptauth.lib.securemessage.SecureMessage
import com.google.security.cryptauth.lib.securemessage.SigScheme
import diglol.crypto.AesCbc
import diglol.crypto.Cipher
import com.carlonzo.ukey2.hkdf
import kotlinx.coroutines.runBlocking
import okio.Buffer
import okio.ByteString.Companion.toByteString

internal object D2DCryptoOps {

  internal val d2dSalt = EcSha256.hash("D2D".encodeToByteArray())
  private val derivationSalt = EcSha256.hash("SecureMessage".encodeToByteArray())

  /**
   * Truncated hash output length, in bytes.
   */
  private const val DIGEST_LENGTH = 20

  /**
   * Enum of supported signature types, with additional mappings to indicate the name of the
   * underlying JCA algorithm used to create the signature.
   * @see [
   * Java Cryptography Architecture, Standard Algorithm Name Documentation](http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html)
   */
  enum class SigType(val sigType: SigScheme, val jcaName: String, val publicKeyScheme: Boolean) {
    HMAC_SHA256(SigScheme.HMAC_SHA256, "HmacSHA256", false),
    ECDSA_P256_SHA256(SigScheme.ECDSA_P256_SHA256, "SHA256withECDSA", true),
    RSA2048_SHA256(SigScheme.RSA2048_SHA256, "SHA256withRSA", true);

    companion object {
      fun valueOf(sigScheme: SigScheme): SigType {
        for (value in SigType.values()) {
          if (value.sigType == sigScheme) {
            return value
          }
        }
        throw IllegalArgumentException("Unsupported SigType: $sigScheme")
      }
    }
  }


  /**
   * Enum of supported encryption types, with additional mappings to indicate the name of the
   * underlying JCA algorithm used to perform the encryption.
   * @see [
   * Java Cryptography Architecture, Standard Algorithm Name Documentation](http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html)
   */
  enum class EncType(val encScheme: EncScheme, val jcaName: String, val blockSize: Int) {
    NONE(EncScheme.NONE, "InvalidDoNotUseForJCA", 0),
    AES_256_CBC(EncScheme.AES_256_CBC, "AES/CBC/PKCS5Padding", 16);

    companion object {
      fun valueOf(encScheme: EncScheme): EncType {
        for (value in EncType.values()) {
          if (value.encScheme == encScheme) {
            return value
          }
        }
        throw IllegalArgumentException("Unsupported EncType: $encScheme")
      }
    }
  }


  /**
   * Used by a device to send a secure [Payload] to another device.
   *
   * @param responderHello is an optional public value to attach in the header of
   * the [SecureMessage] (in the DecryptionKeyId).
   */
  fun signcryptPayload(
      payload: Payload, decryptKey: ByteArray, responderHello: ByteArray? = null
  ): ByteArray {

    val secureMessageBuilder: SecureMessageBuilder = SecureMessageBuilder()
      .setPublicMetadata(
        GcmMetadata(
          type = payload.payloadType.type,
          version = SecureGcmConstants.SECURE_GCM_VERSION,
        ).encode()

      )
    if (responderHello != null) {
      secureMessageBuilder.setDecryptionKeyId(responderHello)
    }
    return secureMessageBuilder.buildSignCryptedMessage(
      decryptKey,
        SigType.HMAC_SHA256,
      decryptKey,
        EncType.AES_256_CBC,
      payload.message
    ).encode()

  }

  /**
   * Used by a device to recover a secure [Payload] sent by another device.
   */
  fun verifydecryptPayload(
    signcryptedMessage: ByteArray, masterKey: ByteArray
  ): Payload {

    val secmsg: SecureMessage = SecureMessage.ADAPTER.decode(signcryptedMessage)
    val parsed: HeaderAndBody = parseSignCryptedMessage(
      secmsg,
      masterKey,
      SigType.HMAC_SHA256,
      masterKey,
      EncType.AES_256_CBC
    )
    if (parsed.header_.public_metadata == null) {
      throw IllegalStateException("missing metadata")
    }
    val metadata: GcmMetadata = GcmMetadata.ADAPTER.decode(parsed.header_.public_metadata)
    if (metadata.version!! > SecureGcmConstants.SECURE_GCM_VERSION) {
      throw IllegalStateException("Unsupported protocol version")
    }

    return Payload(PayloadType.valueOf(metadata.type), parsed.body.toByteArray())
  }

  /**
   * @return the concatenation of `a` and `b`, treating `null` as the empty array.
   */
  fun concat(a: ByteArray?, b: ByteArray?): ByteArray {
    if (a == null && b == null) {
      return byteArrayOf()
    }

    return if (a == null) {
      b!!
    } else if (b == null) {
      a
    } else a + b
  }

  /**
   * Computes a collision-resistant hash of [.DIGEST_LENGTH] bytes
   * (using a truncated SHA-256 output).
   */
  fun digest(data: ByteArray): ByteArray {
    return EcSha256.hash(data).take(DIGEST_LENGTH).toByteArray()
  }

  fun encrypt(encryptionKey: ByteArray, encType: EncType, iv: ByteArray, plaintext: ByteArray): ByteArray {
    if (encType === EncType.NONE) {
      throw IllegalArgumentException("Cannot use NONE type here")
    }

    val derivedKey = deriveAes256KeyFor(encryptionKey, getPurpose(encType))

    val encrypter: Cipher = when (encType) {
      EncType.AES_256_CBC -> AesCbc(derivedKey, iv)
      else -> throw IllegalArgumentException("Unsupported encryption type: $encType")
    }

    return runBlocking {
      val result = encrypter.encrypt(plaintext)
      // TODO the library prefix the iv. removing it
      result.copyOfRange(iv.size, result.size)
    }
  }

  /**
   * A key derivation function specific to this library, which accepts a `masterKey` and an
   * arbitrary `purpose` describing the intended application of the derived sub-key,
   * and produces a derived AES-256 key safe to use as if it were independent of any other
   * derived key which used a different `purpose`.
   *
   * @param masterKey any key suitable for use with HmacSHA256
   * @param purpose a UTF-8 encoded string describing the intended purpose of derived key
   * @return a derived SecretKey suitable for use with AES-256
   * @throws InvalidKeyException if the encoded form of `masterKey` cannot be accessed
   */
  private fun deriveAes256KeyFor(masterKey: ByteArray, purpose: String): ByteArray {
    return hkdf(masterKey, derivationSalt, purpose.encodeToByteArray())
  }

  private fun getPurpose(sigType: SigType): String {
    return "SIG:" + sigType.sigType.value
  }

  private fun getPurpose(encType: EncType): String {
    return "ENC:" + encType.encScheme.value
  }


  /**
   * Parses a [SecureMessage] containing an encrypted payload body, extracting a decryption of
   * the payload body and verifying the signature.
   *
   * @param associatedData optional associated data bound to the signature (but not in the message)
   * @return the parsed [HeaderAndBody] pair (which is fully verified and decrypted)
   * @throws SignatureException if signature verification fails
   * @see SecureMessageBuilder.buildSignCryptedMessage
   */
  private fun parseSignCryptedMessage(
      secmsg: SecureMessage,
      verificationKey: ByteArray,
      sigType: SigType,
      decryptionKey: ByteArray,
      encType: EncType
  ): HeaderAndBody {

    if (encType === EncType.NONE) {
      throw IllegalStateException("Not a signcrypted message")
    }
    val tagRequired = SecureMessageBuilder.taggedPlaintextRequired(verificationKey, sigType, decryptionKey)
    val headerAndEncryptedBody: HeaderAndBody = verifyHeaderAndBody(
      secmsg,
      verificationKey,
      sigType,
      encType,
    )

    val header: Header = headerAndEncryptedBody.header_
    if (header.iv == null) {
      throw IllegalStateException("Missing IV")
    }

    val rawDecryptedBody: ByteArray =
      decrypt(
        decryptionKey, encType, header.iv.toByteArray(),
        headerAndEncryptedBody.body.toByteArray()
      )

    if (!tagRequired) {
      // No tag expected, so we're all done
      return HeaderAndBody(
        header_ = header,
        body = rawDecryptedBody.toByteString()
      )
    }

    // Verify the tag that binds the ciphertext to the header, and remove it
    val headerBytes: ByteArray = HeaderAndBodyInternal.ADAPTER.decode(secmsg.header_and_body)
      .header_.toByteArray()

    var verifiedBinding = false
    val expectedTag: ByteArray = digest(headerBytes)
    if (rawDecryptedBody.size >= DIGEST_LENGTH) {
      val actualTag: ByteArray = rawDecryptedBody.copyOfRange(0, DIGEST_LENGTH)
      if (constantTimeArrayEquals(actualTag, expectedTag)) {
        verifiedBinding = true
      }
    }
    if (!verifiedBinding) {
      throw IllegalStateException("Tag verification failed")
    }

    val bodyLen = rawDecryptedBody.size - DIGEST_LENGTH
    return headerAndEncryptedBody.copy(
      body = rawDecryptedBody.copyOfRange(DIGEST_LENGTH, bodyLen).toByteString()
    )
  }

  private fun verifyHeaderAndBody(
      secmsg: SecureMessage,
      verificationKey: ByteArray,
      sigType: SigType,
      encType: EncType,
  ): HeaderAndBody {

    val signature = secmsg.signature.toByteArray()
    val data: ByteArray = secmsg.header_and_body.toByteArray()
    val signedData = data

    // Try not to leak the specific reason for verification failures, due to security concerns.
    var verified: Boolean = verify(verificationKey, sigType, signature, signedData)
    val result = HeaderAndBody.ADAPTER.decode(secmsg.header_and_body)

    verified = verified && (result.header_.signature_scheme == sigType.sigType)
    verified = verified && (result.header_.encryption_scheme == encType.encScheme)
    // Check that either a decryption operation is expected, or no DecryptionKeyId is set.
    verified = verified && (encType !== EncType.NONE || result.header_.decryption_key_id == null)
    // If encryption was used, check that either we are not using a public key signature or a
    // VerificationKeyId was set (as is required for public key based signature + encryption).
    verified = verified && (encType === EncType.NONE || !sigType.publicKeyScheme ||
        result.header_.verification_key_id != null)
    verified = verified && (result.header_.associated_data_length == null)

    if (verified) {
      return result
    } else {
      throw IllegalStateException("Header verification failed")
    }
  }

  /**
   * Verifies the `signature` on `data` using the algorithm specified by
   * `sigType` with `verificationKey`.
   *
   * @return true if the signature is verified
   */
  fun verify(verificationKey: ByteArray, sigType: SigType, signature: ByteArray, data: ByteArray): Boolean {

    return when (sigType) {
      SigType.HMAC_SHA256 -> {
        val derivedKey = deriveAes256KeyFor(verificationKey, getPurpose(sigType))
        val result = Buffer().write(data).hmacSha256(derivedKey.toByteString()).toByteArray()

        constantTimeArrayEquals(result, signature)
      }

      SigType.ECDSA_P256_SHA256 -> TODO()
      SigType.RSA2048_SHA256 -> TODO()
    }
  }

  /**
   * Signs {@code data} using the algorithm specified by {@code sigType} with {@code signingKey}.
   *
   * @return raw signature
   */
  fun sign(sigType: SigType, signingKey: ByteArray, data: ByteArray): ByteArray {

    return when (sigType) {
      SigType.HMAC_SHA256 -> {
        val derivedKey = deriveAes256KeyFor(signingKey, getPurpose(sigType))
        Buffer().write(data).hmacSha256(derivedKey.toByteString()).toByteArray()
      }

      SigType.ECDSA_P256_SHA256 -> TODO()
      SigType.RSA2048_SHA256 -> TODO()
    }
  }

  /**
   * Decrypts `ciphertext` using the algorithm specified in `encType`, with the
   * specified `iv` and `decryptionKey`.
   *
   * @return the plaintext (decrypted) data
   * @throws NoSuchAlgorithmException if the security provider is inadequate for `encType`
   * @throws InvalidKeyException if `decryptionKey` is incompatible with `encType`
   * @throws InvalidAlgorithmParameterException if `encType` exceeds legal cryptographic
   * strength limits in this jurisdiction
   * @throws IllegalBlockSizeException if `ciphertext` contains an illegal block
   * @throws BadPaddingException if `ciphertext` contains an illegal padding
   */

  fun decrypt(decryptionKey: ByteArray, encType: EncType, iv: ByteArray, ciphertext: ByteArray): ByteArray {

    if (encType === EncType.NONE) {
      throw IllegalStateException("Cannot use NONE type here")
    }

    val derivedKey = deriveAes256KeyFor(decryptionKey, getPurpose(encType))

    val decrypter: Cipher = when (encType) {
      EncType.AES_256_CBC -> AesCbc(derivedKey, iv)
      else -> throw IllegalArgumentException("Unsupported encryption type: $encType")
    }

    return runBlocking {
      // TODO the library expects the cipher to be prefixed with iv. removing it
      val plain = decrypter.decrypt(iv + ciphertext)
      plain
    }
  }

  /**
   * Returns `true` if the two arrays are equal to one another.
   * When the two arrays differ in length, trivially returns `false`.
   * When the two arrays are equal in length, does a constant-time comparison
   * of the two, i.e. does not abort the comparison when the first differing
   * element is found.
   *
   *
   * NOTE: This is a copy of `java/com/google/math/crypto/ConstantTime#arrayEquals`.
   *
   * @param a An array to compare
   * @param b Another array to compare
   * @return `true` if these arrays are both null or if they have equal
   * length and equal bytes in all elements
   */
  private fun constantTimeArrayEquals(a: ByteArray?, b: ByteArray?): Boolean {
    if (a == null || b == null) {
      return a === b
    }
    if (a.size != b.size) {
      return false
    }
    var result: Byte = 0
    for (i in b.indices) {
      result = (result.toInt() or (a[i].toInt() xor b[i].toInt())).toByte()
    }
    return result.toInt() == 0
  }

}