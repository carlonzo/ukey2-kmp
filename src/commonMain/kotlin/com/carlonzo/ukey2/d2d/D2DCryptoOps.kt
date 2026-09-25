package com.carlonzo.ukey2.d2d

import com.carlonzo.ukey2.constantTimeEquals
import com.carlonzo.ukey2.hkdf
import com.carlonzo.ukey2.sha256
import com.google.security.cryptauth.lib.securegcm.GcmMetadata
import com.google.security.cryptauth.lib.securemessage.EncScheme
import com.google.security.cryptauth.lib.securemessage.Header
import com.google.security.cryptauth.lib.securemessage.HeaderAndBody
import com.google.security.cryptauth.lib.securemessage.HeaderAndBodyInternal
import com.google.security.cryptauth.lib.securemessage.SecureMessage
import com.google.security.cryptauth.lib.securemessage.SigScheme
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.DelicateCryptographyApi
import dev.whyoleg.cryptography.algorithms.AES
import okio.Buffer
import okio.ByteString.Companion.toByteString

@OptIn(DelicateCryptographyApi::class)
internal object D2DCryptoOps {

  internal val d2dSalt by lazy { sha256("D2D".encodeToByteArray()) }
  private val derivationSalt by lazy { sha256("SecureMessage".encodeToByteArray()) }
  private const val DIGEST_LENGTH = 20
  private const val SECURE_GCM_VERSION = 1
  internal const val AES_BLOCK_SIZE = 16
  private val SIG_PURPOSE = "SIG:${SigScheme.HMAC_SHA256.value}"
  private val ENC_PURPOSE = "ENC:${EncScheme.AES_256_CBC.value}"

  fun signcryptPayload(
    payload: Payload, decryptKey: ByteArray, responderHello: ByteArray? = null
  ): ByteArray {
    val secureMessageBuilder = SecureMessageBuilder()
      .setPublicMetadata(
        GcmMetadata(
          type = payload.payloadType.type,
          version = SECURE_GCM_VERSION,
        ).encode()
      )
    if (responderHello != null) {
      secureMessageBuilder.setDecryptionKeyId(responderHello)
    }
    return secureMessageBuilder.buildSignCryptedMessage(
      decryptKey,
      decryptKey,
      payload.message
    ).encode()
  }

  fun verifydecryptPayload(
    signcryptedMessage: ByteArray, masterKey: ByteArray
  ): Payload {
    val secmsg: SecureMessage = SecureMessage.ADAPTER.decode(signcryptedMessage)
    val parsed: HeaderAndBody = parseSignCryptedMessage(secmsg, masterKey, masterKey)
    if (parsed.header_.public_metadata == null) {
      throw IllegalStateException("missing metadata")
    }
    val metadata: GcmMetadata = GcmMetadata.ADAPTER.decode(parsed.header_.public_metadata)
    if (metadata.version!! > SECURE_GCM_VERSION) {
      throw IllegalStateException("Unsupported protocol version")
    }

    return Payload(PayloadType.valueOf(metadata.type), parsed.body.toByteArray())
  }

  fun digest(data: ByteArray): ByteArray {
    return sha256(data).take(DIGEST_LENGTH).toByteArray()
  }

  fun encrypt(encryptionKey: ByteArray, iv: ByteArray, plaintext: ByteArray): ByteArray {
    val derivedKey = deriveAes256KeyFor(encryptionKey, ENC_PURPOSE)
    val aesCbc = CryptographyProvider.Default.get(AES.CBC)
    val key = aesCbc.keyDecoder().decodeFromByteArrayBlocking(AES.Key.Format.RAW, derivedKey)
    return key.cipher().encryptWithIvBlocking(iv, plaintext)
  }

  fun decrypt(decryptionKey: ByteArray, iv: ByteArray, ciphertext: ByteArray): ByteArray {
    val derivedKey = deriveAes256KeyFor(decryptionKey, ENC_PURPOSE)
    val aesCbc = CryptographyProvider.Default.get(AES.CBC)
    val key = aesCbc.keyDecoder().decodeFromByteArrayBlocking(AES.Key.Format.RAW, derivedKey)
    return key.cipher().decryptWithIvBlocking(iv, ciphertext)
  }

  fun sign(signingKey: ByteArray, data: ByteArray): ByteArray {
    val derivedKey = deriveAes256KeyFor(signingKey, SIG_PURPOSE)
    return Buffer().write(data).hmacSha256(derivedKey.toByteString()).toByteArray()
  }

  fun verify(verificationKey: ByteArray, signature: ByteArray, data: ByteArray): Boolean {
    return constantTimeEquals(sign(verificationKey, data), signature)
  }

  private fun deriveAes256KeyFor(masterKey: ByteArray, purpose: String): ByteArray {
    return hkdf(masterKey, derivationSalt, purpose.encodeToByteArray())
  }

  private fun parseSignCryptedMessage(
    secmsg: SecureMessage,
    verificationKey: ByteArray,
    decryptionKey: ByteArray,
  ): HeaderAndBody {
    val tagRequired = SecureMessageBuilder.taggedPlaintextRequired(verificationKey, decryptionKey)
    val headerAndEncryptedBody: HeaderAndBody = verifyHeaderAndBody(secmsg, verificationKey)

    val header: Header = headerAndEncryptedBody.header_
    if (header.iv == null) {
      throw IllegalStateException("Missing IV")
    }

    val rawDecryptedBody: ByteArray =
      decrypt(decryptionKey, header.iv.toByteArray(), headerAndEncryptedBody.body.toByteArray())

    if (!tagRequired) {
      return HeaderAndBody(
        header_ = header,
        body = rawDecryptedBody.toByteString()
      )
    }

    val headerBytes: ByteArray = HeaderAndBodyInternal.ADAPTER.decode(secmsg.header_and_body)
      .header_.toByteArray()

    val expectedTag: ByteArray = digest(headerBytes)
    val verifiedBinding = rawDecryptedBody.size >= DIGEST_LENGTH &&
      constantTimeEquals(rawDecryptedBody.copyOfRange(0, DIGEST_LENGTH), expectedTag)
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
  ): HeaderAndBody {
    val signature = secmsg.signature.toByteArray()
    val data: ByteArray = secmsg.header_and_body.toByteArray()

    var verified: Boolean = verify(verificationKey, signature, data)
    val result = HeaderAndBody.ADAPTER.decode(secmsg.header_and_body)

    verified = verified && (result.header_.signature_scheme == SigScheme.HMAC_SHA256)
    verified = verified && (result.header_.encryption_scheme == EncScheme.AES_256_CBC)
    verified = verified && (result.header_.associated_data_length == null)

    if (verified) {
      return result
    } else {
      throw IllegalStateException("Header verification failed")
    }
  }
}
