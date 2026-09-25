package com.carlonzo.ukey2

import com.carlonzo.ukey2.d2d.D2DCryptoOps
import com.google.security.cryptauth.lib.securegcm.Ukey2ClientFinished
import com.google.security.cryptauth.lib.securegcm.Ukey2ClientInit
import com.google.security.cryptauth.lib.securegcm.Ukey2HandshakeCipher
import com.google.security.cryptauth.lib.securegcm.Ukey2Message
import com.google.security.cryptauth.lib.securegcm.Ukey2ServerInit
import com.google.security.cryptauth.lib.securemessage.EcP256PublicKey
import com.google.security.cryptauth.lib.securemessage.GenericPublicKey
import com.google.security.cryptauth.lib.securemessage.PublicKeyType
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.EC
import dev.whyoleg.cryptography.algorithms.ECDH
import okio.ByteString.Companion.toByteString
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

/**
 * Cross-implementation test vector suite:
 * Asserts that the new dev.whyoleg.cryptography implementation produces
 * byte-for-byte identical output to the original com.carlonzo.ecdsa + com.diglol.crypto implementation
 * across ECDH key agreement, public key wire protobuf encoding/decoding,
 * HKDF key derivations, D2D AES-CBC encryption/decryption, and session unique computation.
 */
class FixedKeyVectorTest {

  @OptIn(ExperimentalStdlibApi::class)
  @Test
  fun testFixedKeyVectors() {
    val ecdh = CryptographyProvider.Default.get(ECDH)

    // Hardcoded Client private key = 1 (SEC 1 RAW format, 32 bytes)
    val clientPrivBytes = "0000000000000000000000000000000000000000000000000000000000000001".hexToByteArray()
    // Hardcoded Server private key = 2
    val serverPrivBytes = "0000000000000000000000000000000000000000000000000000000000000002".hexToByteArray()
    // Hardcoded Server 2 private key = 4 (produces coordinates with MSB >= 0x80)
    val server2PrivBytes = "0000000000000000000000000000000000000000000000000000000000000004".hexToByteArray()

    val clientPriv = ecdh.privateKeyDecoder(EC.Curve.P256)
      .decodeFromByteArrayBlocking(EC.PrivateKey.Format.RAW, clientPrivBytes)
    val serverPriv = ecdh.privateKeyDecoder(EC.Curve.P256)
      .decodeFromByteArrayBlocking(EC.PrivateKey.Format.RAW, serverPrivBytes)
    val server2Priv = ecdh.privateKeyDecoder(EC.Curve.P256)
      .decodeFromByteArrayBlocking(EC.PrivateKey.Format.RAW, server2PrivBytes)

    // Expected public key coordinates (computed by old implementation)
    val expectedClientPubX = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296".hexToByteArray()
    val expectedClientPubY = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5".hexToByteArray()
    val expectedServerPubX = "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978".hexToByteArray()
    val expectedServerPubY = "07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1".hexToByteArray()

    // 1. Verify two's-complement encoding and decoding for standard coordinates (32 bytes)
    assertContentEquals(expectedClientPubX, toBigEndianTwosComplement(expectedClientPubX))
    assertContentEquals(expectedClientPubY, toBigEndianTwosComplement(expectedClientPubY))
    assertContentEquals(expectedClientPubX, fromBigEndianTwosComplement(expectedClientPubX))
    assertContentEquals(expectedClientPubY, fromBigEndianTwosComplement(expectedClientPubY))

    // 2. Verify two's-complement encoding and decoding for coordinates with high bit >= 0x80 (33 bytes)
    val rawCoordWithHighBit = "e2534a3532d08fbba02dde659ee62bd0031fe2db785596ef509302446b030852".hexToByteArray()
    val expected33ByteTwosComplement = "00e2534a3532d08fbba02dde659ee62bd0031fe2db785596ef509302446b030852".hexToByteArray()
    assertContentEquals(expected33ByteTwosComplement, toBigEndianTwosComplement(rawCoordWithHighBit))
    assertContentEquals(rawCoordWithHighBit, fromBigEndianTwosComplement(expected33ByteTwosComplement))

    // 3. Decode Server public key from protobuf GenericPublicKey
    val serverGenericPublicKey = GenericPublicKey(
      type = PublicKeyType.EC_P256,
      ec_p256_public_key = EcP256PublicKey(
        x = expectedServerPubX.toByteString(),
        y = expectedServerPubY.toByteString(),
      )
    )
    val ecKey = requireNotNull(serverGenericPublicKey.ec_p256_public_key)
    val uncompressedServer = ByteArray(65).also {
      it[0] = 0x04
      fromBigEndianTwosComplement(ecKey.x.toByteArray()).copyInto(it, 1)
      fromBigEndianTwosComplement(ecKey.y.toByteArray()).copyInto(it, 33)
    }
    val serverPub = ecdh.publicKeyDecoder(EC.Curve.P256)
      .decodeFromByteArrayBlocking(EC.PublicKey.Format.RAW.Uncompressed, uncompressedServer)

    // Decode Client public key from protobuf GenericPublicKey
    val uncompressedClient = ByteArray(65).also {
      it[0] = 0x04
      expectedClientPubX.copyInto(it, 1)
      expectedClientPubY.copyInto(it, 33)
    }
    val clientPub = ecdh.publicKeyDecoder(EC.Curve.P256)
      .decodeFromByteArrayBlocking(EC.PublicKey.Format.RAW.Uncompressed, uncompressedClient)

    // 4. Compute ECDH shared secret: Client priv=1 with Server pub=2
    val clientSharedSecret = clientPriv.sharedSecretGenerator().generateSharedSecretToByteArrayBlocking(serverPub)
    val serverSharedSecret = serverPriv.sharedSecretGenerator().generateSharedSecretToByteArrayBlocking(clientPub)

    val expectedSharedSecret = "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978".hexToByteArray()
    assertContentEquals(expectedSharedSecret, clientSharedSecret)
    assertContentEquals(expectedSharedSecret, serverSharedSecret)

    // Derived secret key = SHA-256(sharedSecret)
    val expectedDerivedSecret = "23775201799b2234a18e8071e409cec80d42632fe77534180afdc533c9b76f81".hexToByteArray()
    val derivedSecret = sha256(clientSharedSecret)
    assertContentEquals(expectedDerivedSecret, derivedSecret)

    // 5. Test ECDH with Server 2 (priv=4) to verify high-bit coordinates (X >= 0x80)
    val server2PubXTwosComplement = "00e2534a3532d08fbba02dde659ee62bd0031fe2db785596ef509302446b030852".hexToByteArray()
    val server2PubYTwosComplement = "00e0f1575a4c633cc719dfee5fda862d764efc96c3f30ee0055c42c23f184ed8c6".hexToByteArray()
    val uncompressedServer2 = ByteArray(65).also {
      it[0] = 0x04
      fromBigEndianTwosComplement(server2PubXTwosComplement).copyInto(it, 1)
      fromBigEndianTwosComplement(server2PubYTwosComplement).copyInto(it, 33)
    }
    val server2Pub = ecdh.publicKeyDecoder(EC.Curve.P256)
      .decodeFromByteArrayBlocking(EC.PublicKey.Format.RAW.Uncompressed, uncompressedServer2)
    val server2SharedSecret = clientPriv.sharedSecretGenerator().generateSharedSecretToByteArrayBlocking(server2Pub)

    val expectedServer2SharedSecret = "e2534a3532d08fbba02dde659ee62bd0031fe2db785596ef509302446b030852".hexToByteArray()
    assertContentEquals(expectedServer2SharedSecret, server2SharedSecret)
    val expectedServer2DerivedSecret = "4cb8c9027810c86b7e389a4f0ae4cb08e0e45df120a4ea2e8dab48a917d4ec5f".hexToByteArray()
    assertContentEquals(expectedServer2DerivedSecret, sha256(server2SharedSecret))

    // 6. Test Handshake Key Derivations with fixed nonces and messages
    val clientNonce = ByteArray(32) { (it + 1).toByte() }
    val serverNonce = ByteArray(32) { (it + 33).toByte() }

    val clientInitProto = Ukey2ClientInit(
      version = 1,
      random = clientNonce.toByteString(),
      next_protocol = "AES_256_CBC-HMAC_SHA256",
      cipher_commitments = listOf(
        Ukey2ClientInit.CipherCommitment(
          handshake_cipher = Ukey2HandshakeCipher.P256_SHA512,
          commitment = byteArrayOf().toByteString()
        )
      )
    )
    val clientFinishedProto = Ukey2ClientFinished(
      public_key = GenericPublicKey(
        type = PublicKeyType.EC_P256,
        ec_p256_public_key = EcP256PublicKey(
          x = expectedClientPubX.toByteString(),
          y = expectedClientPubY.toByteString(),
        )
      ).encodeByteString()
    )
    val rawMessage3 = Ukey2Message(
      message_type = Ukey2Message.Type.CLIENT_FINISH,
      message_data = clientFinishedProto.encode().toByteString()
    ).encode()

    val commitment = sha512(rawMessage3)
    val clientInitWithCommitment = clientInitProto.copy(
      cipher_commitments = listOf(
        Ukey2ClientInit.CipherCommitment(
          handshake_cipher = Ukey2HandshakeCipher.P256_SHA512,
          commitment = commitment.toByteString()
        )
      )
    )
    val rawMessage1 = Ukey2Message(
      message_type = Ukey2Message.Type.CLIENT_INIT,
      message_data = clientInitWithCommitment.encode().toByteString()
    ).encode()

    val serverInitProto = Ukey2ServerInit(
      version = 1,
      random = serverNonce.toByteString(),
      handshake_cipher = Ukey2HandshakeCipher.P256_SHA512,
      public_key = serverGenericPublicKey.encodeByteString()
    )
    val rawMessage2 = Ukey2Message(
      message_type = Ukey2Message.Type.SERVER_INIT,
      message_data = serverInitProto.encode().toByteString()
    ).encode()

    val handshakeInfo = rawMessage1 + rawMessage2
    val authSalt = "UKEY2 v1 auth".encodeToByteArray()
    val authString = hkdf(derivedSecret, authSalt, handshakeInfo, 32)
    val expectedAuthString = "47e0e327b0e2b2473cd9a294d849d3791259f297303c213f4714873db69634b8".hexToByteArray()
    assertContentEquals(expectedAuthString, authString)

    val nextSalt = "UKEY2 v1 next".encodeToByteArray()
    val nextProtocolKey = hkdf(derivedSecret, nextSalt, handshakeInfo, 32)
    val expectedNextProtocolKey = "9b3e006d6ab55bb58014336447e219724ea1b0b81449b244e4641d8392e6a08f".hexToByteArray()
    assertContentEquals(expectedNextProtocolKey, nextProtocolKey)

    val d2dSalt = sha256("D2D".encodeToByteArray())
    val expectedD2dSalt = "82aa55a0d397f88346ca1cee8d3909b95f13fa7deb1d4ab38376b8256da85510".hexToByteArray()
    assertContentEquals(expectedD2dSalt, d2dSalt)

    val clientKey = hkdf(nextProtocolKey, d2dSalt, "client".encodeToByteArray(), 32)
    val serverKey = hkdf(nextProtocolKey, d2dSalt, "server".encodeToByteArray(), 32)
    val expectedClientKey = "3db592827990460df17d83c45bd26e0367c160a0912368e23d48fa3039a3fb0a".hexToByteArray()
    val expectedServerKey = "ee1270c5a0e5826ff89096f140f727a34b220bde1af6bfe7b4bf2df353342049".hexToByteArray()
    assertContentEquals(expectedClientKey, clientKey)
    assertContentEquals(expectedServerKey, serverKey)

    // 7. Verify D2D AES-256-CBC encryption/decryption and HMAC signing
    val fixedIv = "05060708090a0b0c0d0e0f1011121314".hexToByteArray()
    val plaintext = "Hello Ukey2 Vector Test".encodeToByteArray()
    val encrypted = D2DCryptoOps.encrypt(clientKey, fixedIv, plaintext)
    val expectedEncrypted = "3f5f7331d4870d0718023915722683b01809c17666d95c7e98a51da85df002ef".hexToByteArray()
    assertContentEquals(expectedEncrypted, encrypted)

    val decrypted = D2DCryptoOps.decrypt(clientKey, fixedIv, encrypted)
    assertContentEquals(plaintext, decrypted)

    val signature = D2DCryptoOps.sign(clientKey, plaintext)
    val expectedSignature = "39f63ac940fe45e1f13f520037e9a2825ba246ec0a89b4d34e161331b31d1e0a".hexToByteArray()
    assertContentEquals(expectedSignature, signature)

    // 8. Verify sessionUnique computation
    val encodeKeyBytes = clientKey
    val decodeKeyBytes = serverKey
    val encodeKeyHash = encodeKeyBytes.contentHashCode()
    val decodeKeyHash = decodeKeyBytes.contentHashCode()
    val firstKeyBytes = if (encodeKeyHash < decodeKeyHash) encodeKeyBytes else decodeKeyBytes
    val secondKeyBytes = if (firstKeyBytes.contentEquals(encodeKeyBytes)) decodeKeyBytes else encodeKeyBytes
    val sessionUnique = sha256(d2dSalt + firstKeyBytes + secondKeyBytes)
    val expectedSessionUnique = "a0ea7dbacc4941a75e750d4c443762633fadeb887a9fdfa430a682388af3b115".hexToByteArray()
    assertContentEquals(expectedSessionUnique, sessionUnique)
  }
}
