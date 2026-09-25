package com.carlonzo.ukey2

import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.SHA256
import dev.whyoleg.cryptography.algorithms.SHA512
import okio.Buffer
import okio.ByteString

internal fun sha256(data: ByteArray): ByteArray {
  return CryptographyProvider.Default.get(SHA256).hasher().hashBlocking(data)
}

internal fun sha512(data: ByteArray): ByteArray {
  return CryptographyProvider.Default.get(SHA512).hasher().hashBlocking(data)
}

internal fun toBigEndianTwosComplement(bytes: ByteArray): ByteArray {
  var firstNonZero = 0
  while (firstNonZero < bytes.size - 1 && bytes[firstNonZero] == 0.toByte()) {
    firstNonZero++
  }
  val trimmed = if (firstNonZero > 0) bytes.copyOfRange(firstNonZero, bytes.size) else bytes
  return if ((trimmed[0].toInt() and 0x80) != 0) {
    ByteArray(trimmed.size + 1).also {
      it[0] = 0
      trimmed.copyInto(it, destinationOffset = 1)
    }
  } else {
    trimmed
  }
}

internal fun fromBigEndianTwosComplement(bytes: ByteArray): ByteArray {
  val unsignedBytes = if (bytes.size == 33 && bytes[0] == 0.toByte()) {
    bytes.copyOfRange(1, 33)
  } else {
    bytes
  }
  if (unsignedBytes.size > 32) {
    throw IllegalArgumentException("Coordinate too long: ${bytes.size}")
  }
  return if (unsignedBytes.size < 32) {
    ByteArray(32).also {
      unsignedBytes.copyInto(it, destinationOffset = 32 - unsignedBytes.size)
    }
  } else {
    unsignedBytes
  }
}

internal fun hkdf(inputKeyMaterial: ByteArray, salt: ByteArray, info: ByteArray, length: Int = 32): ByteArray {

  if (length < 0) {
    throw IllegalArgumentException("Length must be positive")
  }
  return hkdfSha256Expand(hkdfSha256Extract(inputKeyMaterial, salt), info, length)
}

private fun hkdfSha256Expand(pseudoRandomKey: ByteArray, info: ByteArray, length: Int): ByteArray {

  // Number of blocks N = ceil(hash length / output length).
  var blocks = length / 32
  if (length % 32 > 0) {
    blocks += 1
  }


  // The counter used to generate the blocks according to the RFC is only one byte long,
  // which puts a limit on the number of blocks possible.
  require(blocks <= 0xFF) { "Maximum HKDF output length exceeded." }
  var outputBlock = ByteString.of(*ByteArray(32))
  val buffer = Buffer()

  for (i in 0 until blocks) {
    buffer.clear()
    if (i > 0) {
      // Previous block
      buffer.write(outputBlock)
    }
    // Arbitrary info
    buffer.write(info)
    // Counter
    buffer.writeByte(i + 1)
    outputBlock = buffer.hmacSha256(ByteString.of(*pseudoRandomKey))
  }
  return outputBlock.substring(0, length).toByteArray()
}

private fun hkdfSha256Extract(inputKeyMaterial: ByteArray, salt: ByteArray): ByteArray {
  return Buffer().write(inputKeyMaterial).hmacSha256(ByteString.of(*salt)).toByteArray()
}

/** MessageDigest.isEqual-style comparison that does not short-circuit on the first mismatch. */
internal fun constantTimeEquals(a: ByteArray?, b: ByteArray?): Boolean {
  if (a == null || b == null) {
    return false
  }
  val lenA = a.size
  val lenB = b.size
  if (lenB == 0) {
    return lenA == 0
  }
  var result = 0
  result = result or (lenA - lenB)
  for (i in 0 until lenA) {
    val indexB = (i - lenB ushr 31) * i
    result = result or (a[i].toInt() xor b[indexB].toInt())
  }
  return result == 0
}

/**
 * Validates that the point (x, y) lies on the NIST P-256 curve.
 *
 * @param x 32-byte unsigned big-endian x coordinate
 * @param y 32-byte unsigned big-endian y coordinate
 * @throws IllegalArgumentException if the point is not on the curve
 */
internal expect fun requireP256PointOnCurve(x: ByteArray, y: ByteArray)