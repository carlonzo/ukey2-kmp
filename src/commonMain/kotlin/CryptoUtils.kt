import okio.Buffer
import okio.ByteString


fun hkdf(inputKeyMaterial: ByteArray, salt: ByteArray, info: ByteArray, length: Int = 32): ByteArray {

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