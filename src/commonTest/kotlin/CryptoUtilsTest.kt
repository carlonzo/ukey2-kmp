import kotlin.test.Test
import kotlin.test.assertContentEquals

class CryptoUtilsTest {


  @Test
  fun testHkdf() {
    val input = "e61f1b1746614767abd1c93bbbfddda3b5f81d73c7f33376a32ca66f604ae01f".decodeHex()
    val salt = "a91c63c074326f4cda6f1f86dc944c50".decodeHex()
    val info = "84f3b21e2029249f4a530f7573c557a7".decodeHex()

    val result = hkdf(input, salt, info, 32)

//  Calculated using implementation in https://github.com/google/ukey2/blob/master/src/main/java/com/google/security/cryptauth/lib/securemessage/CryptoOps.java
    val expected = "8270d7f00c818bf6ba6c6d29df2de89643e2d2d16d6055a44650edc6ae1f5952".decodeHex()

    assertContentEquals(expected, result)
  }

  private fun String.decodeHex(): ByteArray {
    check(length % 2 == 0) { "Must have an even length" }

    return chunked(2)
      .map { it.toInt(16).toByte() }
      .toByteArray()
  }
}