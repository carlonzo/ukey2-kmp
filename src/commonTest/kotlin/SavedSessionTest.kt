import com.carlonzo.ukey2.Ukey2Handshake
import com.carlonzo.ukey2.Ukey2Handshake.HandshakeCipher
import com.carlonzo.ukey2.d2d.D2DConnectionContext
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

class SavedSessionTest {

  @Test
  fun saveSessionHasCorrectFormat() {
    val (client, server) = handshake()
    exchange(client, server, "ping")
    exchange(server, client, "pong")

    val saved = assertNotNull(client.saveSession())
    assertEquals(73, saved.size)
    assertEquals(1, saved[0].toInt())
    assertEquals(client.sequenceNumberForEncoding, saved.readBeInt(1))
    assertEquals(client.sequenceNumberForDecoding, saved.readBeInt(5))
    assertContentEquals(client.encodeKey, saved.copyOfRange(9, 41))
    assertContentEquals(client.decodeKey, saved.copyOfRange(41, 73))
  }

  @Test
  fun roundTripPreservesState() {
    val (client, server) = handshake()
    exchange(client, server, "one")
    exchange(client, server, "two")
    exchange(server, client, "three")
    exchange(server, client, "four")

    val saved = assertNotNull(client.saveSession())
    val restored = D2DConnectionContext.fromSavedSession(saved)

    assertContentEquals(client.encodeKey, restored.encodeKey)
    assertContentEquals(client.decodeKey, restored.decodeKey)
    assertEquals(client.sequenceNumberForEncoding, restored.sequenceNumberForEncoding)
    assertEquals(client.sequenceNumberForDecoding, restored.sequenceNumberForDecoding)
    assertContentEquals(client.sessionUnique, restored.sessionUnique)
    assertContentEquals(saved, restored.saveSession())
  }

  @Test
  fun restoredContextsInterop() {
    val (client, server) = handshake()
    exchange(client, server, "warmup-c")
    exchange(server, client, "warmup-s")

    val clientSave = assertNotNull(client.saveSession())
    val serverSave = assertNotNull(server.saveSession())

    val restoredClient = D2DConnectionContext.fromSavedSession(clientSave)
    val restoredServer = D2DConnectionContext.fromSavedSession(serverSave)
    exchange(restoredClient, restoredServer, "rc-rs-1")
    exchange(restoredServer, restoredClient, "rs-rc-1")
    exchange(restoredClient, restoredServer, "rc-rs-2")
    exchange(restoredServer, restoredClient, "rs-rc-2")

    val mixedClient = D2DConnectionContext.fromSavedSession(clientSave)
    exchange(mixedClient, server, "mc-os-1")
    exchange(server, mixedClient, "os-mc-1")
    exchange(mixedClient, server, "mc-os-2")
    exchange(server, mixedClient, "os-mc-2")

    val mixedServer = D2DConnectionContext.fromSavedSession(serverSave)
    exchange(client, mixedServer, "oc-ms-1")
    exchange(mixedServer, client, "ms-oc-1")
    exchange(client, mixedServer, "oc-ms-2")
    exchange(mixedServer, client, "ms-oc-2")
  }

  private fun handshake(): Pair<D2DConnectionContext, D2DConnectionContext> {
    val client = Ukey2Handshake.forInitiator(HandshakeCipher.P256_SHA512)
    val server = Ukey2Handshake.forResponder(HandshakeCipher.P256_SHA512)
    server.parseHandshakeMessage(client.getNextHandshakeMessage())
    client.parseHandshakeMessage(server.getNextHandshakeMessage())
    server.parseHandshakeMessage(client.getNextHandshakeMessage())
    client.getVerificationString(32)
    server.getVerificationString(32)
    client.verifyHandshake()
    server.verifyHandshake()
    return client.toConnectionContext() to server.toConnectionContext()
  }

  private fun exchange(from: D2DConnectionContext, to: D2DConnectionContext, payload: String) {
    val bytes = payload.encodeToByteArray()
    assertContentEquals(bytes, to.decodeMessageFromPeer(from.encodeMessageToPeer(bytes)))
  }

  private fun ByteArray.readBeInt(offset: Int): Int {
    return ((this[offset].toInt() and 0xff) shl 24) or
      ((this[offset + 1].toInt() and 0xff) shl 16) or
      ((this[offset + 2].toInt() and 0xff) shl 8) or
      (this[offset + 3].toInt() and 0xff)
  }
}
