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

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.*
import java.util.concurrent.ExecutionException
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

/**
 * A wrapper to execute and interact with the //security/cryptauth/lib/securegcm:ukey2_shell binary.
 *
 *
 * This binary is a shell over the C++ implementation of the UKEY2 protocol, so this wrapper is
 * used to test compatibility between the C++ and Java implementations.
 *
 *
 * The ukey2_shell is invoked as follows:
 *
 * <pre>`ukey2_shell --mode=<mode> --verification_string_length=<length>
`</pre> *
 *
 * where `mode={initiator, responder}` and `verification_string_length` is a positive
 * integer.
 */
class Ukey2ShellCppWrapper(private val mode: Mode, private val verificationStringLength: Int) {
  enum class Mode {
    INITIATOR,
    RESPONDER
  }

  private val executorService: ExecutorService = Executors.newSingleThreadExecutor()

  private var shellProcess: Process? = null
  private var secureContextEstablished = false

  /**
   * Begins execution of the ukey2_shell binary.
   *
   * @throws IOException
   */
  @Throws(IOException::class)
  fun startShell() {
    check(shellProcess == null) { "Shell already started." }
    val modeArg = "--mode=" + modeString
    val verificationStringLengthArg = "--verification_string_length=$verificationStringLength"
    val builder = ProcessBuilder(BINARY_PATH, modeArg, verificationStringLengthArg)

    // Merge the shell's stderr with the stderr of the current process.
    builder.redirectError(ProcessBuilder.Redirect.INHERIT)
    shellProcess = builder.start()
  }

  /**
   * Stops execution of the ukey2_shell binary.
   *
   * @throws IOException
   */
  fun stopShell() {
    checkNotNull(shellProcess) { "Shell not started." }
    shellProcess!!.destroy()
  }

  /**
   * @return the handshake message read from the shell.
   * @throws IOException
   */
  @Throws(IOException::class)
  fun readHandshakeMessage(): ByteArray {
    return readFrameWithTimeout()
  }

  /**
   * Sends the handshake message to the shell.
   *
   * @param message
   * @throws IOException
   */
  @Throws(IOException::class)
  fun writeHandshakeMessage(message: ByteArray) {
    writeFrameWithTimeout(message)
  }

  /**
   * Reads the auth string from the shell and compares it with `authString`. If verification
   * succeeds, then write "ok" back as a confirmation.
   *
   * @param authString the auth string to compare to.
   * @throws IOException
   */
  @OptIn(ExperimentalEncodingApi::class)
  @Throws(IOException::class)
  fun confirmAuthString(authString: ByteArray?) {
    val shellAuthString = readFrameWithTimeout()
    if (!Arrays.equals(authString, shellAuthString)) {

      throw IOException(
        java.lang.String.format(
          "Unable to verify auth string: 0x%s != 0x%s",
          authString?.let { Base64.encode(it) },
          shellAuthString.let { Base64.encode(it) },
        )
      )
    }
    writeFrameWithTimeout("ok".toByteArray())
    secureContextEstablished = true
  }

  /**
   * Sends `payload` to be encrypted by the shell. This function can only be called after a
   * handshake is performed and a secure context established.
   *
   * @param payload the data to be encrypted.
   * @return the encrypted message returned by the shell.
   * @throws IOException
   */
  @Throws(IOException::class)
  fun sendEncryptCommand(payload: ByteArray?): ByteArray {
    writeFrameWithTimeout(createExpression("encrypt", payload))
    return readFrameWithTimeout()
  }

  /**
   * Sends `message` to be decrypted by the shell. This function can only be called after a
   * handshake is performed and a secure context established.
   *
   * @param message the data to be decrypted.
   * @return the decrypted payload returned by the shell.
   * @throws IOException
   */
  @Throws(IOException::class)
  fun sendDecryptCommand(message: ByteArray?): ByteArray {
    writeFrameWithTimeout(createExpression("decrypt", message))
    return readFrameWithTimeout()
  }

  /**
   * Requests the session unique value from the shell. This function can only be called after a
   * handshake is performed and a secure context established.
   *
   * @return the session unique value returned by the shell.
   * @throws IOException
   */
  @Throws(IOException::class)
  fun sendSessionUniqueCommand(): ByteArray {
    writeFrameWithTimeout(createExpression("session_unique", null))
    return readFrameWithTimeout()
  }

  /**
   * Reads a frame from the shell's stdout with a timeout.
   *
   * @return The contents of the frame.
   * @throws IOException
   */
  @Throws(IOException::class)
  private fun readFrameWithTimeout(): ByteArray {
    val future = executorService.submit<ByteArray> { readFrame() }
    return try {
      future[IO_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS]
    } catch (e: InterruptedException) {
      throw IOException(e)
    } catch (e: ExecutionException) {
      throw IOException(e)
    } catch (e: TimeoutException) {
      throw IOException(e)
    }
  }

  /**
   * Writes a frame to the shell's stdin with a timeout.
   *
   * @param contents the contents of the frame.
   * @throws IOException
   */
  @Throws(IOException::class)
  private fun writeFrameWithTimeout(contents: ByteArray) {
    val future = executorService.submit {
      try {
        writeFrame(contents)
      } catch (e: IOException) {
        throw RuntimeException(e)
      }
    }
    try {
      future[IO_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS]
    } catch (e: InterruptedException) {
      throw IOException(e)
    } catch (e: ExecutionException) {
      throw IOException(e)
    } catch (e: TimeoutException) {
      throw IOException(e)
    }
  }

  /**
   * Reads a frame from the shell's stdout, which has the format:
   *
   * <pre>`+---------------------+-----------------+
   * | 4-bytes             | |length| bytes  |
   * +---------------------+-----------------+
   * | (unsigned) length   |     contents    |
   * +---------------------+-----------------+
  `</pre> *
   *
   * @return the contents that were read
   * @throws IOException
   */
  @Throws(IOException::class)
  private fun readFrame(): ByteArray {
    checkNotNull(shellProcess) { "Shell not started." }
    val inputStream = shellProcess!!.inputStream
    val lengthBytes = ByteArray(4)
    if (inputStream.read(lengthBytes) != lengthBytes.size) {
      throw IOException("Failed to read length.")
    }
    val length = ByteBuffer.wrap(lengthBytes).order(ByteOrder.BIG_ENDIAN).getInt()
    if (length < 0) {
      throw IOException("Length too large: " + Arrays.toString(lengthBytes))
    }
    val contents = ByteArray(length)
    val bytesRead = inputStream.read(contents)
    if (bytesRead != length) {
      throw IOException("Failed to read entire contents: $bytesRead != $length")
    }
    return contents
  }

  /**
   * Writes a frame to the shell's stdin, which has the format:
   *
   * <pre>`+---------------------+-----------------+
   * | 4-bytes             | |length| bytes  |
   * +---------------------+-----------------+
   * | (unsigned) length   |     contents    |
   * +---------------------+-----------------+
  `</pre> *
   *
   * @param contents the contents to send.
   * @throws IOException
   */
  @Throws(IOException::class)
  private fun writeFrame(contents: ByteArray) {
    checkNotNull(shellProcess) { "Shell not started." }

    // The length is big-endian encoded, network byte order.
    val length = contents.size.toLong()
    val lengthBytes = ByteArray(4)
    lengthBytes[0] = (length shr 32 and 0xFFL).toByte()
    lengthBytes[1] = (length shr 16 and 0xFFL).toByte()
    lengthBytes[2] = (length shr 8 and 0xFFL).toByte()
    lengthBytes[3] = (length shr 0 and 0xFFL).toByte()
    val outputStream = shellProcess!!.outputStream
    outputStream.write(lengthBytes)
    outputStream.write(contents)
    outputStream.flush()
  }

  /**
   * Creates an expression to be processed when a secure connection is established, after the
   * handshake is done.
   *
   * @param command The command to send.
   * @param argument The argument of the command. Can be null.
   * @return the expression that can be sent to the shell.
   * @throws IOException
   */
  @Throws(IOException::class)
  private fun createExpression(command: String, argument: ByteArray?): ByteArray {
    val outputStream = ByteArrayOutputStream()
    outputStream.write(command.toByteArray())
    outputStream.write(" ".toByteArray())
    if (argument != null) {
      outputStream.write(argument)
    }
    return outputStream.toByteArray()
  }

  private val modeString: String
    /** @return the mode string to use in the argument to start the ukey2_shell process.
     */
    get() = when (mode) {
      Mode.INITIATOR -> "initiator"
      Mode.RESPONDER -> "responder"
    }

  companion object {
    // The path the the ukey2_shell binary.
    private const val BINARY_PATH = "<ukey2folder>/bazel-bin/src/main/cpp/ukey2_shell"

    // The time to wait before timing out a read or write operation to the shell.
    // TODO(b/147378611): store a java.time.Duration instead
    private const val IO_TIMEOUT_MILLIS: Long = 5000
  }
}
