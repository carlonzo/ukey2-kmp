package com.google.security.cryptauth.lib.securegcm

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

import com.google.security.cryptauth.lib.securegcm.Ukey2Handshake.HandshakeCipher
import kotlin.test.Test


/**
 * Tests the compatibility between the Java and C++ implementations of the UKEY2 protocol. This
 * integration test executes and talks to a compiled binary exposing the C++ implementation (wrapped
 * by [Ukey2ShellCppWrapper]).
 *
 *
 * The C++ implementation is located in //security/cryptauth/lib/securegcm.
 */
class Ukey2CppCompatibilityTest {

  /** Tests full handshake with C++ client and Java server.  */
  @Test
  fun testCppClientJavaServer() {
    val cppUkey2Shell = Ukey2ShellCppWrapper(Ukey2ShellCppWrapper.Mode.INITIATOR, VERIFICATION_STRING_LENGTH)
    cppUkey2Shell.startShell()
    val javaUkey2Handshake = Ukey2Handshake.forResponder(HandshakeCipher.P256_SHA512)

    // ClientInit:
    val clientInit = cppUkey2Shell.readHandshakeMessage()
    javaUkey2Handshake.parseHandshakeMessage(clientInit)

    // ServerInit:
    val serverInit = javaUkey2Handshake.nextHandshakeMessage
    cppUkey2Shell.writeHandshakeMessage(serverInit)

    // ClientFinished:
    val clientFinished = cppUkey2Shell.readHandshakeMessage()
    javaUkey2Handshake.parseHandshakeMessage(clientFinished)

    // Verification String:
    cppUkey2Shell.confirmAuthString(
      javaUkey2Handshake.getVerificationString(VERIFICATION_STRING_LENGTH)
    )
    javaUkey2Handshake.verifyHandshake()

    val result = javaUkey2Handshake.handshakeResult

    assert(result.decodeKey.isNotEmpty())
    assert(result.encodeKey.isNotEmpty())

    cppUkey2Shell.stopShell()
  }

  /** Tests full handshake with C++ server and Java client.  */
  @Test
  fun testCppServerJavaClient() {
    val cppUkey2Shell = Ukey2ShellCppWrapper(Ukey2ShellCppWrapper.Mode.RESPONDER, VERIFICATION_STRING_LENGTH)
    cppUkey2Shell.startShell()
    val javaUkey2Handshake = Ukey2Handshake.forInitiator(HandshakeCipher.P256_SHA512)

    // ClientInit:
    val clientInit = javaUkey2Handshake.nextHandshakeMessage
    cppUkey2Shell.writeHandshakeMessage(clientInit)

    // ServerInit:
    val serverInit = cppUkey2Shell.readHandshakeMessage()
    javaUkey2Handshake.parseHandshakeMessage(serverInit)

    // ClientFinished:
    val clientFinished = javaUkey2Handshake.nextHandshakeMessage
    cppUkey2Shell.writeHandshakeMessage(clientFinished)

    // Verification String:
    cppUkey2Shell.confirmAuthString(
      javaUkey2Handshake.getVerificationString(VERIFICATION_STRING_LENGTH)
    )
    javaUkey2Handshake.verifyHandshake()

    val result = javaUkey2Handshake.handshakeResult

    assert(result.decodeKey.isNotEmpty())
    assert(result.encodeKey.isNotEmpty())

    cppUkey2Shell.stopShell()
  }

  companion object {
    private const val VERIFICATION_STRING_LENGTH = 32
  }
}

