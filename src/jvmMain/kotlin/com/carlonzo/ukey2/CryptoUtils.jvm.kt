package com.carlonzo.ukey2

import java.math.BigInteger

// NIST P-256 curve parameters
private val P = BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16)
private val B = BigInteger("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16)
private val A = P - BigInteger.valueOf(3) // a = -3 (mod p)

internal actual fun requireP256PointOnCurve(x: ByteArray, y: ByteArray) {
    require(x.size == 32 && y.size == 32) { "Coordinates must be exactly 32 bytes" }

    // Interpret as unsigned big-endian integers
    val xBig = BigInteger(1, x)
    val yBig = BigInteger(1, y)

    // Check 0 <= x < p and 0 <= y < p
    require(xBig < P) { "x coordinate is not in [0, p)" }
    require(yBig < P) { "y coordinate is not in [0, p)" }

    // Verify y² ≡ x³ + ax + b (mod p)  where a = -3
    val lhs = yBig.modPow(BigInteger.TWO, P)
    val rhs = xBig.modPow(BigInteger.valueOf(3), P)
        .add(A.multiply(xBig))
        .add(B)
        .mod(P)

    require(lhs == rhs) { "Point (x, y) is not on the P-256 curve" }
}
