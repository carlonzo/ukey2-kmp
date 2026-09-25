package com.carlonzo.ukey2

// No-op: OpenSSL (Linux) and CryptoKit (Apple) validate that the point lies on
// the curve during public-key decoding, so an explicit check is unnecessary.
// The linuxX64 testPointNotOnCurve* tests confirm this for OpenSSL.
internal actual fun requireP256PointOnCurve(x: ByteArray, y: ByteArray) { }
