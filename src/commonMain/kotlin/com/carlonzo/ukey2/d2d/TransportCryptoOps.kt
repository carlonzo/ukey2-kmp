package com.carlonzo.ukey2.d2d

import com.google.security.cryptauth.lib.securegcm.Type

internal enum class PayloadType(val type: Type) {
  DEVICE_TO_DEVICE_MESSAGE(Type.DEVICE_TO_DEVICE_MESSAGE);

  companion object {
    fun valueOf(type: Type?): PayloadType {
      if (type != Type.DEVICE_TO_DEVICE_MESSAGE) {
        throw IllegalArgumentException("Unsupported payload type: $type")
      }
      return DEVICE_TO_DEVICE_MESSAGE
    }
  }
}

internal data class Payload(val payloadType: PayloadType, val message: ByteArray) {

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (other == null || this::class != other::class) return false

    other as Payload

    if (payloadType != other.payloadType) return false
    return message.contentEquals(other.message)
  }

  override fun hashCode(): Int {
    var result = payloadType.hashCode()
    result = 31 * result + message.contentHashCode()
    return result
  }
}
