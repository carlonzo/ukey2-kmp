package d2d

import com.google.security.cryptauth.lib.securegcm.Type

/**
 * A type safe version of the [SecureGcmProto] `Type` codes.
 */
enum class PayloadType(val type: Type) {
  ENROLLMENT(Type.ENROLLMENT),
  TICKLE(Type.TICKLE),
  TX_REQUEST(Type.TX_REQUEST),
  TX_REPLY(Type.TX_REPLY),
  TX_SYNC_REQUEST(Type.TX_SYNC_REQUEST),
  TX_SYNC_RESPONSE(Type.TX_SYNC_RESPONSE),
  TX_PING(Type.TX_PING),
  DEVICE_INFO_UPDATE(Type.DEVICE_INFO_UPDATE),
  TX_CANCEL_REQUEST(Type.TX_CANCEL_REQUEST),
  LOGIN_NOTIFICATION(Type.LOGIN_NOTIFICATION),
  PROXIMITYAUTH_PAIRING(Type.PROXIMITYAUTH_PAIRING),
  GCMV1_IDENTITY_ASSERTION(Type.GCMV1_IDENTITY_ASSERTION),
  DEVICE_TO_DEVICE_RESPONDER_HELLO_PAYLOAD(Type.DEVICE_TO_DEVICE_RESPONDER_HELLO_PAYLOAD),
  DEVICE_TO_DEVICE_MESSAGE(Type.DEVICE_TO_DEVICE_MESSAGE),
  DEVICE_PROXIMITY_CALLBACK(Type.DEVICE_PROXIMITY_CALLBACK),
  UNLOCK_KEY_SIGNED_CHALLENGE(Type.UNLOCK_KEY_SIGNED_CHALLENGE);


  companion object {
    fun valueOf(type: Type): PayloadType {
      return valueOf(type.value)
    }

    fun valueOf(type: Int): PayloadType {
      for (payloadType in values()) {
        if (payloadType.type.value == type) {
          return payloadType
        }
      }
      throw IllegalArgumentException("Unsupported payload type: $type")
    }
  }
}

/**
 * Encapsulates a [PayloadType] specifier, and a corresponding raw `message` payload.
 */
data class Payload(val payloadType: PayloadType, val message: ByteArray) {

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