package d2d


object SecureGcmConstants {
  const val SECURE_GCM_VERSION = 1

  /**
   * The GCM sender identity used by this library (GMSCore).
   */
  const val SENDER_ID = "745476177629"

  /**
   * The key used for indexing the GCM [TransportCryptoOps.Payload] within `AppData`.
   */
  const val MESSAGE_KEY = "P"

  /**
   * The origin that should be use for GCM device enrollments.
   */
  const val GOOGLE_ORIGIN = "google.com"

  /**
   * The origin that should be use for GCM Legacy android device enrollments.
   */
  const val LEGACY_ANDROID_ORIGIN = "c.g.a.gms"

  /**
   * The name of the protocol this library speaks.
   */
  const val PROTOCOL_TYPE_NAME = "gcmV1"
}