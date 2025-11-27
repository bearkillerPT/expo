package expo.modules.crypto

import expo.modules.kotlin.types.Enumerable

enum class HmacAlgorithm(val value: String) : Enumerable {
  HMAC_SHA1("HmacSHA1"),
  HMAC_SHA256("HmacSHA256"),
  HMAC_SHA384("HmacSHA384"),
  HMAC_SHA512("HmacSHA512")
}
