import CommonCrypto
import ExpoModulesCore

internal enum HmacAlgorithm: String, Enumerable {
  case hmacSha1 = "HMAC-SHA-1"
  case hmacSha256 = "HMAC-SHA-256"
  case hmacSha384 = "HMAC-SHA-384"
  case hmacSha512 = "HMAC-SHA-512"

  var ccAlgorithm: CCHmacAlgorithm {
    switch self {
    case .hmacSha1: return CCHmacAlgorithm(kCCHmacAlgSHA1)
    case .hmacSha256: return CCHmacAlgorithm(kCCHmacAlgSHA256)
    case .hmacSha384: return CCHmacAlgorithm(kCCHmacAlgSHA384)
    case .hmacSha512: return CCHmacAlgorithm(kCCHmacAlgSHA512)
    }
  }

  var digestLength: Int {
    switch self {
    case .hmacSha1: return Int(CC_SHA1_DIGEST_LENGTH)
    case .hmacSha256: return Int(CC_SHA256_DIGEST_LENGTH)
    case .hmacSha384: return Int(CC_SHA384_DIGEST_LENGTH)
    case .hmacSha512: return Int(CC_SHA512_DIGEST_LENGTH)
    }
  }
}
