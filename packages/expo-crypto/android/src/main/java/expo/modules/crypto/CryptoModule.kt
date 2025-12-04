package expo.modules.crypto

import android.util.Base64
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import expo.modules.kotlin.typedarray.TypedArray
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.UUID

class CryptoModule : Module() {
  private val secureRandom by lazy { SecureRandom() }

  override fun definition() = ModuleDefinition {
    Name("ExpoCrypto")

    Function("digestString", this@CryptoModule::digestString)
    AsyncFunction("digestStringAsync", this@CryptoModule::digestString)
    Function("getRandomBase64String", this@CryptoModule::getRandomBase64String)
    AsyncFunction("getRandomBase64StringAsync", this@CryptoModule::getRandomBase64String)
    Function("getRandomValues", this@CryptoModule::getRandomValues)
    Function("digest", this@CryptoModule::digest)
    Function("hmac", this@CryptoModule::hmac)
    Function("hmacString", this@CryptoModule::hmacString)
    AsyncFunction("hmacStringAsync", this@CryptoModule::hmacString)
    Function("randomUUID") {
      UUID.randomUUID().toString()
    }
  }

  private fun getRandomBase64String(randomByteCount: Int): String {
    val output = ByteArray(randomByteCount)
    secureRandom.nextBytes(output)
    return Base64.encodeToString(output, Base64.NO_WRAP)
  }

  private fun digestString(algorithm: DigestAlgorithm, data: String, options: DigestOptions): String {
    val messageDigest = MessageDigest.getInstance(algorithm.value).apply { update(data.toByteArray()) }

    val digest: ByteArray = messageDigest.digest()
    return when (options.encoding) {
      DigestOptions.Encoding.BASE64 -> {
        Base64.encodeToString(digest, Base64.NO_WRAP)
      }
      DigestOptions.Encoding.HEX -> {
        digest.joinToString(separator = "") { byte ->
          ((byte.toInt() and 0xff) + 0x100)
            .toString(radix = 16)
            .substring(startIndex = 1)
        }
      }
    }
  }

  private fun digest(algorithm: DigestAlgorithm, output: TypedArray, data: TypedArray) {
    val messageDigest = MessageDigest.getInstance(algorithm.value).apply { update(data.toDirectBuffer()) }

    val digest: ByteArray = messageDigest.digest()
    output.write(digest, output.byteOffset, output.byteLength)
  }

  private fun hmac(algorithm: HmacAlgorithm, output: TypedArray, key: TypedArray, data: TypedArray) {
    val mac = javax.crypto.Mac.getInstance(algorithm.value)
    val keyBuffer = key.toDirectBuffer()
    val keyBytes = ByteArray(keyBuffer.remaining())
    keyBuffer.get(keyBytes)
    val secret = javax.crypto.spec.SecretKeySpec(keyBytes, algorithm.value)
    mac.init(secret)
    mac.update(data.toDirectBuffer())
    val result = mac.doFinal()
    require(result.size == output.byteLength) { "Output TypedArray length ${output.byteLength} does not match HMAC length ${result.size}" }
    output.write(result, output.byteOffset, output.byteLength)
  }

  private fun hmacString(algorithm: HmacAlgorithm, key: String, data: String, options: DigestOptions): String {
    val mac = javax.crypto.Mac.getInstance(algorithm.value)
    val secret = javax.crypto.spec.SecretKeySpec(key.toByteArray(), algorithm.value)
    mac.init(secret)
    val result = mac.doFinal(data.toByteArray())
    return when (options.encoding) {
      DigestOptions.Encoding.BASE64 -> Base64.encodeToString(result, Base64.NO_WRAP)
      DigestOptions.Encoding.HEX -> result.joinToString(separator = "") { byte ->
        ((byte.toInt() and 0xff) + 0x100).toString(radix = 16).substring(startIndex = 1)
      }
    }
  }

  private fun getRandomValues(typedArray: TypedArray) {
    val array = ByteArray(typedArray.byteLength)
    secureRandom.nextBytes(array)
    typedArray.write(array, typedArray.byteOffset, typedArray.byteLength)
  }
}
