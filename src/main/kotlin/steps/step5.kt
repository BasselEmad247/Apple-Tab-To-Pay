package steps

import java.security.MessageDigest
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

fun generateSharedAesKey(kdfInput: String): SecretKey {
    val sha256Digest = MessageDigest.getInstance("SHA-256")
    val hashBytes = sha256Digest.digest(hexStringToByteArray(kdfInput))
    return SecretKeySpec(hashBytes, "AES")
}

//fun main() {
//    val aesKeyHex = byteArrayToHexString(generateSharedAesKey(kdfInputHex).encoded)
//}