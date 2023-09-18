package steps

import java.security.MessageDigest
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

fun generateSharedAesKey(kdfInput: String): SecretKey {
    val sha256Digest = MessageDigest.getInstance("SHA-256")
    val hashBytes = sha256Digest.digest(hexStringToByteArray2(kdfInput))
    return SecretKeySpec(hashBytes, "AES")
}

fun hexStringToByteArray2(hexString: String): ByteArray {
    val hexChars = hexString.toCharArray()
    val byteLength = hexChars.size / 2
    val byteArray = ByteArray(byteLength)

    for (i in 0..<byteLength) {
        val startIndex = i * 2
        val hexValue = Integer.parseInt(hexChars[startIndex].toString() + hexChars[startIndex + 1], 16)
        byteArray[i] = hexValue.toByte()
    }

    return byteArray
}

fun bytesToHex2(bytes: ByteArray): String {
    val hexArray = "0123456789ABCDEF".toCharArray()
    val hexChars = CharArray(bytes.size * 2)
    for (i in bytes.indices) {
        val v = bytes[i].toInt() and 0xFF
        hexChars[i * 2] = hexArray[v ushr 4]
        hexChars[i * 2 + 1] = hexArray[v and 0x0F]
    }
    return String(hexChars)
}

//fun main() {
//    val aesKeyHex = bytesToHex2(generateSharedAesKey(kdfInputHex).encoded)
//}