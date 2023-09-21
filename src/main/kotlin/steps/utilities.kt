package steps

import java.security.KeyFactory
import java.security.PrivateKey
import java.security.spec.PKCS8EncodedKeySpec

// Helper method to convert bytes to hexadecimal string
fun byteArrayToHexString(bytes: ByteArray): String {
    val stringBuilder = StringBuilder()
    for (b in bytes) {
        stringBuilder.append(String.format("%02x", b))
    }
    return stringBuilder.toString()
}

// Helper method to convert hexadecimal string to bytes
fun hexStringToByteArray(hexString: String): ByteArray {
    val hexChars = hexString.toCharArray()
    val byteLength = hexChars.size / 2
    val byteArray = ByteArray(byteLength)

    for (i in 0 until byteLength) {
        val startIndex = i * 2
        val hexValue = Integer.parseInt(hexChars[startIndex].toString() + hexChars[startIndex + 1], 16)
        byteArray[i] = hexValue.toByte()
    }

    return byteArray
}

fun byteArrayToPrivateKey(byteArray: ByteArray): PrivateKey {
    val keyFactory = KeyFactory.getInstance("RSA")
    val keySpec = PKCS8EncodedKeySpec(byteArray)
    return keyFactory.generatePrivate(keySpec)
}