package steps

fun nistKdf(sharedSecret: ByteArray, ephemeralPublicKey: ByteArray): ByteArray {
    val counter = byteArrayOf(0x00, 0x00, 0x00, 0x01)
    val algorithmIdLength = byteArrayOf(0x0D)
    val algorithmId = byteArrayOf(
        0x69, 0x64, 0x2D, 0x61, 0x65, 0x73, 0x32, 0x35, 0x36, 0x2D, 0x47, 0x43, 0x4D
    )
    val partyUInfo = byteArrayOf(0x41, 0x70, 0x70, 0x6C, 0x65)

    val kdfInput = ByteArray(120)
    System.arraycopy(counter, 0, kdfInput, 0, counter.size)
    System.arraycopy(sharedSecret, 0, kdfInput, counter.size, sharedSecret.size)
    System.arraycopy(algorithmIdLength, 0, kdfInput, counter.size + sharedSecret.size, algorithmIdLength.size)
    System.arraycopy(algorithmId, 0, kdfInput, counter.size + sharedSecret.size + algorithmIdLength.size, algorithmId.size)
    System.arraycopy(partyUInfo, 0, kdfInput, counter.size + sharedSecret.size + algorithmIdLength.size + algorithmId.size, partyUInfo.size)
    System.arraycopy(ephemeralPublicKey, 0, kdfInput, counter.size + sharedSecret.size + algorithmIdLength.size + algorithmId.size + partyUInfo.size, ephemeralPublicKey.size)

    return kdfInput
}

fun hexStringToByteArray(hexString: String): ByteArray {
    val len = hexString.length
    val data = ByteArray(len / 2)
    var i = 0
    while (i < len) {
        data[i / 2] = ((Character.digit(hexString[i], 16) shl 4) + Character.digit(hexString[i + 1], 16)).toByte()
        i += 2
    }
    return data
}

fun byteArrayToHexString(byteArray: ByteArray): String {
    val result = StringBuilder()
    for (b in byteArray) {
        result.append(String.format("%02X", b))
    }
    return result.toString()
}

//fun main() {
//    val sharedSecret = hexStringToByteArray(sharedSecretHex)
//    val ephemeralPublicKey = hexStringToByteArray(bytesToHex(keyPairs.ephPublicKey))
//
//    val kdfInput = nistKdf(sharedSecret, ephemeralPublicKey)
//    val kdfInputHex = byteArrayToHexString(kdfInput)
//}