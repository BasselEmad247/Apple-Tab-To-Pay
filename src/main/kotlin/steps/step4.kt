package steps

fun nistKdf(sharedSecret: ByteArray, ephemeralPublicKey: ByteArray): ByteArray {
    val counter = byteArrayOf(0x00, 0x00, 0x00, 0x01) // 00000001
    val algorithmIdLength = byteArrayOf(0x0D) // 0D
    val algorithmId = byteArrayOf(0x69, 0x64, 0x2D, 0x61, 0x65, 0x73, 0x32, 0x35, 0x36, 0x2D, 0x47, 0x43, 0x4D) // ("id-aes256-GCM", 13 bytes): 69642D6165733235362D47434D
    val partyUInfo = byteArrayOf(0x41, 0x70, 0x70, 0x6C, 0x65) // ("Apple", 5 bytes): 4170706C65

    val kdfInput = ByteArray(120)
    System.arraycopy(counter, 0, kdfInput, 0, counter.size)
    System.arraycopy(sharedSecret, 0, kdfInput, counter.size, sharedSecret.size)
    System.arraycopy(algorithmIdLength, 0, kdfInput, counter.size + sharedSecret.size, algorithmIdLength.size)
    System.arraycopy(algorithmId, 0, kdfInput, counter.size + sharedSecret.size + algorithmIdLength.size, algorithmId.size)
    System.arraycopy(partyUInfo, 0, kdfInput, counter.size + sharedSecret.size + algorithmIdLength.size + algorithmId.size, partyUInfo.size)
    System.arraycopy(ephemeralPublicKey, 0, kdfInput, counter.size + sharedSecret.size + algorithmIdLength.size + algorithmId.size + partyUInfo.size, ephemeralPublicKey.size)

    return kdfInput
}

//fun main() {
//    val sharedSecret = hexStringToByteArray(sharedSecretHex)
//
//    val kdfInput = nistKdf(sharedSecret, keyPairs.ephemeralPubKey)
//    val kdfInputHex = byteArrayToHexString(kdfInput)
//}