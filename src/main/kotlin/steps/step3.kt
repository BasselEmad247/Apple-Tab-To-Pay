package steps

import java.security.PrivateKey
import java.security.PublicKey
import javax.crypto.KeyAgreement

fun generateSharedSecret(applePublicKey: PublicKey, ephemeralPrivateKey: PrivateKey): String {
    val keyAgreement = KeyAgreement.getInstance("ECDH")
    keyAgreement.init(ephemeralPrivateKey)
    keyAgreement.doPhase(applePublicKey, true)

    val secretKey = keyAgreement.generateSecret()

    return bytesToHex(secretKey).uppercase()
}

// Helper method to convert bytes to hexadecimal string
fun bytesToHex(bytes: ByteArray): String {
    val stringBuilder = StringBuilder()
    for (b in bytes) {
        stringBuilder.append(String.format("%02x", b))
    }
    return stringBuilder.toString()
}

//fun main() {
//    val sharedSecretHex = generateSharedSecret(keyPairs.pubKey, keyPairs.priKey)
//}