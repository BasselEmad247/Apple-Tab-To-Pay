package steps

import java.security.PrivateKey
import java.security.PublicKey
import javax.crypto.KeyAgreement

fun generateSharedSecret(applePublicKey: PublicKey, ephemeralPrivateKey: PrivateKey): String {
    val keyAgreement = KeyAgreement.getInstance("ECDH")
    keyAgreement.init(ephemeralPrivateKey)
    keyAgreement.doPhase(applePublicKey, true)

    val secretKey = keyAgreement.generateSecret()

    return byteArrayToHexString(secretKey).uppercase()
}

//fun main() {
//    val sharedSecretHex = generateSharedSecret(keyPairs.applePubKey, byteArrayToPrivateKey(keyPairs.ephemeralPriKey))
//}