package steps

import java.security.KeyPairGenerator
import java.security.PublicKey
import java.security.spec.ECGenParameterSpec

class Keys(applePublicKey: PublicKey, ephemeralPublicKey: ByteArray, ephemeralPrivateKey: ByteArray) {
    val applePubKey: PublicKey = applePublicKey
    val ephemeralPubKey: ByteArray = ephemeralPublicKey
    val ephemeralPriKey: ByteArray = ephemeralPrivateKey
}

fun generateEphemeralKeyPairs(applePublicKey: PublicKey): Keys {
    // Ephemeral Key Pairs
    val keyPairGenerator = KeyPairGenerator.getInstance("EC")
    val ecGenParameterSpec = ECGenParameterSpec("secp256r1") // NIST P-256.
    keyPairGenerator.initialize(ecGenParameterSpec)

    val keyPair = keyPairGenerator.genKeyPair()

    val publicKey = keyPair.public
    val publicKeyBytes = publicKey.encoded
    val ephemeralPublicKey = ByteArray(65)
    System.arraycopy(publicKeyBytes, publicKeyBytes.size - 65, ephemeralPublicKey, 0, 65)

    val privateKey = keyPair.private
    val privateKeyBytes = privateKey.encoded
    var ephemeralPrivateKey = ByteArray(32)

    if (privateKeyBytes.size >= 32) {
        privateKeyBytes.sliceArray(0 until 32)
        ephemeralPrivateKey = privateKeyBytes.clone()
    } else {
        // If the private key is shorter than 32 bytes, pad it with zeros
        System.arraycopy(privateKeyBytes, 0, ephemeralPrivateKey, 0, privateKeyBytes.size)
    }

    return Keys(applePublicKey, ephemeralPublicKey, ephemeralPrivateKey)
}

//fun main() {
//    val keyPairs = generateEphemeralKeyPairs(extractedApplePublicKey)
//}