package steps

import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.ECGenParameterSpec

class Keys(publicKey: PublicKey, privateKey: PrivateKey, ephemeralPublicKey: ByteArray) {
    val pubKey: PublicKey = publicKey
    val priKey: PrivateKey = privateKey
    val ephPublicKey: ByteArray = ephemeralPublicKey
}

fun generateEphemeralKeyPairs(encodedPublicKey: ByteArray): Keys {
    // Ephemeral Key Pairs
    val keyPairGenerator = KeyPairGenerator.getInstance("EC")
    val ecGenParameterSpec = ECGenParameterSpec("secp256r1") // NIST P-256.
    keyPairGenerator.initialize(ecGenParameterSpec)

    val keyPair = keyPairGenerator.genKeyPair()

    val publicKey = keyPair.public
    val ephemeralPublicKey = ByteArray(65)
    System.arraycopy(keyPair.public.encoded, encodedPublicKey.size - 65, ephemeralPublicKey, 0, 65)

    val privateKey = keyPair.private
    val privateKeyBytes = privateKey.encoded

    // Trim leading zeros if any
    if (privateKeyBytes.size > 32) {
        val trimmedPrivateKeyBytes = ByteArray(32)
        System.arraycopy(privateKeyBytes, privateKeyBytes.size - 32, trimmedPrivateKeyBytes, 0, 32)
    }

    return Keys(publicKey, privateKey, ephemeralPublicKey)
}

//fun main() {
//    val keyPairs = generateEphemeralKeyPairs(extractedApplePublicKey)
//}