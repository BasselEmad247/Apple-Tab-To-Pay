import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.modes.GCMBlockCipher
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.util.encoders.Hex
import java.io.FileInputStream
import java.security.*
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.util.*
import javax.crypto.KeyAgreement
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

class EncryptTabToPayDataResponse(
    val activationData: String, // Base64
    val encryptedPassData: String, // Base64 - This will include ( primaryAccountNumber - expiration - name - nonce - nonceSignature )
    val ephemeralPublicKey: String // Base64
)

class Keys(applePublicKey: PublicKey, ephemeralPublicKey: ByteArray, ephemeralPrivateKey: ByteArray) {
    val applePubKey: PublicKey = applePublicKey
    val ephemeralPubKey: ByteArray = ephemeralPublicKey
    val ephemeralPriKey: ByteArray = ephemeralPrivateKey
}

fun extractApplePublicKey(leafCertificateFilePath: String): PublicKey {
    // Load the certificate file
    val fileInputStream = FileInputStream(leafCertificateFilePath)

    // Create a CertificateFactory instance for X.509 certificates
    val certificateFactory = CertificateFactory.getInstance("X.509")

    // Load the certificate
    val certificate = certificateFactory.generateCertificate(fileInputStream) as X509Certificate

    // Close the FileInputStream
    fileInputStream.close()

    // Retrieve the public key from the certificate
    return certificate.publicKey
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

fun generateSharedSecret(applePublicKey: PublicKey, ephemeralPrivateKey: PrivateKey): String {
    val keyAgreement = KeyAgreement.getInstance("ECDH")
    keyAgreement.init(ephemeralPrivateKey)
    keyAgreement.doPhase(applePublicKey, true)

    val secretKey = keyAgreement.generateSecret()

    return byteArrayToHexString(secretKey).uppercase()
}

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

fun generateSharedAesKey(kdfInput: String): SecretKey {
    val sha256Digest = MessageDigest.getInstance("SHA-256")
    val hashBytes = sha256Digest.digest(hexStringToByteArray(kdfInput))
    return SecretKeySpec(hashBytes, "AES")
}

fun encryptAesGcmWithMac(key: ByteArray, plaintext: ByteArray): ByteArray {
    Security.addProvider(BouncyCastleProvider())

    val cipher = GCMBlockCipher(AESEngine())
    val keyParam = KeyParameter(key)
    val params = AEADParameters(keyParam, 128, ByteArray(12)) // 12-byte null IV

    cipher.init(true, params)

    val ciphertext = ByteArray(cipher.getOutputSize(plaintext.size))

    val outputLength = cipher.processBytes(plaintext, 0, plaintext.size, ciphertext, 0)
    cipher.doFinal(ciphertext, outputLength)

    // Append the MAC to the end of the ciphertext
    val mac = cipher.mac
    val encryptedDataWithMac = ByteArray(ciphertext.size + mac.size)
    System.arraycopy(ciphertext, 0, encryptedDataWithMac, 0, ciphertext.size)
    System.arraycopy(mac, 0, encryptedDataWithMac, ciphertext.size, mac.size)

    return encryptedDataWithMac
}

fun encodeAndSendData(activationData: ByteArray, publicKey: ByteArray, encryptedData: ByteArray): EncryptTabToPayDataResponse {
    // Encode data as Base64 strings
    val activationDataString = Base64.getEncoder().encodeToString(activationData)
    val publicKeyString = Base64.getEncoder().encodeToString(publicKey)
    val encryptedDataString = Base64.getEncoder().encodeToString(encryptedData)

    return EncryptTabToPayDataResponse(publicKeyString, encryptedDataString, activationDataString)
}

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
    val keyFactory = KeyFactory.getInstance("EC")
    val keySpec = PKCS8EncodedKeySpec(byteArray)
    return keyFactory.generatePrivate(keySpec)
}

fun main() {
    // Specify the path to the leaf certificate file
    val leafCertificateFilePath = "src/main/resources/Certificate.crt"
    val extractedApplePublicKey = extractApplePublicKey(leafCertificateFilePath)

    //------------------------------------------------------------------------------------------------------------------

    val keyPairs = generateEphemeralKeyPairs(extractedApplePublicKey)

    //------------------------------------------------------------------------------------------------------------------

    val sharedSecretHex = generateSharedSecret(keyPairs.applePubKey, byteArrayToPrivateKey(keyPairs.ephemeralPriKey))

    //------------------------------------------------------------------------------------------------------------------

    val sharedSecret = hexStringToByteArray(sharedSecretHex)
    val ephemeralPublicKey = hexStringToByteArray(byteArrayToHexString(keyPairs.ephemeralPubKey))

    val kdfInput = nistKdf(sharedSecret, ephemeralPublicKey)
    val kdfInputHex = byteArrayToHexString(kdfInput)

    //------------------------------------------------------------------------------------------------------------------

    val aesKeyHex = byteArrayToHexString(generateSharedAesKey(kdfInputHex).encoded)

    //------------------------------------------------------------------------------------------------------------------

    val key = Hex.decode(aesKeyHex)

    // JSON payload (67 bytes), UTF-8 encoded
    val jsonPayload =
                "{\"primaryAccountNumber\":${"cardNumber"}," +
                "\"expiration\":${"expiryDate"}," +
                "\"name\":${"name"}," +
                "\"nonce\":${"nonce"}," +
                "\"nonceSignature\":${"nonceSignature"}}"

    val plaintext = jsonPayload.toByteArray(Charsets.UTF_8)

    val encryptedDataWithMac = encryptAesGcmWithMac(key, plaintext)

    //------------------------------------------------------------------------------------------------------------------

    val activationData = "5572b844-e46a-4100-b6a4-a6d4c3cd265d".toByteArray()

    // Encode and send data
    val jsonResponse = encodeAndSendData(activationData, keyPairs.ephemeralPubKey, encryptedDataWithMac)
    println("Activation Data: ${jsonResponse.activationData}")
    println("Encrypted Pass Data: ${jsonResponse.encryptedPassData}")
    println("Ephemeral Public Key: ${jsonResponse.ephemeralPublicKey}")
}