package steps

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.modes.GCMBlockCipher
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.util.encoders.Hex
import java.security.Security

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

//fun main() {
//    val key = Hex.decode(aesKeyHex)
//
//    // JSON payload (67 bytes), UTF-8 encoded
//    val jsonPayload = "{\"Parameter1\":\"Value1\",\"Parameter2\":\"Value2\",\"Parameter3\":\"Value3\"}"
//    val plaintext = jsonPayload.toByteArray(Charsets.UTF_8)
//
//    val encryptedDataWithMac = encryptAesGcmWithMac(key, plaintext)
//}