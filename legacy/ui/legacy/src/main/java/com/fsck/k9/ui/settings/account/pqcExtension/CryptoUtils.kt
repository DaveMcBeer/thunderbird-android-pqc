package com.fsck.k9.ui.settings.account.pqcExtension
import android.util.Base64
import java.security.SecureRandom
import java.security.spec.KeySpec
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * Utility-Klasse für symmetrische AES-Verschlüsselung und -Entschlüsselung
 * mit Passwort-basierter Schlüsselableitung (PBKDF2).
 *
 * Diese Klasse wird verwendet, um sensible Daten (z. B. PQC-Schlüsselpaare)
 * sicher als ByteArray zu speichern oder zu übertragen.
 */

object CryptoUtils {
    private const val ITERATION_COUNT = 100_000 // Anzahl der Iterationen für die Passwort-Ableitung (PBKDF2)
    private const val KEY_LENGTH = 256 // Länge des AES-Schlüssels in Bit
    private const val SALT_LENGTH = 16 // Länge des Salt (in Byte)
    private const val IV_LENGTH = 16  // Länge des Initialisierungsvektors (AES-CBC)
    private const val ALGORITHM = "AES/CBC/PKCS5Padding" // Verschlüsselungsmodus

    /**
     * Verschlüsselt einen gegebenen JSON-String mit dem übergebenen Passwort.
     *
     * @param jsonData Die zu verschlüsselnden Daten (z. B. Schlüssel als JSON)
     * @param password Das Passwort zur Ableitung des Schlüssels
     * @return Ein ByteArray, das Salt + IV + Ciphertext enthält
     */
    fun encrypt(jsonData: String, password: String): ByteArray {
        val salt = SecureRandom().generateSeed(SALT_LENGTH)
        val iv = SecureRandom().generateSeed(IV_LENGTH)

        val key = deriveKey(password, salt)
        val cipher = Cipher.getInstance(ALGORITHM)
        cipher.init(Cipher.ENCRYPT_MODE, key, IvParameterSpec(iv))
        val encrypted = cipher.doFinal(jsonData.toByteArray(Charsets.UTF_8))

        return salt + iv + encrypted // Concatenate for storage
    }

    /**
     * Entschlüsselt ein zuvor mit [encrypt] verschlüsseltes ByteArray.
     *
     * @param data Das verschlüsselte Datenpaket (Salt + IV + Ciphertext)
     * @param password Das Passwort, das zum Ableiten des Schlüssels verwendet wurde
     * @return Der entschlüsselte JSON-String
     *
     * @throws Exception bei falschem Passwort oder ungültigem Datenformat
     */
    fun decrypt(data: ByteArray, password: String): String {
        val salt = data.copyOfRange(0, SALT_LENGTH)
        val iv = data.copyOfRange(SALT_LENGTH, SALT_LENGTH + IV_LENGTH)
        val ciphertext = data.copyOfRange(SALT_LENGTH + IV_LENGTH, data.size)

        val key = deriveKey(password, salt)
        val cipher = Cipher.getInstance(ALGORITHM)
        cipher.init(Cipher.DECRYPT_MODE, key, IvParameterSpec(iv))
        val decrypted = cipher.doFinal(ciphertext)
        return String(decrypted, Charsets.UTF_8)
    }

    /**
     * Leitet aus einem Passwort und Salt einen AES-Schlüssel mit PBKDF2 ab.
     *
     * @param password Das Passwort, aus dem der Schlüssel generiert wird
     * @param salt Der Salt-Wert für die Schlüsselableitung (sollte zufällig sein)
     * @return Der abgeleitete AES-Schlüssel als [SecretKeySpec]
     */
    private fun deriveKey(password: String, salt: ByteArray): SecretKeySpec {
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val spec: KeySpec = PBEKeySpec(password.toCharArray(), salt, ITERATION_COUNT, KEY_LENGTH)
        val tmp = factory.generateSecret(spec)
        return SecretKeySpec(tmp.encoded, "AES")
    }
}
