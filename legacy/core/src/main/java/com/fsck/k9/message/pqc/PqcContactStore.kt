package com.fsck.k9.message.pqc
import android.content.Context
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import java.io.File
import java.util.concurrent.ConcurrentHashMap

object PqcContactStore {

    private val pqcPublicKeys = ConcurrentHashMap<String, PqcContact>()

    @Serializable
    data class PqcContact(
        val email: String,
        val kemAlgorithm: String,
        val publicKey: ByteArray,
        val sharedSecret: ByteArray? = null,
        val lastUpdated: Long = System.currentTimeMillis()
    )

    private const val FILE_NAME = "pqc_contacts.json"

    fun saveContact(email: String, kemAlgorithm: String, publicKey: ByteArray) {
        try {
            val kem = org.openquantumsafe.KeyEncapsulation(kemAlgorithm)
            val expectedLength = kem.export_public_key().size
            kem.dispose_KEM()

            if (publicKey.size != expectedLength) {
                throw IllegalArgumentException("Public key length does not match expected length for algorithm $kemAlgorithm")
            }

            pqcPublicKeys[email.lowercase()] = PqcContact(
                email = email,
                kemAlgorithm = kemAlgorithm,
                publicKey = publicKey
            )
        } catch (e: Exception) {
            e.printStackTrace()
            throw IllegalArgumentException("Failed to verify public key length: ${e.message}")
        }
    }

    fun getPublicKey(email: String): ByteArray? {
        return pqcPublicKeys[email.lowercase()]?.publicKey
    }

    fun getKemAlgorithm(email: String): String? {
        return pqcPublicKeys[email.lowercase()]?.kemAlgorithm
    }

    fun deleteContact(email: String) {
        pqcPublicKeys.remove(email.lowercase())
    }

    fun getAllContacts(): List<PqcContact> {
        return pqcPublicKeys.values.toList()
    }

    fun clear() {
        pqcPublicKeys.clear()
    }

    fun saveSharedSecret(email: String, sharedSecret: ByteArray) {
        val key = email.lowercase()
        val existingContact = pqcPublicKeys[key]
        if (existingContact != null) {
            pqcPublicKeys[key] = existingContact.copy(
                sharedSecret = sharedSecret,
                lastUpdated = System.currentTimeMillis()
            )
        } else {
            throw IllegalArgumentException("Cannot save shared secret: Contact for $email does not exist!")
        }
    }


    fun saveToDisk(context: Context) {
        try {
            val json = Json.encodeToString(pqcPublicKeys.values.toList())
            val file = File(context.filesDir, FILE_NAME)
            file.writeText(json)
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    fun loadFromDisk(context: Context) {
        try {
            val file = File(context.filesDir, FILE_NAME)
            if (!file.exists()) return

            val json = file.readText()
            val list = Json.decodeFromString<List<PqcContact>>(json)
            pqcPublicKeys.clear()
            list.forEach { contact ->
                pqcPublicKeys[contact.email.lowercase()] = contact
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }
}

