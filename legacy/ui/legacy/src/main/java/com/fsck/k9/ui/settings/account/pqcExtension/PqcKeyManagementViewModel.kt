package com.fsck.k9.ui.settings.account.pqcExtension


import androidx.lifecycle.ViewModel
import androidx.lifecycle.asLiveData
import androidx.lifecycle.viewModelScope
import app.k9mail.legacy.account.Account
import app.k9mail.legacy.account.AccountManager
import com.fsck.k9.Preferences
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.openquantumsafe.Signature
import org.openquantumsafe.Sigs
import android.content.Context
import android.net.Uri
import android.os.Build
import android.os.Environment
import androidx.annotation.RequiresApi
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.LiveData
import java.io.InputStream
import java.util.Base64

/**
 * ViewModel zur Verwaltung von PQC-Schlüsselpaaren (Post-Quantum Cryptography)
 * für einen Mail-Account. Beinhaltet Generieren, Zurücksetzen, Export und Import.
 */

class PqcKeyManagementViewModel(
    private val accountManager: AccountManager,
    private val preferences: Preferences,
    accountUuid: String
) : ViewModel() {

    private val _keyStatus = MutableLiveData<KeyStatus>()
    val keyStatus: LiveData<KeyStatus> = _keyStatus


    private val _isLoading = MutableLiveData<Boolean>()
    val isLoading: LiveData<Boolean> = _isLoading


    private val _errorMessage = MutableLiveData<Event<String>>()
    val errorMessage: LiveData<Event<String>> = _errorMessage

    // Alle Accounts als LiveData verfügbar (falls mehrere Accounts unterstützt werden sollen)
    val accounts = accountManager.getAccountsFlow().asLiveData()

    private val account: Account? = try {
        loadAccount(accountUuid).also {
            if (it == null) {
                _errorMessage.postValue(Event("Account nicht gefunden: $accountUuid"))
            }
        }
    } catch (e: Exception) {
        _errorMessage.postValue(Event("Fehler beim Laden des Accounts: ${e.message}"))
        null
    }


     /** lade Account daten, des ausgewählten accounts*/
    private fun loadAccount(accountUuid: String): Account? {
        return accountManager.getAccount(accountUuid)
    }

    /**
     * Generiert ein neues PQC-Schlüsselpaar (public/private) für den aktuellen Account.
     * Verwendet den im Account gespeicherten Algorithmus (z. B. Dilithium2).
     * Ergebnis wird im Account gespeichert und persistiert.
     */
    @RequiresApi(Build.VERSION_CODES.O)
    fun generatePqcKeyPair() {
        viewModelScope.launch {
            _isLoading.value = true
            try {


                if (account == null) {
                    _errorMessage.postValue(Event("Account konnte nicht geladen werden."))
                    return@launch
                }

                withContext(Dispatchers.IO) {
                    val algorithm = account.pqcSigningAlgorithm ?: "Dilithium2"
                    if (!Sigs.is_sig_enabled(algorithm)) {
                        throw RuntimeException("PQC algorithm '$algorithm' not enabled.")
                    }

                    val signature =  Signature(algorithm)
                    try {
                        signature.generate_keypair()

                        val publicKey = Base64.getEncoder().encodeToString(signature.export_public_key())
                        val privateKey =   Base64.getEncoder().encodeToString(signature.export_secret_key())

                        account.pqcPublicSigngingKey = publicKey
                        account.pqcSecretSigningKey = privateKey
                        account.pqcKeysetExists = true

                        preferences.saveAccount(account)
                    }
                    finally
                    {
                        signature.dispose_sig()
                    }
                }
            } catch (e: Exception) {
                e.printStackTrace()
                _errorMessage.value = Event("Fehler beim Generieren: ${e.message}")
            } finally {
                updateKeyStatus()
                _isLoading.value = false
            }
        }
    }


    /**
     * Setzt das aktuelle PQC-Schlüsselpaar des Accounts zurück (löscht beide Schlüssel).
     * Danach wird der Account aktualisiert gespeichert.
     */
    fun resetKeyPair() {
        viewModelScope.launch {
            _isLoading.value = true
            try {


                if (account == null) {
                    _errorMessage.postValue(Event("Account konnte nicht geladen werden."))
                    return@launch
                }

                withContext(Dispatchers.IO) {
                    account.pqcPublicSigngingKey = null
                    account.pqcSecretSigningKey = null
                    account.pqcKeysetExists = false
                    preferences.saveAccount(account)
                }

            } catch (e: Exception) {
                e.printStackTrace()
                _errorMessage.value = Event("Fehler beim Zurücksetzen des Schlüsselpaars: ${e.message}")
            } finally {
                updateKeyStatus()
                _isLoading.value = false
            }
        }
    }


    /**
     * Exportiert das aktuelle PQC-Schlüsselpaar in eine Datei auf dem Gerät.
     * Die Datei wird JSON-formatiert, verschlüsselt und im Dokumente-Ordner gespeichert.
     */
    fun exportKeyFile(context: Context, password: String) {
        viewModelScope.launch(Dispatchers.IO) {
            try {



                if (account == null) {
                    _errorMessage.postValue(Event("Account konnte nicht geladen werden."))
                    return@launch
                }

                val algorithm = account.pqcSigningAlgorithm ?: "Unbekannt"
                val publicKey = account.pqcPublicSigngingKey
                val privateKey = account.pqcSecretSigningKey

                if (publicKey.isNullOrBlank() || privateKey.isNullOrBlank())  {
                    _errorMessage.postValue(Event("Schlüsselpaar konnte nicht geladen werden."))
                    return@launch
                }

                val json = JSONObject().apply {
                    put("algorithm", algorithm)
                    put("publicKey", publicKey)
                    put("privateKey", privateKey)
                }

                val encrypted = CryptoUtils.encrypt(json.toString(), password)

                val exportDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOCUMENTS)


                val file = File(exportDir, "pqkeys_${account.name}.pqk")
                FileOutputStream(file).use { it.write(encrypted) }

            } catch (e: Exception) {
                e.printStackTrace()
                _errorMessage.postValue(Event("Fehler beim Exportieren: ${e.message}"))
            }
        }
    }

    /**
     * Importiert ein PQC-Schlüsselpaar aus einer zuvor exportierten Datei.
     * Die Datei wird entschlüsselt, validiert und in den aktuellen Account übernommen.
     */
    fun importKeyFile(context: Context, uri: Uri, password: String) {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val inputStream: InputStream? = context.contentResolver.openInputStream(uri)

                if (inputStream == null) {
                    _errorMessage.postValue(Event("Datei konnte nicht geöffnet werden."))
                    return@launch
                }

                if (account == null) {
                    _errorMessage.postValue(Event("Account konnte nicht geladen werden."))
                    return@launch
                }

                val encryptedBytes = inputStream.readBytes()
                val decrypted = CryptoUtils.decrypt(encryptedBytes, password)

                val json = JSONObject(decrypted)

                val algorithm = json.getString("algorithm")
                val publicKey = json.getString("publicKey")
                val privateKey = json.getString("privateKey")

                account.pqcSigningAlgorithm = algorithm
                account.pqcPublicSigngingKey = publicKey
                account.pqcSecretSigningKey = privateKey
                account.pqcKeysetExists = true

                preferences.saveAccount(account)

            } catch (e: Exception) {
                e.printStackTrace()
                _errorMessage.postValue(Event("Fehler beim Importieren: ${e.message}"))
            }
            finally {
                updateKeyStatus()
            }
        }
    }

    fun getPublicKey(): String? {
        return account?.pqcPublicSigngingKey
    }

    fun getSecretKey(): String? {
        return account?.pqcSecretSigningKey
    }


    fun getCurrentAlgorithm(): String? {
        return account?.pqcSigningAlgorithm
    }

    private fun ByteArray.toHexString(): String {
        return joinToString("") { "%02x".format(it) }
    }


    data class KeyStatus(
        val publicKey: String?,
        val privateKey: String?,
        val algorithm: String?
    )

    private fun updateKeyStatus() {
        _keyStatus.postValue(
            KeyStatus(
                publicKey = account?.pqcPublicSigngingKey,
                privateKey = account?.pqcSecretSigningKey,
                algorithm = account?.pqcSigningAlgorithm
            )
        )
    }
}

class Event<out T>(private val content: T) {
    private var hasBeenHandled = false

    fun getContentIfNotHandled(): T? {
        return if (hasBeenHandled) null else {
            hasBeenHandled = true
            content
        }
    }
}
