package com.fsck.k9.ui.settings.account.pqcExtension

import android.content.Context
import android.net.Uri
import android.os.Build
import android.os.Environment
import androidx.annotation.RequiresApi
import androidx.lifecycle.*
import app.k9mail.legacy.account.Account
import app.k9mail.legacy.account.AccountManager
import com.fsck.k9.Preferences
import com.fsck.k9.message.pqc.CryptoUtils
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import org.openquantumsafe.KEMs
import org.openquantumsafe.KeyEncapsulation
import java.io.File
import java.io.FileOutputStream
import java.io.InputStream
import java.util.Base64

class PqcKemKeyManagementViewModel(
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

    private fun loadAccount(accountUuid: String): Account? {
        return accountManager.getAccount(accountUuid)
    }

    @RequiresApi(Build.VERSION_CODES.O)
    fun generatePqcKemKeyPair() {
        viewModelScope.launch {
            _isLoading.value = true
            try {
                if (account == null) {
                    _errorMessage.postValue(Event("Account konnte nicht geladen werden."))
                    return@launch
                }

                withContext(Dispatchers.IO) {
                    val algorithm = account.pqcKemAlgorithm

                    if (algorithm.isNullOrBlank() || !KEMs.is_KEM_enabled(algorithm)) {
                        throw RuntimeException("PQC KEM algorithm '$algorithm' not enabled.")
                    }

                    val kem = KeyEncapsulation(algorithm)
                    try {
                        kem.generate_keypair()

                        val publicKey = Base64.getMimeEncoder().encodeToString(kem.export_public_key())
                        val secretKey = Base64.getMimeEncoder().encodeToString(kem.export_secret_key())

                        account.pqcKemPublicKey = publicKey
                        account.pqcKemSecretKey = secretKey
                        account.pqcKemKeysetExists = true

                        preferences.saveAccount(account)
                    } finally {
                        kem.dispose_KEM()                    }
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

    fun resetKeyPair() {
        viewModelScope.launch {
            _isLoading.value = true
            try {
                if (account == null) {
                    _errorMessage.postValue(Event("Account konnte nicht geladen werden."))
                    return@launch
                }

                withContext(Dispatchers.IO) {
                    account.pqcKemPublicKey = null
                    account.pqcKemSecretKey = null
                    account.pqcKemKeysetExists = false
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

    fun exportKeyFile(context: Context, password: String) {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                if (account == null) {
                    _errorMessage.postValue(Event("Account konnte nicht geladen werden."))
                    return@launch
                }

                val algorithm = account.pqcKemAlgorithm ?: "Unbekannt"
                val publicKey = account.pqcKemPublicKey
                val privateKey = account.pqcKemSecretKey

                if (publicKey.isNullOrBlank() || privateKey.isNullOrBlank()) {
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
                val file = File(exportDir, "pqkemkeys_${account.name}.pqk")

                FileOutputStream(file).use { it.write(encrypted) }

            } catch (e: Exception) {
                e.printStackTrace()
                _errorMessage.postValue(Event("Fehler beim Exportieren: ${e.message}"))
            }
        }
    }

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

                account.pqcKemAlgorithm = json.getString("algorithm")
                account.pqcKemPublicKey = json.getString("publicKey")
                account.pqcKemSecretKey = json.getString("privateKey")
                account.pqcKemKeysetExists = true

                preferences.saveAccount(account)

            } catch (e: Exception) {
                e.printStackTrace()
                _errorMessage.postValue(Event("Fehler beim Importieren: ${e.message}"))
            } finally {
                updateKeyStatus()
            }
        }
    }

    fun getPublicKey(): String? = account?.pqcKemPublicKey
    fun getSecretKey(): String? = account?.pqcKemSecretKey
    fun getCurrentAlgorithm(): String? = account?.pqcKemAlgorithm

    private fun updateKeyStatus() {
        _keyStatus.postValue(
            KeyStatus(
                publicKey = account?.pqcKemPublicKey,
                privateKey = account?.pqcKemSecretKey,
                algorithm = account?.pqcKemAlgorithm
            )
        )
    }

    data class KeyStatus(
        val publicKey: String?,
        val privateKey: String?,
        val algorithm: String?
    )
}
