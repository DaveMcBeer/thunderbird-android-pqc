package com.fsck.k9.ui.settings.account.pqcExtension

import android.content.Context
import android.net.Uri
import android.os.Build
import android.os.Environment
import androidx.annotation.RequiresApi
import androidx.lifecycle.*
import app.k9mail.legacy.account.Account
import app.k9mail.legacy.account.AccountManager
import app.k9mail.legacy.di.DI
import com.fsck.k9.Preferences
import com.fsck.k9.controller.MessagingController
import com.fsck.k9.helper.Contacts
import com.fsck.k9.mail.Address
import com.fsck.k9.message.pqc.CryptoUtils
import com.fsck.k9.pqcExtension.KeyDistribution.KeyDistributor
import com.fsck.k9.pqcExtension.PqcExtensionCore
import com.fsck.k9.pqcExtension.keyManagement.KeyRegistryFactory
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import java.io.InputStream

class PqcSigningKeyManagementViewModel(
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

    private fun loadAccount(accountUuid: String): Account? = accountManager.getAccount(accountUuid)

    @RequiresApi(Build.VERSION_CODES.O)
    fun generateSigningKey(context: Context, accountUuid: String, algorithm: String) {
        viewModelScope.launch {
            _isLoading.value = true
            try {
                withContext(Dispatchers.IO) {

                    PqcExtensionCore.generatePqcSigningKeypair(context, accountUuid, algorithm)
                }
            } catch (e: Exception) {
                e.printStackTrace()
                _errorMessage.postValue(Event("Fehler beim Generieren: ${e.message}"))
            } finally {
                updateKeyStatus(context)
                _isLoading.value = false
            }
        }
    }


    fun resetKeyPair(context: Context) {
        viewModelScope.launch {
            _isLoading.value = true
            try {
                val id = account?.uuid ?: return@launch
                val registry = KeyRegistryFactory.getRegistry(KeyRegistryFactory.KeyType.PQC_SIG)
                registry.clearKeyPair(context, id)
            } catch (e: Exception) {
                e.printStackTrace()
                _errorMessage.postValue(Event("Fehler beim Zurücksetzen des Schlüsselpaars: ${e.message}"))
            } finally {
                updateKeyStatus(context)
                _isLoading.value = false
            }
        }
    }

    fun exportKeyFile(context: Context, password: String) {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val id = account?.uuid ?: return@launch
                val registry = KeyRegistryFactory.getRegistry(KeyRegistryFactory.KeyType.PQC_SIG)
                registry.loadOwnKeyPair(context, id)
                val jsonString = registry.exportPublicKey(context, id)
                val encrypted = CryptoUtils.encrypt(jsonString, password)

                val exportDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOCUMENTS)
                val file = File(exportDir, "pqkeys_${account?.name}.pqk")
                FileOutputStream(file).use { it.write(encrypted) }
            } catch (e: Exception) {
                e.printStackTrace()
                _errorMessage.postValue(Event("Fehler beim Exportieren: ${e.message}"))
            }
            finally {
                updateKeyStatus(context)
            }
        }
    }

    fun importKeyFile(context: Context, uri: Uri, password: String) {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val inputStream: InputStream = context.contentResolver.openInputStream(uri)
                    ?: throw Exception("Datei konnte nicht geöffnet werden.")
                val decrypted = CryptoUtils.decrypt(inputStream.readBytes(), password)
                val json = JSONObject(decrypted)

                val id = account?.uuid ?: return@launch
                val registry = KeyRegistryFactory.getRegistry(KeyRegistryFactory.KeyType.PQC_SIG)
                registry.setKeyPair(
                    context,
                    id,
                    json.getString("algorithm"),
                    json.getString("publicKey"),
                    json.getString("privateKey")
                )
            } catch (e: Exception) {
                e.printStackTrace()
                _errorMessage.postValue(Event("Fehler beim Importieren: ${e.message}"))
            } finally {
                updateKeyStatus(context)
            }
        }
    }

    fun getPublicKey(context: Context): String? {
        return try {
            val id = account?.uuid ?: return null
            val registry = KeyRegistryFactory.getRegistry(KeyRegistryFactory.KeyType.PQC_SIG)
            registry.loadOwnKeyPair(context, id)
            val json = JSONObject(registry.exportPublicKey(context, id))
            json.optString("publicKey")
        } catch (e: Exception) {
            null
        }
    }

    fun getSecretKey(): String? {
        return null // Kein Zugriff per Interface möglich
    }

    fun getCurrentAlgorithm(): String? = account?.pqcSigningAlgorithm

    data class KeyStatus(
        val publicKey: String?,
        val algorithm: String?
    )

    private fun updateKeyStatus(context: Context) {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val id = account?.uuid ?: return@launch
                val registry = KeyRegistryFactory.getRegistry(KeyRegistryFactory.KeyType.PQC_SIG)
                registry.loadOwnKeyPair(context, id)
                val json = JSONObject(registry.exportPublicKey(context, id))
                _keyStatus.postValue(
                    KeyStatus(
                        publicKey = json.optString("publicKey", null),
                        algorithm = json.optString("algorithm", null)
                    )
                )
            } catch (_: Exception) {
                // Ignoriere Statusfehler still
            }
        }
    }

    fun hasKeyPair(context: Context): Boolean {
        val id = account?.uuid ?: return false
        val registry = KeyRegistryFactory.getRegistry(KeyRegistryFactory.KeyType.PQC_SIG)
        return registry.hasKeyPair(context, id)
    }

    fun sendKeysByEmail(context: Context, recipients: List<String>) {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val id = account?.uuid ?: return@launch
                val accountObj = account ?: return@launch

                val kemRegistry = KeyRegistryFactory.getRegistry(KeyRegistryFactory.KeyType.PQC_KEM)
                val sigRegistry = KeyRegistryFactory.getRegistry(KeyRegistryFactory.KeyType.PQC_SIG)
                val pgpRegistry = KeyRegistryFactory.getRegistry(KeyRegistryFactory.KeyType.PGP)

                if(!sigRegistry.hasKeyPair(context,id)){
                    _errorMessage.postValue(Event("Es ist kein Sig-Schlüssel vorhanden."))
                    return@launch
                }
                if (!pgpRegistry.hasKeyPair(context, id)) {
                    _errorMessage.postValue(Event("Es ist kein PGP-Schlüssel vorhanden."))
                    return@launch
                }
                val pgpKey = try {
                    pgpRegistry.exportPublicKey(context, id)
                } catch (_: Exception) { null }

                if (pgpKey.isNullOrEmpty()) {
                    _errorMessage.postValue(Event("Es konnte kein PGP-Schlüssel geladen werden."))
                    return@launch
                }

                val sigKey = if (sigRegistry.hasKeyPair(context, id)) {
                    JSONObject(sigRegistry.exportPublicKey(context, id))
                } else null

                val kemKey = if (kemRegistry.hasKeyPair(context, id)) {
                    JSONObject(kemRegistry.exportPublicKey(context, id))
                } else null


                KeyDistributor.createAndSendKeyDistributionMessage(
                    context,
                    DI.get(MessagingController::class.java),
                    DI.get(Preferences::class.java),
                    DI.get(Contacts::class.java),
                    accountObj,
                    Address(accountObj.email, accountObj.name),
                    kemKey?.optString("publicKey"),
                    sigKey?.optString("publicKey"),
                    kemKey?.optString("algorithm"),
                    sigKey?.optString("algorithm"),
                    pgpKey,
                    null,
                    "Meine öffentlichen Schlüssel",
                    null,
                    null
                )

            } catch (e: Exception) {
                _errorMessage.postValue(Event("Fehler beim Versenden: ${e.message}"))
            }
            finally {
                updateKeyStatus(context)
            }
        }
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
