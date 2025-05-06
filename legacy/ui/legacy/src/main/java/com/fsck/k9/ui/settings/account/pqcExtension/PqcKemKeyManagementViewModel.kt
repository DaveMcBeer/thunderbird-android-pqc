package com.fsck.k9.ui.settings.account.pqcExtension

import android.content.Context
import android.net.Uri
import android.os.Build
import android.os.Environment
import androidx.activity.result.contract.ActivityResultContracts
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
import com.fsck.k9.pqcExtension.keyManagement.SimpleKeyStoreFactory
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import java.io.InputStream

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

    val account: Account? = try {
        accountManager.getAccount(accountUuid)
    } catch (e: Exception) {
        _errorMessage.postValue(Event("Fehler beim Laden des Accounts: \${e.message}"))
        null
    }

    @RequiresApi(Build.VERSION_CODES.O)
    fun generatePqcKemKeyPair(context: Context, accountUuid: String, algorithm: String) {
        viewModelScope.launch {
            _isLoading.value = true
            try {
                withContext(Dispatchers.IO) {
                    val pgpStore = SimpleKeyStoreFactory.getKeyStore(SimpleKeyStoreFactory.KeyType.PGP)
                    if (!pgpStore.hasOwnKeyPair(context, accountUuid)) {
                        pgpStore.generateKeyPair(context, accountUuid, "pgp") // oder leerer Algo-String, wenn intern fix
                    }

                    SimpleKeyStoreFactory.getKeyStore(SimpleKeyStoreFactory.KeyType.PQC_KEM)
                        .generateKeyPair(context, accountUuid, algorithm)

                }
            } catch (e: Exception) {
                e.printStackTrace()
                _errorMessage.postValue(Event("Error while generating: ${e.message}"))
            } finally {
                updateKeyStatus(context)
                _isLoading.value = false
            }
        }
    }

    fun resetKeyPair(context: Context, deleteAll: Boolean) {
        viewModelScope.launch {
            _isLoading.value = true
            try {
                val id = account?.uuid ?: return@launch
                val keyStore = SimpleKeyStoreFactory.getKeyStore(SimpleKeyStoreFactory.KeyType.PQC_KEM)
                keyStore.clearAllKeys(context, id, deleteAll)
            } catch (e: Exception) {
                _errorMessage.postValue(Event("Error while resetting: ${e.message}"))
            } finally {
                updateKeyStatus(context)
                _isLoading.value = false
            }
        }
    }

    fun exportKeyFileToUri(context: Context, uri: Uri) {
        viewModelScope.launch {
            try {
                val id = account?.uuid ?: return@launch
                val name = account?.name ?: "account"
                val email = account?.email ?: "unknown@example.com"
                val algorithm = account?.pqcKemAlgorithm ?: "None"

                val keyStore = SimpleKeyStoreFactory.getKeyStore(SimpleKeyStoreFactory.KeyType.PQC_KEM)
                val publicKey = withContext(Dispatchers.IO) {
                    keyStore.exportPublicKey(context, id)
                }

                val json = JSONObject().apply {
                    put("email", email)
                    put("algorithm", algorithm)
                    put("pqc_kem_publicKey", publicKey)
                }

                context.contentResolver.openOutputStream(uri)?.use { output ->
                    output.write(json.toString().toByteArray())
                } ?: throw Exception("Could not open output stream")

                _errorMessage.postValue(Event("Key export successful"))
            } catch (e: Exception) {
                e.printStackTrace()
                _errorMessage.postValue(Event("Error while exporting: ${e.message}"))
            } finally {
                updateKeyStatus(context)
            }
        }
    }

    fun importKeyFile(context: Context, uri: Uri) {
        viewModelScope.launch {
            try {
                val id = account?.uuid ?: return@launch

                val json = withContext(Dispatchers.IO) {
                    val inputStream: InputStream = context.contentResolver.openInputStream(uri)
                        ?: throw Exception("Could not open file.")
                    val content = inputStream.bufferedReader().use { it.readText() }
                    JSONObject(content)
                }

                val email = json.getString("email")
                val algorithm = json.getString("algorithm")

                val (keyType, publicKeyField) = when {
                    json.has("pqc_kem_publicKey") -> SimpleKeyStoreFactory.KeyType.PQC_KEM to "pqc_kem_publicKey"
                    json.has("pqc_sig_publicKey") -> SimpleKeyStoreFactory.KeyType.PQC_SIG to "pqc_sig_publicKey"
                    json.has("pgp_publicKey")     -> SimpleKeyStoreFactory.KeyType.PGP     to "pgp_publicKey"
                    json.has("publicKey")         -> SimpleKeyStoreFactory.KeyType.PQC_KEM to "publicKey" // fallback
                    else -> throw Exception("Unrecognized key format")
                }

                val publicKey = json.getString(publicKeyField)
                val keyStore = SimpleKeyStoreFactory.getKeyStore(keyType)
                keyStore.importRemotePublicKey(context, id, email, algorithm, publicKey)

                _errorMessage.postValue(Event("Key import successful"))
            } catch (e: Exception) {
                e.printStackTrace()
                _errorMessage.postValue(Event("Error while importing: ${e.message}"))
            } finally {
                updateKeyStatus(context)
            }
        }
    }

    fun getPublicKey(context: Context): String? {
        return try {
            val id = account?.uuid ?: return null
            val keyStore = SimpleKeyStoreFactory.getKeyStore(SimpleKeyStoreFactory.KeyType.PQC_KEM)
            keyStore.exportPublicKey(context, id)
        } catch (e: Exception) {
            null
        }
    }

    fun getCurrentAlgorithm(): String? = account?.pqcKemAlgorithm

    data class KeyStatus(
        val publicKey: String?,
        val algorithm: String?
    )

    private fun updateKeyStatus(context: Context) {
        viewModelScope.launch(Dispatchers.IO) {
            val id = account?.uuid ?: return@launch
            val algorithm = account?.pqcKemAlgorithm ?: return@launch

            val keyStore = SimpleKeyStoreFactory.getKeyStore(SimpleKeyStoreFactory.KeyType.PQC_KEM)
            val publicKey = keyStore.exportPublicKey(context, id)

            _keyStatus.postValue(
                KeyStatus(
                    publicKey = publicKey,
                    algorithm = algorithm
                )
            )
        }
    }

    fun hasKeyPair(context: Context): Boolean {
        val id = account?.uuid ?: return false
        val keyStore = SimpleKeyStoreFactory.getKeyStore(SimpleKeyStoreFactory.KeyType.PQC_KEM)
        return keyStore.hasOwnKeyPair(context, id)
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
}
