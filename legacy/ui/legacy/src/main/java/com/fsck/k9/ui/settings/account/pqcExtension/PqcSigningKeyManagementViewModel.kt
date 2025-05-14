package com.fsck.k9.ui.settings.account.pqcExtension

import android.content.Context
import android.net.Uri
import android.os.Build
import androidx.annotation.RequiresApi
import androidx.lifecycle.*
import app.k9mail.legacy.account.Account
import app.k9mail.legacy.account.AccountManager
import com.fsck.k9.Preferences
import com.fsck.k9.pqcExtension.keyManagement.SimpleKeyStoreFactory
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.InputStream

/**
 * ViewModel for managing PQC signature (PQC-SIG) keys.
 * Handles key generation, deletion, export/import, and status updates for the account.
 */
class PqcSigningKeyManagementViewModel(
    val accountManager: AccountManager,
    private val preferences: Preferences,
    accountUuid: String
) : ViewModel() {

    // Holds current public key and algorithm status
    private val _keyStatus = MutableLiveData<KeyStatus>()
    val keyStatus: LiveData<KeyStatus> = _keyStatus

    // Used to show loading indicators in the UI
    private val _isLoading = MutableLiveData<Boolean>()
    val isLoading: LiveData<Boolean> = _isLoading

    // Single-use messages for UI (e.g., errors or success messages)
    private val _errorMessage = MutableLiveData<Event<String>>()
    val errorMessage: LiveData<Event<String>> = _errorMessage

    // Live list of all accounts for dropdowns or selection
    val accounts = accountManager.getAccountsFlow().asLiveData()

    // The current account this viewmodel is managing
    val account: Account? = try {
        loadAccount(accountUuid).also {
            if (it == null) {
                _errorMessage.postValue(Event("Account not found: $accountUuid"))
            }
        }
    } catch (e: Exception) {
        _errorMessage.postValue(Event("Error while loading account: ${e.message}"))
        null
    }

    private fun loadAccount(accountUuid: String): Account? = accountManager.getAccount(accountUuid)

    /**
     * Generates a PQC signature key pair for the given algorithm.
     * Also ensures a fallback PGP key exists (for hybrid setups).
     */
    @RequiresApi(Build.VERSION_CODES.O)
    fun generateSigningKey(context: Context, accountUuid: String, algorithm: String) {
        viewModelScope.launch {
            _isLoading.value = true
            try {
                withContext(Dispatchers.IO) {
                    val pgpStore = SimpleKeyStoreFactory.getKeyStore(SimpleKeyStoreFactory.KeyType.PGP)
                    if (!pgpStore.hasOwnKeyPair(context, accountUuid)) {
                        pgpStore.generateKeyPair(context, accountUuid, "pgp")
                    }

                    SimpleKeyStoreFactory.getKeyStore(SimpleKeyStoreFactory.KeyType.PQC_SIG)
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

    /**
     * Deletes the PQC-SIG keypair.
     * If `deleteAll` is true, also removes remote keys.
     */
    fun resetKeyPair(context: Context, deleteAll: Boolean) {
        viewModelScope.launch {
            _isLoading.value = true
            try {
                val id = account?.uuid ?: return@launch
                val registry = SimpleKeyStoreFactory.getKeyStore(SimpleKeyStoreFactory.KeyType.PQC_SIG)
                registry.clearAllKeys(context, id, deleteAll)
            } catch (e: Exception) {
                e.printStackTrace()
                _errorMessage.postValue(Event("Error while resetting key pair: ${e.message}"))
            } finally {
                updateKeyStatus(context)
                _isLoading.value = false
            }
        }
    }

    /**
     * Exports the PQC-SIG public key and algorithm to the specified URI in JSON format.
     */
    fun exportKeyFileToUri(context: Context, uri: Uri) {
        viewModelScope.launch {
            try {
                val id = account?.uuid ?: return@launch
                val name = account?.name ?: "account"
                val email = account?.email ?: "unknown@example.com"
                val algorithm = account?.pqcSigningAlgorithm ?: "None"

                val keyStore = SimpleKeyStoreFactory.getKeyStore(SimpleKeyStoreFactory.KeyType.PQC_SIG)
                val publicKey = withContext(Dispatchers.IO) {
                    keyStore.exportPublicKey(context, id)
                }

                val json = JSONObject().apply {
                    put("email", email)
                    put("algorithm", algorithm)
                    put("publicKey", publicKey)
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

    /**
     * Imports a PQC-SIG public key from the given file URI.
     */
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
                val publicKey = json.getString("publicKey")

                val keyStore = SimpleKeyStoreFactory.getKeyStore(SimpleKeyStoreFactory.KeyType.PQC_SIG)
                keyStore.importRemotePublicKey(context, id, email, algorithm, publicKey)

            } catch (e: Exception) {
                e.printStackTrace()
                _errorMessage.postValue(Event("Error while importing: ${e.message}"))
            } finally {
                updateKeyStatus(context)
            }
        }
    }

    /**
     * Returns the current public key as a string if available.
     */
    fun getPublicKey(context: Context): String? {
        return try {
            val id = account?.uuid ?: return null
            val keyStore = SimpleKeyStoreFactory.getKeyStore(SimpleKeyStoreFactory.KeyType.PQC_SIG)
            keyStore.exportPublicKey(context, id)
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Returns the current selected PQC signature algorithm.
     */
    fun getCurrentAlgorithm(): String? = account?.pqcSigningAlgorithm

    /**
     * Holds current key metadata for UI display.
     */
    data class KeyStatus(
        val publicKey: String?,
        val algorithm: String?
    )

    /**
     * Updates the current key status LiveData based on stored state.
     */
    private fun updateKeyStatus(context: Context) {
        viewModelScope.launch(Dispatchers.IO) {
            val id = account?.uuid ?: return@launch
            val algorithm = account?.pqcSigningAlgorithm ?: return@launch

            val keyStore = SimpleKeyStoreFactory.getKeyStore(SimpleKeyStoreFactory.KeyType.PQC_SIG)
            val publicKey = keyStore.exportPublicKey(context, id)

            _keyStatus.postValue(
                KeyStatus(
                    publicKey = publicKey,
                    algorithm = algorithm
                )
            )
        }
    }

    /**
     * Checks if a PQC-SIG keypair is stored locally.
     */
    fun hasKeyPair(context: Context): Boolean {
        val id = account?.uuid ?: return false
        val keyStore = SimpleKeyStoreFactory.getKeyStore(SimpleKeyStoreFactory.KeyType.PQC_SIG)
        return keyStore.hasOwnKeyPair(context, id)
    }

    /**
     * Wrapper for one-time use events such as Toasts or Snack bars to prevent duplicate consumption.
     */
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

