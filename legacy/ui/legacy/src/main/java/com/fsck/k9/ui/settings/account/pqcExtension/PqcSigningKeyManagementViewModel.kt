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
import com.fsck.k9.pqcExtension.keyManagement.SimpleKeyStoreFactory
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
                    val pgpStore = SimpleKeyStoreFactory.getKeyStore(SimpleKeyStoreFactory.KeyType.PGP)
                    if (!pgpStore.hasOwnKeyPair(context, accountUuid)) {
                        pgpStore.generateKeyPair(context, accountUuid, "pgp") // oder leerer Algo-String, wenn intern fix
                    }

                    SimpleKeyStoreFactory.getKeyStore(SimpleKeyStoreFactory.KeyType.PQC_SIG)
                        .generateKeyPair(context, accountUuid, algorithm)
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
                val registry = SimpleKeyStoreFactory.getKeyStore(
                    SimpleKeyStoreFactory.KeyType.PQC_SIG)
                registry.clearAllKeys(context, id)
            } catch (e: Exception) {
                e.printStackTrace()
                _errorMessage.postValue(Event("Fehler beim Zurücksetzen des Schlüsselpaars: ${e.message}"))
            } finally {
                updateKeyStatus(context)
                _isLoading.value = false
            }
        }
    }

    fun exportKeyFile(context: Context) {
        viewModelScope.launch {
            try {
                val id = account?.uuid ?: return@launch
                val name = account?.name ?: "account"
                val email = account?.email ?: "unknown@example.com"
                val safeName = name.replace("[^a-zA-Z0-9-_]".toRegex(), "_")

                val keyStore = SimpleKeyStoreFactory.getKeyStore(SimpleKeyStoreFactory.KeyType.PQC_SIG)
                val publicKey = withContext(Dispatchers.IO) {
                    keyStore.exportPublicKey(context, id)
                }

                // Aktuell festgelegter Algorithmus (je nach UI z. B. gespeichert in `account.pqcSigningAlgorithm`)
                val algorithm = account?.pqcSigningAlgorithm ?: "None"

                val json = JSONObject().apply {
                    put("email", email)
                    put("algorithm", algorithm)
                    put("publicKey", publicKey)
                }

                val exportDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOCUMENTS)
                if (!exportDir.exists()) exportDir.mkdirs()

                val file = File(exportDir, "pqkeys_${safeName}.pqk")
                FileOutputStream(file).use { it.write(json.toString().toByteArray()) }

            } catch (e: Exception) {
                e.printStackTrace()
                _errorMessage.postValue(Event("Fehler beim Exportieren: ${e.message}"))
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
                        ?: throw Exception("Datei konnte nicht geöffnet werden.")
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
                _errorMessage.postValue(Event("Fehler beim Importieren: ${e.message}"))
            } finally {
                updateKeyStatus(context)
            }
        }
    }


    fun getPublicKey(context: Context): String? {
        return try {
            val id = account?.uuid ?: return null
            val keyStore = SimpleKeyStoreFactory.getKeyStore(SimpleKeyStoreFactory.KeyType.PQC_SIG)
            keyStore.exportPublicKey(context, id)
        } catch (e: Exception) {
            null
        }
    }

    fun getCurrentAlgorithm(): String? = account?.pqcSigningAlgorithm

    data class KeyStatus(
        val publicKey: String?,
        val algorithm: String?
    )

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


    fun hasKeyPair(context: Context): Boolean {
        val id = account?.uuid ?: return false
        val keyStore = SimpleKeyStoreFactory.getKeyStore(SimpleKeyStoreFactory.KeyType.PQC_SIG)
        return keyStore.hasOwnKeyPair(context, id)
    }


    fun sendKeysByEmail(context: Context, recipients: List<String>) {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val id = account?.uuid ?: return@launch
                val accountObj = account ?: return@launch

                val sigStore = SimpleKeyStoreFactory.getKeyStore(SimpleKeyStoreFactory.KeyType.PQC_SIG)
                val kemStore = SimpleKeyStoreFactory.getKeyStore(SimpleKeyStoreFactory.KeyType.PQC_KEM)
                val pgpStore = SimpleKeyStoreFactory.getKeyStore(SimpleKeyStoreFactory.KeyType.PGP)

                if (!sigStore.hasOwnKeyPair(context, id)) {
                    _errorMessage.postValue(Event("Es ist kein Signaturschlüssel vorhanden."))
                    return@launch
                }
                if (!pgpStore.hasOwnKeyPair(context, id)) {
                    _errorMessage.postValue(Event("Es ist kein PGP-Schlüssel vorhanden."))
                    return@launch
                }

                val pgpKey = pgpStore.exportPublicKey(context, id)
                if (pgpKey.isNullOrEmpty()) {
                    _errorMessage.postValue(Event("Es konnte kein PGP-Schlüssel geladen werden."))
                    return@launch
                }

                val sigKey = sigStore.exportPublicKey(context, id)
                val sigAlgo = accountObj.pqcSigningAlgorithm

                val kemKey = if (kemStore.hasOwnKeyPair(context, id)) {
                    kemStore.exportPublicKey(context, id)
                } else null
                val kemAlgo = accountObj.pqcKemAlgorithm

                KeyDistributor.createAndSendKeyDistributionMessage(
                    context,
                    DI.get(MessagingController::class.java),
                    DI.get(Preferences::class.java),
                    DI.get(Contacts::class.java),
                    accountObj,
                    recipients,
                    kemKey,
                    sigKey,
                    kemAlgo,
                    sigAlgo,
                    pgpKey,
                    null,
                    "Meine öffentlichen Schlüssel",
                    null,
                    null
                )

            } catch (e: Exception) {
                _errorMessage.postValue(Event("Fehler beim Versenden: ${e.message}"))
            } finally {
                updateKeyStatus(context)
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
}

