package com.fsck.k9.ui.settings.account

import android.content.Context
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import androidx.lifecycle.asLiveData
import androidx.lifecycle.viewModelScope
import app.k9mail.core.mail.folder.api.FolderType
import app.k9mail.legacy.account.Account
import app.k9mail.legacy.account.AccountManager
import app.k9mail.legacy.di.DI
import app.k9mail.legacy.folder.RemoteFolder
import app.k9mail.legacy.mailstore.FolderRepository
import com.fsck.k9.controller.MessagingController
import com.fsck.k9.helper.Contacts
import com.fsck.k9.mailstore.SpecialFolderSelectionStrategy
import com.fsck.k9.pqcExtension.KeyDistribution.KeyDistributor
import com.fsck.k9.pqcExtension.keyManagement.SimpleKeyStoreFactory
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import com.fsck.k9.Preferences

class AccountSettingsViewModel(
    private val accountManager: AccountManager,
    private val folderRepository: FolderRepository,
    private val specialFolderSelectionStrategy: SpecialFolderSelectionStrategy,
    private val backgroundDispatcher: CoroutineDispatcher = Dispatchers.IO,
) : ViewModel() {
    val accounts = accountManager.getAccountsFlow().asLiveData()
    private var accountUuid: String? = null
    private val accountLiveData = MutableLiveData<Account?>()
    private val foldersLiveData = MutableLiveData<RemoteFolderInfo>()

    fun getAccount(accountUuid: String): LiveData<Account?> {
        if (this.accountUuid != accountUuid) {
            this.accountUuid = accountUuid
            viewModelScope.launch {
                val account = withContext(backgroundDispatcher) {
                    loadAccount(accountUuid)
                }
                accountLiveData.value = account
            }
        }

        return accountLiveData
    }

    /**
     * Returns the cached [Account] if possible. Otherwise does a blocking load because `PreferenceFragmentCompat`
     * doesn't support asynchronous preference loading.
     */
    fun getAccountBlocking(accountUuid: String): Account {
        return accountLiveData.value
            ?: loadAccount(accountUuid).also { account ->
                this.accountUuid = accountUuid
                accountLiveData.value = account
            }
            ?: error("Account $accountUuid not found")
    }

    private fun loadAccount(accountUuid: String): Account? {
        return accountManager.getAccount(accountUuid)
    }

    fun getFolders(account: Account): LiveData<RemoteFolderInfo> {
        if (foldersLiveData.value == null) {
            loadFolders(account)
        }

        return foldersLiveData
    }

    private fun loadFolders(account: Account) {
        viewModelScope.launch {
            val remoteFolderInfo = withContext(backgroundDispatcher) {
                val folders = folderRepository.getRemoteFolders(account)
                    .sortedWith(
                        compareByDescending<RemoteFolder> { it.type == FolderType.INBOX }
                            .thenBy(String.CASE_INSENSITIVE_ORDER) { it.name },
                    )

                val automaticSpecialFolders = getAutomaticSpecialFolders(folders)
                RemoteFolderInfo(folders, automaticSpecialFolders)
            }
            foldersLiveData.value = remoteFolderInfo
        }
    }

    private fun getAutomaticSpecialFolders(folders: List<RemoteFolder>): Map<FolderType, RemoteFolder?> {
        return mapOf(
            FolderType.ARCHIVE to specialFolderSelectionStrategy.selectSpecialFolder(folders, FolderType.ARCHIVE),
            FolderType.DRAFTS to specialFolderSelectionStrategy.selectSpecialFolder(folders, FolderType.DRAFTS),
            FolderType.SENT to specialFolderSelectionStrategy.selectSpecialFolder(folders, FolderType.SENT),
            FolderType.SPAM to specialFolderSelectionStrategy.selectSpecialFolder(folders, FolderType.SPAM),
            FolderType.TRASH to specialFolderSelectionStrategy.selectSpecialFolder(folders, FolderType.TRASH),
        )
    }

    //--- PQC Extension ---
    fun sendPqcKeysByEmail(context: Context, account: Account, recipients: List<String>) {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val sigStore = SimpleKeyStoreFactory.getKeyStore(SimpleKeyStoreFactory.KeyType.PQC_SIG)
                val kemStore = SimpleKeyStoreFactory.getKeyStore(SimpleKeyStoreFactory.KeyType.PQC_KEM)
                val pgpStore = SimpleKeyStoreFactory.getKeyStore(SimpleKeyStoreFactory.KeyType.PGP)

                val id = account.uuid

                if (!sigStore.hasOwnKeyPair(context, id)) return@launch
                if (!pgpStore.hasOwnKeyPair(context, id)) return@launch

                val pgpKey = pgpStore.exportPublicKey(context, id) ?: return@launch
                val sigKey = sigStore.exportPublicKey(context, id)
                val kemKey = if (kemStore.hasOwnKeyPair(context, id)) kemStore.exportPublicKey(context, id) else null

                KeyDistributor.createAndSendKeyDistributionMessage(
                    context,
                    DI.get(MessagingController::class.java),
                    DI.get(Preferences::class.java),
                    DI.get(Contacts::class.java),
                    account,
                    recipients,
                    kemKey,
                    sigKey,
                    account.pqcKemAlgorithm,
                    account.pqcSigningAlgorithm,
                    pgpKey,
                    null,
                    "My public keys",
                    null,
                    null
                )
            } catch (e: Exception) {
                e.printStackTrace()
            }
        }
    }

    //--- END ---
}

data class RemoteFolderInfo(
    val folders: List<RemoteFolder>,
    val automaticSpecialFolders: Map<FolderType, RemoteFolder?>,
)
