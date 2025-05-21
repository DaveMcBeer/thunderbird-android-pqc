package com.fsck.k9.ui.settings.account

import android.annotation.SuppressLint
import android.app.AlertDialog
import android.app.ProgressDialog
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.text.InputType
import android.view.Menu
import android.view.MenuInflater
import android.view.MenuItem
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.Toast
import androidx.core.net.toUri
import androidx.preference.ListPreference
import androidx.preference.Preference
import androidx.preference.PreferenceCategory
import androidx.preference.SwitchPreference
import app.k9mail.core.common.provider.AppNameProvider
import app.k9mail.core.mail.folder.api.FolderType
import app.k9mail.feature.launcher.FeatureLauncherActivity
import app.k9mail.feature.launcher.FeatureLauncherTarget
import app.k9mail.legacy.account.Account
import app.k9mail.legacy.folder.RemoteFolder
import com.fsck.k9.account.BackgroundAccountRemover
import com.fsck.k9.activity.ManageIdentities
import com.fsck.k9.activity.setup.AccountSetupComposition
import com.fsck.k9.controller.MessagingController
import com.fsck.k9.crypto.OpenPgpApiHelper
import com.fsck.k9.fragment.ConfirmationDialogFragment
import com.fsck.k9.fragment.ConfirmationDialogFragment.ConfirmationDialogFragmentListener
import com.fsck.k9.notification.NotificationChannelManager
import com.fsck.k9.notification.NotificationChannelManager.ChannelType
import com.fsck.k9.notification.NotificationSettingsUpdater
import com.fsck.k9.pqcExtension.keyManagement.SimpleKeyStoreFactory
import com.fsck.k9.pqcExtension.keyManagement.service.SimpleKeyService
import com.fsck.k9.ui.R
import com.fsck.k9.ui.base.extensions.withArguments
import com.fsck.k9.ui.endtoend.AutocryptKeyTransferActivity
import com.fsck.k9.ui.settings.account.pqcExtension.PqcKemKeyManagementFragment
import com.fsck.k9.ui.settings.account.pqcExtension.PqcSigningKeyManagementFragment
import com.fsck.k9.ui.settings.account.pqcExtension.benchmark.PQCBenchmarkRunner
import com.fsck.k9.ui.settings.onClick
import com.fsck.k9.ui.settings.oneTimeClickListener
import com.fsck.k9.ui.settings.remove
import com.fsck.k9.ui.settings.removeEntry
import com.google.android.material.snackbar.Snackbar
import com.takisoft.preferencex.PreferenceFragmentCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.koin.android.ext.android.inject
import org.koin.androidx.viewmodel.ext.android.activityViewModel
import org.koin.core.parameter.parametersOf
import org.openintents.openpgp.OpenPgpApiManager
import org.openintents.openpgp.util.OpenPgpKeyPreference
import org.openintents.openpgp.util.OpenPgpProviderUtil
import com.fsck.k9.ui.base.R as BaseR

class AccountSettingsFragment : PreferenceFragmentCompat(), ConfirmationDialogFragmentListener {
    private val viewModel: AccountSettingsViewModel by activityViewModel()
    private val dataStoreFactory: AccountSettingsDataStoreFactory by inject()
    private val openPgpApiManager: OpenPgpApiManager by inject { parametersOf(this) }
    private val messagingController: MessagingController by inject()
    private val accountRemover: BackgroundAccountRemover by inject()
    private val notificationChannelManager: NotificationChannelManager by inject()
    private val notificationSettingsUpdater: NotificationSettingsUpdater by inject()
    private val vibrator: Vibrator by inject()
    private val appNameProvider: AppNameProvider by inject()

    private lateinit var dataStore: AccountSettingsDataStore

    private var notificationSoundPreference: NotificationSoundPreference? = null
    private var notificationLightPreference: ListPreference? = null
    private var notificationVibrationPreference: VibrationPreference? = null

    private val accountUuid: String by lazy {
        checkNotNull(arguments?.getString(ARG_ACCOUNT_UUID)) { "$ARG_ACCOUNT_UUID == null" }
    }
    private var title: CharSequence? = null

    override fun onCreatePreferencesFix(savedInstanceState: Bundle?, rootKey: String?) {
        val account = getAccount()
        dataStore = dataStoreFactory.create(account)

        preferenceManager.preferenceDataStore = dataStore
        setPreferencesFromResource(R.xml.account_settings, rootKey)
        title = preferenceScreen.title
        setHasOptionsMenu(true)

        initializeIncomingServer()
        initializeComposition()
        initializeManageIdentities()
        initializeUploadSentMessages(account)
        initializeOutgoingServer()
        initializeQuoteStyle()
        initializeDeletePolicy(account)
        initializeExpungePolicy(account)
        initializeMessageAge(account)
        initializeAdvancedPushSettings(account)
        initializeCryptoSettings(account)
        initializeFolderSettings(account)
        initializeNotifications(account)

        //--- PQC Addition ---
        initializePqcSigningKeyManagement()
        initializePqcKemKeyManagement()
        initializeInternalKeyDeletion()
        initializePqcSendKeys()
        initializePgpKeyGeneration()
        initializePqcBenchmarkRunner()
        //--- END ---
    }

    override fun onActivityCreated(savedInstanceState: Bundle?) {
        super.onActivityCreated(savedInstanceState)
        requireActivity().title = title
    }

    override fun onResume() {
        super.onResume()

        // we might be returning from OpenPgpAppSelectDialog, make sure settings are up to date
        val account = getAccount()
        initializeCryptoSettings(account)
        initializePqcSendKeys()
        // Don't update the notification preferences when resuming after the user has selected a new notification sound
        // via NotificationSoundPreference. Otherwise we race the background thread and might read data from the old
        // NotificationChannel, overwriting the notification sound with the previous value.
        notificationSoundPreference?.let { notificationSoundPreference ->
            if (notificationSoundPreference.receivedActivityResultJustNow) {
                notificationSoundPreference.receivedActivityResultJustNow = false
            } else {
                maybeUpdateNotificationPreferences(account)
            }
        }
    }

    override fun onCreateOptionsMenu(menu: Menu, inflater: MenuInflater) {
        super.onCreateOptionsMenu(menu, inflater)
        inflater.inflate(R.menu.account_settings_option, menu)
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            R.id.delete_account -> {
                onDeleteAccount()
                true
            }

            else -> super.onOptionsItemSelected(item)
        }
    }

    private fun initializeIncomingServer() {
        findPreference<Preference>(PREFERENCE_INCOMING_SERVER)?.onClick {
            FeatureLauncherActivity.launch(
                context = requireActivity(),
                target = FeatureLauncherTarget.AccountEditIncomingSettings(accountUuid),
            )
        }
    }

    private fun initializeComposition() {
        findPreference<Preference>(PREFERENCE_COMPOSITION)?.onClick {
            AccountSetupComposition.actionEditCompositionSettings(requireActivity(), accountUuid)
        }
    }

    private fun initializeManageIdentities() {
        findPreference<Preference>(PREFERENCE_MANAGE_IDENTITIES)?.onClick {
            ManageIdentities.start(requireActivity(), accountUuid)
        }
    }

    private fun initializeUploadSentMessages(account: Account) {
        findPreference<Preference>(PREFERENCE_UPLOAD_SENT_MESSAGES)?.apply {
            if (!messagingController.supportsUpload(account)) {
                remove()
            }
        }
    }

    private fun initializeOutgoingServer() {
        findPreference<Preference>(PREFERENCE_OUTGOING_SERVER)?.onClick {
            FeatureLauncherActivity.launch(
                context = requireActivity(),
                target = FeatureLauncherTarget.AccountEditOutgoingSettings(accountUuid),
            )
        }
    }

    private fun initializeQuoteStyle() {
        findPreference<Preference>(PREFERENCE_QUOTE_STYLE)?.apply {
            setOnPreferenceChangeListener { _, newValue ->
                val quoteStyle = Account.QuoteStyle.valueOf(newValue.toString())
                notifyDependencyChange(quoteStyle == Account.QuoteStyle.HEADER)
                true
            }
        }
    }

    private fun initializeDeletePolicy(account: Account) {
        (findPreference(PREFERENCE_DELETE_POLICY) as? ListPreference)?.apply {
            if (!messagingController.supportsFlags(account)) {
                removeEntry(DELETE_POLICY_MARK_AS_READ)
            }
        }
    }

    private fun initializeExpungePolicy(account: Account) {
        findPreference<Preference>(PREFERENCE_EXPUNGE_POLICY)?.apply {
            if (!messagingController.supportsExpunge(account)) {
                remove()
            }
        }
    }

    private fun initializeMessageAge(account: Account) {
        findPreference<Preference>(PREFERENCE_MESSAGE_AGE)?.apply {
            if (!messagingController.supportsSearchByDate(account)) {
                remove()
            }
        }
    }

    private fun initializeAdvancedPushSettings(account: Account) {
        if (!messagingController.isPushCapable(account)) {
            findPreference<Preference>(PREFERENCE_ADVANCED_PUSH_SETTINGS)?.remove()
        }
    }

    private fun initializeNotifications(account: Account) {
        if (!vibrator.hasVibrator) {
            findPreference<Preference>(PREFERENCE_NOTIFICATION_VIBRATION)?.remove()
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            findPreference<NotificationSoundPreference>(PREFERENCE_NOTIFICATION_SOUND)?.let { preference ->
                notificationSoundPreference = preference
            }

            findPreference<ListPreference>(PREFERENCE_NOTIFICATION_LIGHT)?.let { preference ->
                notificationLightPreference = preference
            }

            findPreference<VibrationPreference>(PREFERENCE_NOTIFICATION_VIBRATION)?.let { preference ->
                notificationVibrationPreference = preference
            }

            findPreference<NotificationsPreference>(PREFERENCE_NOTIFICATION_SETTINGS_MESSAGES)?.let {
                it.notificationChannelIdProvider = {
                    notificationChannelManager.getChannelIdFor(account, ChannelType.MESSAGES)
                }
            }

            findPreference<NotificationsPreference>(PREFERENCE_NOTIFICATION_SETTINGS_MISCELLANEOUS)?.let {
                it.notificationChannelIdProvider = {
                    notificationChannelManager.getChannelIdFor(account, ChannelType.MISCELLANEOUS)
                }
            }

            updateNotificationPreferences(account)
        } else {
            findPreference<PreferenceCategory>(PREFERENCE_NOTIFICATION_CHANNELS).remove()
        }
    }


    private fun maybeUpdateNotificationPreferences(account: Account) {
        if (notificationSoundPreference != null ||
            notificationLightPreference != null ||
            notificationVibrationPreference != null
        ) {
            updateNotificationPreferences(account)
        }
    }

    @SuppressLint("NewApi")
    private fun updateNotificationPreferences(account: Account) {
        notificationSettingsUpdater.updateNotificationSettings(account)
        val notificationSettings = account.notificationSettings

        notificationSoundPreference?.setNotificationSound(notificationSettings.ringtone?.toUri())

        notificationLightPreference?.value = notificationSettings.light.name

        notificationVibrationPreference?.let { preference ->
            val notificationVibration = notificationSettings.vibration
            preference.setVibration(
                isVibrationEnabled = notificationVibration.isEnabled,
                vibratePattern = notificationVibration.pattern,
                vibrationTimes = notificationVibration.repeatCount,
            )
        }
    }

    private fun initializeCryptoSettings(account: Account) {
        findPreference<Preference>(PREFERENCE_OPENPGP)?.let {
            configureCryptoPreferences(account)
        }
    }

    private fun configureCryptoPreferences(account: Account) {
        var pgpProviderName: String? = null
        var pgpProvider = account.openPgpProvider
        val isPgpConfigured = pgpProvider != null

        if (isPgpConfigured) {
            pgpProviderName = getOpenPgpProviderName(pgpProvider)
            if (pgpProviderName == null) {
                Toast.makeText(requireContext(), R.string.account_settings_openpgp_missing, Toast.LENGTH_LONG).show()

                pgpProvider = null
                removeOpenPgpProvider(account)
            }
        }

        configureEnablePgpSupport(account, isPgpConfigured, pgpProviderName)
        configurePgpKey(account, pgpProvider)
        configureAutocryptTransfer(account)
    }

    private fun getOpenPgpProviderName(pgpProvider: String?): String? {
        val packageManager = requireActivity().packageManager
        return OpenPgpProviderUtil.getOpenPgpProviderName(packageManager, pgpProvider)
    }

    private fun configureEnablePgpSupport(account: Account, isPgpConfigured: Boolean, pgpProviderName: String?) {
        (findPreference<Preference>(PREFERENCE_OPENPGP_ENABLE) as SwitchPreference).apply {
            if (!isPgpConfigured) {
                isChecked = false
                setSummary(R.string.account_settings_crypto_summary_off)
                oneTimeClickListener(clickHandled = false) {
                    val context = requireContext().applicationContext
                    val openPgpProviderPackages = OpenPgpProviderUtil.getOpenPgpProviderPackages(context)
                    if (openPgpProviderPackages.size == 1) {
                        setOpenPgpProvider(account, openPgpProviderPackages[0])
                        configureCryptoPreferences(account)
                    } else {
                        summary = getString(R.string.account_settings_crypto_summary_config)
                        OpenPgpAppSelectDialog.startOpenPgpChooserActivity(requireActivity(), account)
                    }
                }
            } else {
                isChecked = true
                summary = getString(R.string.account_settings_crypto_summary_on, pgpProviderName)
                oneTimeClickListener {
                    removeOpenPgpProvider(account)
                    configureCryptoPreferences(account)
                }
            }
        }
    }

    private fun configurePgpKey(account: Account, pgpProvider: String?) {
        (findPreference<Preference>(PREFERENCE_OPENPGP_KEY) as OpenPgpKeyPreference).apply {
            value = account.openPgpKey
            setOpenPgpProvider(openPgpApiManager, pgpProvider)
            setIntentSenderFragment(this@AccountSettingsFragment)
            setDefaultUserId(OpenPgpApiHelper.buildUserId(account.getIdentity(0)))
            setShowAutocryptHint(true)
        }
    }

    private fun configureAutocryptTransfer(account: Account) {
        findPreference<Preference>(PREFERENCE_AUTOCRYPT_TRANSFER)!!.onClick {
            val intent = AutocryptKeyTransferActivity.createIntent(requireContext(), account.uuid)
            startActivity(intent)
        }
    }

    private fun initializeFolderSettings(account: Account) {
        findPreference<Preference>(PREFERENCE_FOLDERS)?.let {
            if (!messagingController.supportsFolderSubscriptions(account)) {
                findPreference<Preference>(PREFERENCE_SUBSCRIBED_FOLDERS_ONLY).remove()
            }

            if (!messagingController.isMoveCapable(account)) {
                findPreference<Preference>(PREFERENCE_ARCHIVE_FOLDER).remove()
                findPreference<Preference>(PREFERENCE_DRAFTS_FOLDER).remove()
                findPreference<Preference>(PREFERENCE_SENT_FOLDER).remove()
                findPreference<Preference>(PREFERENCE_SPAM_FOLDER).remove()
                findPreference<Preference>(PREFERENCE_TRASH_FOLDER).remove()
            }

            loadFolders(account)
        }
    }

    private fun loadFolders(account: Account) {
        viewModel.getFolders(account).observe(this@AccountSettingsFragment) { remoteFolderInfo ->
            if (remoteFolderInfo != null) {
                setFolders(PREFERENCE_AUTO_EXPAND_FOLDER, remoteFolderInfo.folders)
                setFolders(PREFERENCE_ARCHIVE_FOLDER, remoteFolderInfo, FolderType.ARCHIVE)
                setFolders(PREFERENCE_DRAFTS_FOLDER, remoteFolderInfo, FolderType.DRAFTS)
                setFolders(PREFERENCE_SENT_FOLDER, remoteFolderInfo, FolderType.SENT)
                setFolders(PREFERENCE_SPAM_FOLDER, remoteFolderInfo, FolderType.SPAM)
                setFolders(PREFERENCE_TRASH_FOLDER, remoteFolderInfo, FolderType.TRASH)
            }
        }
    }

    private fun setFolders(preferenceKey: String, folders: List<RemoteFolder>) {
        val folderListPreference = findPreference(preferenceKey) as? FolderListPreference ?: return
        folderListPreference.setFolders(folders)
    }

    private fun setFolders(preferenceKey: String, remoteFolderInfo: RemoteFolderInfo, type: FolderType?) {
        val folderListPreference = findPreference(preferenceKey) as? FolderListPreference ?: return

        val automaticFolder = remoteFolderInfo.automaticSpecialFolders[type]
        folderListPreference.setFolders(remoteFolderInfo.folders, automaticFolder)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        val openPgpKeyPreference = findPreference(PREFERENCE_OPENPGP_KEY) as? OpenPgpKeyPreference
        if (openPgpKeyPreference?.handleOnActivityResult(requestCode, resultCode, data) == true) {
            return
        }
        super.onActivityResult(requestCode, resultCode, data)
    }

    private fun getAccount(): Account {
        return viewModel.getAccountBlocking(accountUuid)
    }

    private fun onDeleteAccount() {
        val dialogFragment = ConfirmationDialogFragment.newInstance(
            DIALOG_DELETE_ACCOUNT,
            getString(R.string.account_delete_dlg_title),
            getString(R.string.account_delete_dlg_instructions_fmt, getAccount().displayName, appNameProvider.appName),
            getString(BaseR.string.okay_action),
            getString(BaseR.string.cancel_action),
        )
        dialogFragment.setTargetFragment(this, REQUEST_DELETE_ACCOUNT)
        dialogFragment.show(requireFragmentManager(), TAG_DELETE_ACCOUNT_CONFIRMATION)
    }

    override fun doPositiveClick(dialogId: Int) {
        closeAccountSettings()
        accountRemover.removeAccountAsync(accountUuid)
    }

    override fun doNegativeClick(dialogId: Int) = Unit

    override fun dialogCancelled(dialogId: Int) = Unit

    private fun closeAccountSettings() {
        requireActivity().finish()
    }

    private fun setOpenPgpProvider(account: Account, openPgpProviderPackage: String) {
        account.openPgpProvider = openPgpProviderPackage
        dataStore.saveSettingsInBackground()
    }

    private fun removeOpenPgpProvider(account: Account) {
        account.openPgpProvider = null
        account.openPgpKey = Account.NO_OPENPGP_KEY
        dataStore.saveSettingsInBackground()
    }

    companion object {
        internal const val PREFERENCE_OPENPGP = "openpgp"
        private const val ARG_ACCOUNT_UUID = "accountUuid"
        private const val PREFERENCE_INCOMING_SERVER = "incoming"
        private const val PREFERENCE_COMPOSITION = "composition"
        private const val PREFERENCE_MANAGE_IDENTITIES = "manage_identities"
        private const val PREFERENCE_OUTGOING_SERVER = "outgoing"
        private const val PREFERENCE_UPLOAD_SENT_MESSAGES = "upload_sent_messages"
        private const val PREFERENCE_QUOTE_STYLE = "quote_style"
        private const val PREFERENCE_DELETE_POLICY = "delete_policy"
        private const val PREFERENCE_EXPUNGE_POLICY = "expunge_policy"
        private const val PREFERENCE_MESSAGE_AGE = "account_message_age"
        private const val PREFERENCE_ADVANCED_PUSH_SETTINGS = "push_advanced"
        private const val PREFERENCE_OPENPGP_ENABLE = "openpgp_provider"
        private const val PREFERENCE_OPENPGP_KEY = "openpgp_key"
        private const val PREFERENCE_AUTOCRYPT_TRANSFER = "autocrypt_transfer"
        private const val PREFERENCE_FOLDERS = "folders"
        private const val PREFERENCE_AUTO_EXPAND_FOLDER = "account_setup_auto_expand_folder"
        private const val PREFERENCE_SUBSCRIBED_FOLDERS_ONLY = "subscribed_folders_only"
        private const val PREFERENCE_ARCHIVE_FOLDER = "archive_folder"
        private const val PREFERENCE_DRAFTS_FOLDER = "drafts_folder"
        private const val PREFERENCE_SENT_FOLDER = "sent_folder"
        private const val PREFERENCE_SPAM_FOLDER = "spam_folder"
        private const val PREFERENCE_TRASH_FOLDER = "trash_folder"
        private const val PREFERENCE_NOTIFICATION_SOUND = "account_ringtone"
        private const val PREFERENCE_NOTIFICATION_LIGHT = "notification_light"
        private const val PREFERENCE_NOTIFICATION_VIBRATION = "account_combined_vibration"
        private const val PREFERENCE_NOTIFICATION_CHANNELS = "notification_channels"
        private const val PREFERENCE_NOTIFICATION_SETTINGS_MESSAGES = "open_notification_settings_messages"
        private const val PREFERENCE_NOTIFICATION_SETTINGS_MISCELLANEOUS = "open_notification_settings_miscellaneous"
        private const val DELETE_POLICY_MARK_AS_READ = "MARK_AS_READ"

        private const val DIALOG_DELETE_ACCOUNT = 1
        private const val REQUEST_DELETE_ACCOUNT = 1
        private const val TAG_DELETE_ACCOUNT_CONFIRMATION = "delete_account_confirmation"

        fun create(accountUuid: String, rootKey: String?) = AccountSettingsFragment().withArguments(
            ARG_ACCOUNT_UUID to accountUuid,
            PreferenceFragmentCompat.ARG_PREFERENCE_ROOT to rootKey,
        )
    }

    //--- PQC Integration  ---

    /**
     * Initializes PQC signing key management UI and logic.
     *
     * - Enables or disables the key management option based on toggle and algorithm selection.
     * - When PQC is enabled, ensures that a PGP key pair exists.
     * - When the user switches the algorithm, the old key pair will be deleted after confirmation.
     * - Launches the PQC Signing Key Management screen when the preference is clicked.
     */
    private fun initializePqcSigningKeyManagement() {
        val keyManagementPref = findPreference<Preference>("pqc_key_management")
        val algorithmPref = findPreference<ListPreference>("pqc_signing_algorithm")
        val account = getAccount()

        if (keyManagementPref == null || algorithmPref == null) return

        val isPqcEnabledPref = findPreference<SwitchPreference>("pqc_enabled")
        isPqcEnabledPref?.isChecked = account.isPqcSigningEnabled
        algorithmPref.value = algorithmPref.value ?: "None"

        fun updateKeyManagementState(enabled: Boolean = isPqcEnabledPref?.isChecked == true, algorithmSelected: Boolean = algorithmPref.value != "None") {
            keyManagementPref.isEnabled = enabled && algorithmSelected
        }

        updateKeyManagementState()

        isPqcEnabledPref?.setOnPreferenceChangeListener { _, newValue ->
            val enabled = newValue as Boolean
            if (enabled) {
                try {
                    SimpleKeyService.ensurePgpKeypairExists(requireContext(), account.uuid, "Ed25519")
                } catch (e: Exception) {
                    Snackbar.make(requireView(), "Fehler bei PGP Key-Setup: ${e.message}", Snackbar.LENGTH_LONG).show()
                }
            }

            updateKeyManagementState(enabled)
            if (enabled) {
                Snackbar.make(requireView(), "PQC Signing aktiviert ✅", Snackbar.LENGTH_SHORT).show()
            }
            true
        }

        algorithmPref.setOnPreferenceChangeListener { _, newValue ->
            val selected = newValue as String
            val oldAlgo = account.pqcSigningAlgorithm
            val enabled = isPqcEnabledPref?.isChecked == true
            val algoSelected = selected != "None"
            val hasKeys = SimpleKeyStoreFactory
                .getKeyStore(SimpleKeyStoreFactory.KeyType.PQC_SIG)
                .hasOwnKeyPair(requireContext(), account.uuid)

            if (hasKeys && selected != oldAlgo) {
                AlertDialog.Builder(requireContext())
                    .setTitle("Algorithmus wechseln?")
                    .setMessage("Du bist dabei, den Algorithmus zu wechseln. Das aktuelle Schlüsselpaar wird gelöscht. Fortfahren?")
                    .setPositiveButton("Ja") { _, _ ->
                        SimpleKeyStoreFactory
                            .getKeyStore(SimpleKeyStoreFactory.KeyType.PQC_SIG)
                            .clearAllKeys(requireContext(), account.uuid,false)
                        account.pqcSigningAlgorithm = selected
                        dataStore.saveSettingsInBackground()
                    }
                    .setNegativeButton("Abbrechen", null)
                    .show()
                return@setOnPreferenceChangeListener false
            }

            account.pqcSigningAlgorithm = selected
            dataStore.saveSettingsInBackground()
            updateKeyManagementState(enabled, algoSelected)
            true
        }


        keyManagementPref.onClick {
           val selectedAlgorithm = account.pqcSigningAlgorithm
            requireActivity().supportFragmentManager.beginTransaction()
                .replace(R.id.accountSettingsContainer, PqcSigningKeyManagementFragment.create(accountUuid, selectedAlgorithm ?: "None"))
                .addToBackStack(null)
                .commit()
        }
    }



    /**
     * Initializes PQC KEM (Key Encapsulation Mechanism) key management UI and logic.
     *
     * - Similar to the signing key logic: enables management only when toggle and algorithm are valid.
     * - On enabling PQC-KEM, ensures a fallback PGP key exists.
     * - Prompts the user to confirm key deletion when switching algorithms.
     * - Opens the PQC KEM key management fragment on click.
     */
    private fun initializePqcKemKeyManagement() {
        val kemKeyManagementPref = findPreference<Preference>("pqc_kem_key_management")
        val kemAlgorithmPref = findPreference<ListPreference>("pqc_kem_algorithm")
        val account = getAccount()

        if (kemKeyManagementPref == null || kemAlgorithmPref == null) return

        val isPqcKemEnabledPref = findPreference<SwitchPreference>("pqc_kem_enabled")
        isPqcKemEnabledPref?.isChecked = account.isPqcKemEnabled
        kemAlgorithmPref.value = kemAlgorithmPref.value ?: "None"

        fun updateKemKeyManagementState(enabled: Boolean = isPqcKemEnabledPref?.isChecked == true, algorithmSelected: Boolean = kemAlgorithmPref.value != "None") {
            kemKeyManagementPref.isEnabled = enabled && algorithmSelected
        }

        updateKemKeyManagementState()

        isPqcKemEnabledPref?.setOnPreferenceChangeListener { _, newValue ->
            val enabled = newValue as Boolean
            if (enabled) {
                try {
                    SimpleKeyService.ensurePgpKeypairExists(context,account.uuid,"Ed25519")
                } catch (e: Exception) {
                    Snackbar.make(requireView(), "Fehler bei PGP Key-Setup: ${e.message}", Snackbar.LENGTH_LONG).show()
                }
            }

            updateKemKeyManagementState(enabled)
            if (enabled) {
                Snackbar.make(requireView(), "PQC KEM aktiviert ✅", Snackbar.LENGTH_SHORT).show()
            }
            true
        }

        kemAlgorithmPref.setOnPreferenceChangeListener { _, newValue ->
            val selected = newValue as String
            val oldAlgo = account.pqcKemAlgorithm
            val enabled = isPqcKemEnabledPref?.isChecked == true
            val algoSelected = selected != "None"
            val hasKeys = SimpleKeyStoreFactory
                .getKeyStore(SimpleKeyStoreFactory.KeyType.PQC_KEM)
                .hasOwnKeyPair(requireContext(), account.uuid)
            if (hasKeys && selected != oldAlgo) {
                AlertDialog.Builder(requireContext())
                    .setTitle("Algorithmus wechseln?")
                    .setMessage("Du bist dabei, den Algorithmus zu wechseln. Das aktuelle Schlüsselpaar wird gelöscht. Fortfahren?")
                    .setPositiveButton("Ja") { _, _ ->
                        SimpleKeyStoreFactory
                            .getKeyStore(SimpleKeyStoreFactory.KeyType.PQC_KEM)
                            .clearAllKeys(requireContext(), account.uuid,false)
                        account.pqcKemAlgorithm = selected
                        dataStore.saveSettingsInBackground()
                    }
                    .setNegativeButton("Abbrechen", null)
                    .show()
                return@setOnPreferenceChangeListener false
            }

            account.pqcKemAlgorithm = selected
            dataStore.saveSettingsInBackground()
            updateKemKeyManagementState(enabled, algoSelected)
            true
        }

        kemKeyManagementPref.onClick {
            val selectedAlgorithm = account.pqcKemAlgorithm
            requireActivity().supportFragmentManager.beginTransaction()
                .replace(R.id.accountSettingsContainer, PqcKemKeyManagementFragment.create(accountUuid, selectedAlgorithm ?: "None"))
                .addToBackStack(null)
                .commit()
        }
    }


    /**
     * Initializes a deletion dialog allowing the user to choose whether to:
     * - Delete all keys (own and stored remote ones)
     * - Delete only own keys
     * - Cancel the operation
     *
     * This uses `SimpleKeyService.ClearAllUsersKeys()` with `deleteAll = true|false`.
     */
    private fun initializeInternalKeyDeletion() {
        findPreference<Preference>("pqc_delete_all_keys")?.onClick {
            AlertDialog.Builder(requireContext())
                .setTitle("Delete stored keys?")
                .setMessage("Do you want to delete only your own keys or also all stored public keys (PGP and PQC) for this account? This action cannot be undone.")
                .setPositiveButton("Delete all") { _, _ ->
                    val account = getAccount()
                    try {
                        SimpleKeyService.ClearAllUsersKeys(requireContext(), account.uuid, true)
                        initializePqcSendKeys()
                        Snackbar.make(requireView(), "All keys successfully deleted", Snackbar.LENGTH_SHORT).show()
                    } catch (e: Exception) {
                        Snackbar.make(requireView(), "Error while deleting keys: ${e.message}", Snackbar.LENGTH_LONG).show()
                    }
                }
                .setNeutralButton("Delete own only") { _, _ ->
                    val account = getAccount()
                    try {
                        SimpleKeyService.ClearAllUsersKeys(requireContext(), account.uuid, false)
                        initializePqcSendKeys()
                        Snackbar.make(requireView(), "Your keys successfully deleted", Snackbar.LENGTH_SHORT).show()
                    } catch (e: Exception) {
                        Snackbar.make(requireView(), "Error while deleting your keys: ${e.message}", Snackbar.LENGTH_LONG).show()
                    }
                }
                .setNegativeButton("Cancel", null)
                .show()
        }
    }

    /**
     * Initializes the feature to manually send your public keys (PGP + PQC) to one or more recipients.
     *
     * - Checks that a PGP key is available before allowing sending.
     * - Prompts the user for one or more email addresses (comma-separated).
     * - Starts email dispatch using `viewModel.sendPqcKeysByEmail()`.
     */
    private fun initializePqcSendKeys() {
        val pref = findPreference<Preference>("pqc_send_keys") ?: return
        val account = getAccount()

        val hasPgpKeyPair = try {
            SimpleKeyStoreFactory
                .getKeyStore(SimpleKeyStoreFactory.KeyType.PGP)
                .hasOwnKeyPair(requireContext(), account.uuid)
        } catch (e: Exception) {
            false
        }


        if (!hasPgpKeyPair) {
            pref.isEnabled = false
            pref.summary = "Requires a one key pair to be available"
            return
        }
        else{
            pref.isEnabled = true
        }

        pref.onClick {
            val input = EditText(requireContext()).apply {
                hint = "Email addresses, separated by commas"
                inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS
            }

            AlertDialog.Builder(requireContext())
                .setTitle("Send public key")
                .setMessage("Please enter one or more email addresses.")
                .setView(input)
                .setPositiveButton("Send") { _, _ ->
                    val raw = input.text.toString()
                    val emails = raw.split(",")
                        .map { it.trim() }
                        .filter { android.util.Patterns.EMAIL_ADDRESS.matcher(it).matches() }

                    if (emails.isNotEmpty()) {
                        viewModel.sendPqcKeysByEmail(requireContext(), account, emails)
                        Snackbar.make(requireView(), "Email sending started 📧", Snackbar.LENGTH_SHORT).show()
                    } else {
                        Snackbar.make(requireView(), "No valid email addresses found.", Snackbar.LENGTH_LONG).show()
                    }
                }
                .setNegativeButton("Cancel", null)
                .show()
        }
    }

    /**
     * Adds an option to manually generate a local PGP key pair.
     *
     * - Will generate a 4096-bit RSA key if no key exists.
     * - Uses the `SimpleKeyStoreFactory` to manage keys.
     */
    private fun initializePgpKeyGeneration() {
        val pref = findPreference<Preference>("pqc_generate_pgp_key") ?: return
        val account = getAccount()

        pref.onClick {
            try {
                val hasKey = SimpleKeyStoreFactory
                    .getKeyStore(SimpleKeyStoreFactory.KeyType.PGP)
                    .hasOwnKeyPair(requireContext(), account.uuid)

                if (hasKey) {
                    Snackbar.make(requireView(), getString(R.string._pqc_generate_pgp_exists), Snackbar.LENGTH_SHORT).show()
                    return@onClick
                }

                SimpleKeyStoreFactory
                    .getKeyStore(SimpleKeyStoreFactory.KeyType.PGP)
                    .generateKeyPair(requireContext(), account.uuid, "RSA")
                initializePqcSendKeys()
                Snackbar.make(requireView(), getString(R.string._pqc_generate_pgp_success), Snackbar.LENGTH_SHORT).show()
            } catch (e: Exception) {
                Snackbar.make(requireView(), getString(R.string._pqc_generate_pgp_error, e.message ?: "unknown"), Snackbar.LENGTH_LONG).show()
            }
        }
    }


    /**
     * Adds a PQC benchmark runner to the settings.
     *
     * - Runs predefined PQC benchmarks (signing, encryption, key generation, etc.)
     * - Shows result via Toast after completion.
     */
    private fun initializePqcBenchmarkRunner() {
        findPreference<Preference>("run_pqc_benchmark")?.onClick {
            showBenchmarkOptions()
        }
    }

    private fun showBenchmarkOptions() {
        val layout = LinearLayout(requireContext()).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(50, 40, 50, 10)
        }

        val iterationsInput = EditText(requireContext()).apply {
            hint = "Anzahl Iterationen (z. B. 1000)"
            inputType = InputType.TYPE_CLASS_NUMBER
        }

        val msgSizeInput = EditText(requireContext()).apply {
            hint = "Nachrichtengröße in Byte (z. B. 1024)"
            inputType = InputType.TYPE_CLASS_NUMBER
        }

        layout.addView(iterationsInput)
        layout.addView(msgSizeInput)

        AlertDialog.Builder(requireContext())
            .setTitle("Benchmark konfigurieren")
            .setView(layout)
            .setPositiveButton("Starten") { _, _ ->
                val iterations = iterationsInput.text.toString().toIntOrNull() ?: 1000
                val msgSize = msgSizeInput.text.toString().toIntOrNull() ?: 1024
                PQCBenchmarkRunner.setIterations(iterations)
                PQCBenchmarkRunner.setSampleMessageSize(msgSize)
                runBenchmark()
            }
            .setNegativeButton("Abbrechen", null)
            .show()
    }

    private fun runBenchmark() {
        val context = requireContext()
        val progressDialog = ProgressDialog(context).apply {
            setMessage("Benchmark läuft – bitte nicht schließen...")
            setCancelable(false)
            show()
        }

        CoroutineScope(Dispatchers.IO).launch {
            val result = PQCBenchmarkRunner.runAllBenchmarks(context)
            withContext(Dispatchers.Main) {
                progressDialog.dismiss()
                Toast.makeText(context, result, Toast.LENGTH_LONG).show()
            }
        }
    }


    //--- End PQC Integration ---
}
