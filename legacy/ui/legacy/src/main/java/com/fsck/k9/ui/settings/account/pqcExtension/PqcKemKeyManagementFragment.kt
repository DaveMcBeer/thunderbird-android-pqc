package com.fsck.k9.ui.settings.account.pqcExtension

import android.app.AlertDialog
import android.content.Context
import android.database.Cursor
import android.net.Uri
import android.os.Bundle
import android.text.InputType
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.fragment.app.Fragment
import com.fsck.k9.fragment.ConfirmationDialogFragment.ConfirmationDialogFragmentListener
import com.fsck.k9.ui.R
import com.google.android.material.snackbar.Snackbar
import org.koin.androidx.viewmodel.ext.android.viewModel
import org.koin.core.parameter.parametersOf

class PqcKemKeyManagementFragment : Fragment(), ConfirmationDialogFragmentListener {

    private val viewModel: PqcKemKeyManagementViewModel by viewModel {
        parametersOf(requireArguments().getString(ARG_ACCOUNT_UUID))
    }

    private lateinit var publicKeyTextView: TextView
    private lateinit var keyStatusTextView: TextView
    private lateinit var keyStatusIconView: TextView
    private lateinit var dynamicActionButton: Button
    private lateinit var algorithmTextView: TextView

    private val filePickerLauncher = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        uri?.let {
            val fileName = getFileNameFromUri(requireContext(), it)
            if (!fileName.endsWith(".pqk")) {
                showErrorDialog("Bitte eine gültige .pqk-Datei auswählen.")
                return@let
            }
            promptPassword { password ->
                viewModel.importKeyFile(requireContext(), it, password)
                Snackbar.make(requireView(), "Key-Datei erfolgreich importiert ✅", Snackbar.LENGTH_LONG).show()
            }
        }
    }

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View? {
        val view = inflater.inflate(R.layout.pqc_kem_key_management_fragment, container, false)

        publicKeyTextView = view.findViewById(R.id.public_key_text)
        algorithmTextView = view.findViewById(R.id.algorithm_text)
        keyStatusTextView = view.findViewById(R.id.key_status_text)
        keyStatusIconView = view.findViewById(R.id.key_status_icon)
        dynamicActionButton = view.findViewById(R.id.dynamic_action_button)

        dynamicActionButton.setOnClickListener {
            if (viewModel.getPublicKey().isNullOrBlank()) {
                viewModel.generatePqcKemKeyPair()
            } else {
                showConfirmResetDialog()
            }
            updateKeyTexts()
        }

        view.findViewById<Button>(R.id.export_keys_button).setOnClickListener {
            promptPassword { password ->
                viewModel.exportKeyFile(requireContext(), password)
            }
        }

        view.findViewById<Button>(R.id.import_keys_button).setOnClickListener {
            filePickerLauncher.launch(arrayOf("application/octet-stream", "*/*"))
        }

        viewModel.isLoading.observe(viewLifecycleOwner) { isLoading ->
            val overlay = view.findViewById<FrameLayout>(R.id.loadingOverlay)
            overlay.animate()
                .alpha(if (isLoading) 1f else 0f)
                .setDuration(200)
                .withStartAction { if (isLoading) overlay.visibility = View.VISIBLE }
                .withEndAction { if (!isLoading) overlay.visibility = View.GONE }
        }

        viewModel.errorMessage.observe(viewLifecycleOwner) { event ->
            event.getContentIfNotHandled()?.let { message ->
                showErrorDialog(message)
            }
        }

        viewModel.keyStatus.observe(viewLifecycleOwner) { keyStatus ->
            algorithmTextView.text = "Algorithmus: ${keyStatus.algorithm ?: "Unbekannt"}"
            publicKeyTextView.text = keyStatus.publicKey ?: "Kein öffentlicher Schlüssel"
            val hasKeys = !keyStatus.publicKey.isNullOrBlank() && !keyStatus.privateKey.isNullOrBlank()
            keyStatusIconView.text = if (hasKeys) "✅" else "❌"
            keyStatusTextView.text = if (hasKeys) "Key-Paar vorhanden" else "Kein Key-Paar vorhanden"
            dynamicActionButton.text = if (hasKeys) "🧹 Schlüssel löschen" else "🛠 Key-Paar generieren"
        }

        updateKeyTexts()
        return view
    }

    private fun updateKeyTexts() {
        val publicKey = viewModel.getPublicKey()
        val secretKey = viewModel.getSecretKey()
        algorithmTextView.text = "Algorithmus: ${viewModel.getCurrentAlgorithm() ?: "Unbekannt"}"

        publicKeyTextView.text = publicKey ?: "Kein öffentlicher Schlüssel"

        if (!publicKey.isNullOrBlank() && !secretKey.isNullOrBlank()) {
            keyStatusIconView.text = "✅"
            keyStatusTextView.text = "Key-Paar vorhanden"
            dynamicActionButton.text = "🧹 Schlüssel löschen"
        } else {
            keyStatusIconView.text = "❌"
            keyStatusTextView.text = "Kein Key-Paar vorhanden"
            dynamicActionButton.text = "🛠 Key-Paar generieren"
        }
    }

    private fun showConfirmResetDialog() {
        AlertDialog.Builder(requireContext())
            .setTitle("Schlüssel löschen?")
            .setMessage("Bist du sicher, dass du das Schlüssel-Paar löschen möchtest?")
            .setPositiveButton("Löschen") { _, _ ->
                viewModel.resetKeyPair()
                updateKeyTexts()
            }
            .setNegativeButton("Abbrechen", null)
            .show()
    }

    private fun promptPassword(onPasswordEntered: (String) -> Unit) {
        val input = EditText(requireContext()).apply {
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        }

        AlertDialog.Builder(requireContext())
            .setTitle("Passwort eingeben")
            .setMessage("Bitte gib ein Passwort für Verschlüsselung ein.")
            .setView(input)
            .setPositiveButton("OK") { _, _ ->
                val password = input.text.toString()
                if (password.isNotBlank()) {
                    onPasswordEntered(password)
                }
            }
            .setNegativeButton("Abbrechen", null)
            .show()
    }

    private fun getFileNameFromUri(context: Context, uri: Uri): String {
        val cursor = context.contentResolver.query(uri, null, null, null, null)
        cursor?.use {
            val nameIndex = it.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
            if (nameIndex >= 0 && it.moveToFirst()) {
                return it.getString(nameIndex)
            }
        }
        return ""
    }
    /**
     * Zeigt einen Fehlerdialog mit übergebener Nachricht.
     */
    private fun showErrorDialog(message: String) {
        AlertDialog.Builder(requireContext())
            .setTitle("Fehler")
            .setMessage(message)
            .setPositiveButton("OK", null)
            .show()
    }
    companion object {
        private const val ARG_ACCOUNT_UUID = "accountUuid"

        fun create(accountUuid:String) : PqcKemKeyManagementFragment{
            return PqcKemKeyManagementFragment().apply{
                arguments = Bundle().apply { putString(PqcKemKeyManagementFragment.ARG_ACCOUNT_UUID,accountUuid)}
            }
        }
    }

    override fun doPositiveClick(dialogId: Int) {}
    override fun doNegativeClick(dialogId: Int) {}
    override fun dialogCancelled(dialogId: Int) {}
}
