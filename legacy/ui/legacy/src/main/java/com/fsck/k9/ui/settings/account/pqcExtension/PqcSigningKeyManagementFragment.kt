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

class PqcSigningKeyManagementFragment : Fragment(), ConfirmationDialogFragmentListener {

    private val viewModel: PqcSigningKeyManagementViewModel by viewModel {
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
                showErrorDialog("Please select a valid .pqk file.")
                return@let
            }
            viewModel.importKeyFile(requireContext(), it)
        }
    }

    private val exportFileLauncher = registerForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        if (uri != null) {
            viewModel.exportKeyFileToUri(requireContext(), uri)
        } else {
            Snackbar.make(requireView(), "Export cancelled", Snackbar.LENGTH_SHORT).show()
        }
    }


    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View? {
        val view = inflater.inflate(R.layout.pqc_signing_key_management_fragment, container, false)

        publicKeyTextView = view.findViewById(R.id.public_key_text)
        algorithmTextView = view.findViewById(R.id.algorithm_text)
        keyStatusTextView = view.findViewById(R.id.key_status_text)
        keyStatusIconView = view.findViewById(R.id.key_status_icon)
        dynamicActionButton = view.findViewById(R.id.dynamic_action_button)

        dynamicActionButton.setOnClickListener {
            val context = requireContext()
            if (viewModel.getPublicKey(context).isNullOrBlank()) {
                val accountId = requireArguments().getString(ARG_ACCOUNT_UUID) ?: return@setOnClickListener
                val algorithm = viewModel.getCurrentAlgorithm() ?: "None"
                viewModel.generateSigningKey(context, accountId, algorithm)
            } else {
                showDeleteKeyOptionsDialog()
            }
            updateKeyTexts()
        }

        view.findViewById<Button>(R.id.export_keys_button).setOnClickListener {
            val accountName = viewModel.account?.name ?: "account"
            val safeName = accountName.replace("[^a-zA-Z0-9-_]".toRegex(), "_")
            exportFileLauncher.launch("pqkeys_${safeName}.pqk")
        }

        view.findViewById<Button>(R.id.import_keys_button).setOnClickListener {
            filePickerLauncher.launch(arrayOf("application/octet-stream", "*/*"))
        }

        val overlay = view.findViewById<FrameLayout>(R.id.loadingOverlay)
        viewModel.isLoading.observe(viewLifecycleOwner) { isLoading ->
            overlay.animate()
                .alpha(if (isLoading) 1f else 0f)
                .setDuration(200)
                .withStartAction { if (isLoading) overlay.visibility = View.VISIBLE }
                .withEndAction { if (!isLoading) overlay.visibility = View.GONE }
        }

        viewModel.errorMessage.observe(viewLifecycleOwner) { event ->
            event.getContentIfNotHandled()?.let { showErrorDialog(it) }
        }

        viewModel.keyStatus.observe(viewLifecycleOwner) { keyStatus ->
            algorithmTextView.text = "Algorithm: ${keyStatus.algorithm ?: "Unknown"}"
            publicKeyTextView.text = keyStatus.publicKey ?: "No public key"

            val hasKeys = viewModel.hasKeyPair(requireContext())
            keyStatusIconView.text = if (hasKeys) "✅" else "❌"
            keyStatusTextView.text = if (hasKeys) "Key pair available" else "No key pair available"
            dynamicActionButton.text = if (hasKeys) "🧹 Delete key pair" else "🛠 Generate key pair"
        }
        updateKeyTexts()
        return view
    }
    private fun updateKeyTexts() {
        val context = requireContext()
        val publicKey = viewModel.getPublicKey(context)
        val algorithm = viewModel.getCurrentAlgorithm()

        publicKeyTextView.text = publicKey ?: "No public key"
        algorithmTextView.text = "Algorithm: ${algorithm ?: "Unknown"}"

        val hasKeys = viewModel.hasKeyPair(context)
        keyStatusIconView.text = if (hasKeys) "✅" else "❌"
        keyStatusTextView.text = if (hasKeys) "Key pair available" else "No key pair available"
        dynamicActionButton.text = if (hasKeys) "🧹 Delete key pair" else "🛠 Generate key pair"
    }


    private fun showErrorDialog(message: String) {
        AlertDialog.Builder(requireContext())
            .setTitle("Error")
            .setMessage(message)
            .setPositiveButton("OK", null)
            .show()
    }

    private fun getFileNameFromUri(context: Context, uri: Uri): String {
        val cursor = context.contentResolver.query(uri, null, null, null, null)
        cursor?.use {
            val nameIndex = it.getColumnIndexOpenableColumnName()
            if (nameIndex >= 0 && it.moveToFirst()) {
                return it.getString(nameIndex)
            }
        }
        return ""
    }
    private fun showDeleteKeyOptionsDialog() {
        AlertDialog.Builder(requireContext())
            .setTitle("Delete keys?")
            .setMessage("Do you want to delete only your own keys, or also the stored public keys of others?")
            .setPositiveButton("Delete all") { _, _ ->
                viewModel.resetKeyPair(requireContext(),true)
            }
            .setNeutralButton("Delete own only") { _, _ ->
                viewModel.resetKeyPair(requireContext(), false)
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun Cursor.getColumnIndexOpenableColumnName(): Int {
        return getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
    }

    companion object {
        private const val ARG_ACCOUNT_UUID = "accountUuid"
        private const val ARG_ALGORITHM_NAME = "algorithm"
        fun create(accountUuid: String,algorithm: String): PqcSigningKeyManagementFragment {
            return PqcSigningKeyManagementFragment().apply {
                arguments = Bundle().apply {
                    putString(ARG_ACCOUNT_UUID, accountUuid)
                    putString(ARG_ALGORITHM_NAME, algorithm)
                }
            }
        }
    }

    private fun promptEmailRecipients(onValidEmails: (List<String>) -> Unit) {
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
                    onValidEmails(emails)
                } else {
                    showErrorDialog("No valid email addresses detected.")
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    override fun doPositiveClick(dialogId: Int) {
        TODO("Not yet implemented")
    }

    override fun doNegativeClick(dialogId: Int) {
        TODO("Not yet implemented")
    }

    override fun dialogCancelled(dialogId: Int) {
        TODO("Not yet implemented")
    }
}
