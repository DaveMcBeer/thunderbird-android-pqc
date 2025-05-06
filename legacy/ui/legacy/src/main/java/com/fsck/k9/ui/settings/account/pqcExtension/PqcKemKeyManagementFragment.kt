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
import android.widget.*
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
                showErrorDialog("Please select a valid .pqk file.")
                return@let
            }
            viewModel.importKeyFile(requireContext(), it)
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
            val context = requireContext()
            if (!viewModel.hasKeyPair(context)) {
                val accountId = requireArguments().getString(ARG_ACCOUNT_UUID) ?: return@setOnClickListener
                val algorithm = viewModel.getCurrentAlgorithm() ?: "None"
                viewModel.generatePqcKemKeyPair(context, accountId, algorithm)
            } else {
                showConfirmResetDialog()
            }
            updateKeyTexts()
        }

        view.findViewById<Button>(R.id.export_keys_button).setOnClickListener {
            viewModel.exportKeyFile(requireContext())
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


    private fun showConfirmResetDialog() {
        AlertDialog.Builder(requireContext())
            .setTitle("Delete Key Pair?")
            .setMessage("Are you sure you want to delete the key pair?")
            .setPositiveButton("Delete") { _, _ ->
                viewModel.resetKeyPair(requireContext())
                updateKeyTexts()
            }
            .setNegativeButton("Cancel", null)
            .show()
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
            val nameIndex = it.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
            if (nameIndex >= 0 && it.moveToFirst()) {
                return it.getString(nameIndex)
            }
        }
        return ""
    }

    companion object {
        private const val ARG_ACCOUNT_UUID = "accountUuid"
        private const val ARG_ALGORITHM_NAME = "algorithm"
        fun create(accountUuid: String, algorithm: String): PqcKemKeyManagementFragment {
            return PqcKemKeyManagementFragment().apply {
                arguments = Bundle().apply {
                    putString(ARG_ACCOUNT_UUID, accountUuid)
                    putString(ARG_ALGORITHM_NAME, algorithm)
                }
            }
        }
    }

    override fun doPositiveClick(dialogId: Int) {}
    override fun doNegativeClick(dialogId: Int) {}
    override fun dialogCancelled(dialogId: Int) {}
}
