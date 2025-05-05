package com.fsck.k9.activity.compose;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.app.Dialog;
import android.content.DialogInterface;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;

import androidx.annotation.IdRes;

import com.fsck.k9.ui.R;
import com.fsck.k9.view.HighlightDialogFragment;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;

public class PqcEncryptionDescriptionDialog extends HighlightDialogFragment {

    public static PqcEncryptionDescriptionDialog newInstance(@IdRes int showcaseView) {
        PqcEncryptionDescriptionDialog dialog = new PqcEncryptionDescriptionDialog();

        Bundle args = new Bundle();
        args.putInt(ARG_HIGHLIGHT_VIEW, showcaseView);
        dialog.setArguments(args);

        return dialog;
    }

    @Override
    public Dialog onCreateDialog(Bundle savedInstanceState) {
        Activity activity = getActivity();

        @SuppressLint("InflateParams")
        View view = LayoutInflater.from(activity).inflate(R.layout.pqc_encryption_description_dialog, null);

        MaterialAlertDialogBuilder builder = new MaterialAlertDialogBuilder(requireActivity());
        builder.setView(view);

        builder.setPositiveButton(R.string.pqc_encryption_enabled_error_gotit, new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) {
                dialog.dismiss();
            }
        });

        return builder.create();
    }
}
