package com.fsck.k9.activity.compose;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.app.Dialog;
import android.content.DialogInterface;
import android.content.DialogInterface.OnClickListener;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;

import androidx.annotation.IdRes;

import com.fsck.k9.ui.R;
import com.fsck.k9.view.HighlightDialogFragment;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;

public class PqcSigEncrytpDescriptionDialog extends HighlightDialogFragment {
    public static final String ARG_FIRST_TIME = "first_time";

    public static PqcSigEncrytpDescriptionDialog newInstance(@IdRes int showcaseView) {
        PqcSigEncrytpDescriptionDialog dialog = new PqcSigEncrytpDescriptionDialog();

        Bundle args = new Bundle();
        args.putInt(ARG_HIGHLIGHT_VIEW, showcaseView);
        dialog.setArguments(args);

        return dialog;
    }

    public Dialog onCreateDialog(Bundle savedInstanceState) {
        Activity activity = getActivity();

        @SuppressLint("InflateParams")
        View view = LayoutInflater.from(activity).inflate(R.layout.pqc_sig_encrypt_dialog, null);

        MaterialAlertDialogBuilder builder = new MaterialAlertDialogBuilder(requireActivity());
        builder.setView(view);

        if (getArguments().getInt(ARG_FIRST_TIME) != 0) {
            builder.setPositiveButton(R.string.openpgp_sign_only_ok, new OnClickListener() {
                @Override
                public void onClick(DialogInterface dialog, int which) {
                    dialog.dismiss();
                }
            });
        } else {
            builder.setPositiveButton(R.string.pqc_dialog_sign_only_disable, new OnClickListener() {
                @Override
                public void onClick(DialogInterface dialog, int which) {
                    Activity activity = getActivity();
                    if (activity == null) {
                        return;
                    }

                    ((PqcSigEncrytpDescriptionDialog.OnPqcSigEncryptOnlyChangeListener) activity).onSigEncryptSignOnlyChange(false);
                    dialog.dismiss();
                }
            });
            builder.setNegativeButton(R.string.pqc_dialog_sign_only_keep_enabled, new OnClickListener() {
                @Override
                public void onClick(DialogInterface dialog, int which) {
                    dialog.dismiss();
                }
            });
        }

        return builder.create();
    }

    public interface OnPqcSigEncryptOnlyChangeListener {
        void onSigEncryptSignOnlyChange(boolean enabled);
    }
}
