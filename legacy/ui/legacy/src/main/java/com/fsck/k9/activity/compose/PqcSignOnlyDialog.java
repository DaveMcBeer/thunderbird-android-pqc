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

/**
 * Dialog, der dem Nutzer erklärt, was der "PQC Sign Only"-Modus ist.
 * Je nachdem, ob es das erste Mal ist oder nicht, wird ein anderer Dialog gezeigt.
 */
public class PqcSignOnlyDialog extends HighlightDialogFragment {
    public static final String ARG_FIRST_TIME = "first_time";

    /**
     * Erstellt eine neue Instanz des Dialogs mit den nötigen Argumenten.
     * @param firstTime Gibt an, ob der Dialog zum ersten Mal angezeigt wird.
     * @param showcaseView Die ID der View, die hervorgehoben werden soll.
     */
    public static PqcSignOnlyDialog newInstance(boolean firstTime, @IdRes int showcaseView) {
        PqcSignOnlyDialog dialog = new PqcSignOnlyDialog();

        Bundle args = new Bundle();
        args.putInt(ARG_FIRST_TIME, firstTime ? 1 : 0);
        args.putInt(ARG_HIGHLIGHT_VIEW, showcaseView);
        dialog.setArguments(args);

        return dialog;
    }

    /**
     * Baut den Dialog, der angezeigt wird.
     * Je nachdem, ob es das erste Mal ist, werden andere Buttons gezeigt.
     */
    @Override
    public Dialog onCreateDialog(Bundle savedInstanceState) {
        Activity activity = getActivity();

        // Layout vom Dialog laden
        @SuppressLint("InflateParams")
        View view = LayoutInflater.from(activity).inflate(R.layout.pqc_sing_only_dialog, null);

        MaterialAlertDialogBuilder builder = new MaterialAlertDialogBuilder(requireActivity());
        builder.setView(view);

        // Wenn es das erste Mal ist → nur "OK"-Button
        if (getArguments().getInt(ARG_FIRST_TIME) != 0) {
            builder.setPositiveButton(R.string.openpgp_sign_only_ok, new OnClickListener() {
                @Override
                public void onClick(DialogInterface dialog, int which) {
                    dialog.dismiss(); // einfach schließen
                }
            });
        } else {
            // Wenn nicht das erste Mal → Option zum Deaktivieren
            builder.setPositiveButton(R.string.openpgp_sign_only_disable, new OnClickListener() {
                @Override
                public void onClick(DialogInterface dialog, int which) {
                    Activity activity = getActivity();
                    if (activity == null) {
                        return;
                    }

                    // Callback, um dem Aufrufer mitzuteilen, dass der Modus deaktiviert werden soll
                    ((OnPqcSignOnlyChangeListener) activity).onPqcSignOnlyChange(false);
                    dialog.dismiss();
                }
            });
            builder.setNegativeButton(R.string.openpgp_sign_only_keep_enabled, new OnClickListener() {
                @Override
                public void onClick(DialogInterface dialog, int which) {
                    dialog.dismiss(); // Modus beibehalten
                }
            });
        }

        return builder.create();
    }

    /**
     * Interface, das von der aufrufenden Activity implementiert werden muss,
     * um über Änderungen am PQC-Sign-Only-Modus benachrichtigt zu werden.
     */
    public interface OnPqcSignOnlyChangeListener {
        void onPqcSignOnlyChange(boolean enabled);
    }
}
