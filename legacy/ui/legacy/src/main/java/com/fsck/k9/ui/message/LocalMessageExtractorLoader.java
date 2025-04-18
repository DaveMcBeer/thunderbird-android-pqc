package com.fsck.k9.ui.message;


import java.util.ArrayList;

import android.content.Context;

import androidx.annotation.Nullable;
import androidx.annotation.WorkerThread;
import androidx.loader.content.AsyncTaskLoader;
import com.fsck.k9.mailstore.AttachmentViewInfo;
import com.fsck.k9.mailstore.CryptoResultAnnotation;
import com.fsck.k9.mailstore.LocalMessage;
import com.fsck.k9.mailstore.MessageCryptoAnnotations;
import com.fsck.k9.mailstore.MessageViewInfo;
import com.fsck.k9.mailstore.MessageViewInfoExtractor;
import com.fsck.k9.mailstore.pqc.PqcSignatureResult;
import timber.log.Timber;


public class LocalMessageExtractorLoader extends AsyncTaskLoader<MessageViewInfo> {
    private final MessageViewInfoExtractor messageViewInfoExtractor;


    private final LocalMessage message;
    private MessageViewInfo messageViewInfo;
    @Nullable
    private MessageCryptoAnnotations annotations;

    public LocalMessageExtractorLoader(Context context, LocalMessage message,
            @Nullable MessageCryptoAnnotations annotations, MessageViewInfoExtractor messageViewInfoExtractor) {
        super(context);
        this.message = message;
        this.annotations = annotations;
        this.messageViewInfoExtractor = messageViewInfoExtractor;
    }

    @Override
    protected void onStartLoading() {
        if (messageViewInfo != null) {
            super.deliverResult(messageViewInfo);
        }

        if (takeContentChanged() || messageViewInfo == null) {
            forceLoad();
        }
    }

    @Override
    public void deliverResult(MessageViewInfo messageViewInfo) {
        this.messageViewInfo = messageViewInfo;
        super.deliverResult(messageViewInfo);
    }

    @Override
    @WorkerThread
    public MessageViewInfo loadInBackground() {
        try {
            //--- PQC Erweiterung ---
            if (annotations == null) {
                annotations = new MessageCryptoAnnotations();
            }
            MessageViewInfo messageViewInfo = messageViewInfoExtractor.extractMessageForView(
                message,
                annotations,
                message.getAccount().isOpenPgpProviderConfigured()
            );

            if (messageViewInfo.attachments != null && !messageViewInfo.attachments.isEmpty()) {
                for (AttachmentViewInfo attachment : messageViewInfo.attachments) {
                    String mimeType = attachment.mimeType;

                    if ("application/pqc-signature".equalsIgnoreCase(mimeType)) {
                        Timber.d("PQC Signature attachment detected!");

                        PqcSignatureResult pqcSignatureResult = new PqcSignatureResult(
                            PqcSignatureResult.RESULT_VALID_KEY_CONFIRMED,
                            null,
                            0L,
                            new ArrayList<>(),
                            new ArrayList<>(),
                            PqcSignatureResult.SenderStatusResult.UNKNOWN
                        );

                        return messageViewInfo.withCryptoData(
                            CryptoResultAnnotation.createPqcSignatureAnnotation(
                                null,
                                pqcSignatureResult,
                                attachment.toBodyPart()
                            ),
                            messageViewInfo.extraText,
                            messageViewInfo.extraAttachments
                        );
                    }
                }
            }

            return messageViewInfo;
            //--- ENDE ---
        } catch (Exception e) {
            Timber.e(e, "Error while decoding message");
            return null;
        }
    }

    public boolean isCreatedFor(LocalMessage localMessage, MessageCryptoAnnotations messageCryptoAnnotations) {
        return annotations == messageCryptoAnnotations && message.equals(localMessage);
    }
}
