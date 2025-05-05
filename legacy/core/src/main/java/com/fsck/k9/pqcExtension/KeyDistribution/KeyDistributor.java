package com.fsck.k9.pqcExtension.KeyDistribution;


import android.app.PendingIntent;
import android.content.Context;
import android.os.AsyncTask;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import app.k9mail.legacy.account.Account;
import app.k9mail.legacy.account.Identity;
import app.k9mail.legacy.message.controller.MessageReference;
import com.fsck.k9.Preferences;
import com.fsck.k9.controller.MessagingController;
import com.fsck.k9.helper.Contacts;
import com.fsck.k9.logging.Timber;
import com.fsck.k9.mail.Address;

import com.fsck.k9.mail.Flag;
import com.fsck.k9.mail.Message;
import com.fsck.k9.mail.Message.RecipientType;
import com.fsck.k9.mail.MessagingException;
import com.fsck.k9.mail.internet.MimeMessage;

import com.fsck.k9.message.Attachment;
import com.fsck.k9.message.MessageBuilder;
import com.fsck.k9.message.SimpleMessageBuilder;
import com.fsck.k9.message.SimpleMessageFormat;
import com.fsck.k9.pqcExtension.helper.PqcMessageHelper;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;

import java.util.Collections;
import java.util.Date;
import java.util.List;


public class KeyDistributor {
    public enum KeyAttachment {
        PQC_SIG("pqc-sig-pk.asc", "X-Key-Sig-Algorithm", "application/octet-stream"),
        PQC_KEM("pqc-kem-pk.asc", "X-Key-Kem-Algorithm", "application/octet-stream"),
        PGP("pgp-pk.asc", null, "application/pgp-keys");

        public final String filename;
        public final String algoHeader;
        public final String mimeType;

        KeyAttachment(String filename, String algoHeader, String mimeType) {
            this.filename = filename;
            this.algoHeader = algoHeader;
            this.mimeType = mimeType;
        }
    }

    public static void createAndSendKeyDistributionMessage(
        Context context,
        MessagingController messagingController,
        Preferences preferences,
        Contacts contacts,
        Account account,
        List<String> to,
        @Nullable String kemKey,
        @Nullable String sigKey,
        @Nullable String kemAlg,
        @Nullable String sigAlg,
        @NonNull String pgpKey,
        @Nullable Long draftId,
        @Nullable String plaintextSubject,
        @Nullable MessageReference messageReference,
        @Nullable Flag flag
    ) throws Exception {

        Identity identity = account.getIdentity(0);
        List<Attachment> attachments = new ArrayList<>();

        if (sigKey != null && sigAlg != null) {
            String armored = PqcMessageHelper.armor(sigKey, "PQC SIGNATURE PUBLIC KEY", sigAlg);
            attachments.add(createTempAttachment(context, armored, KeyAttachment.PQC_SIG.filename, KeyAttachment.PQC_SIG.mimeType));
        }

        if (kemKey != null && kemAlg != null) {
            String armored = PqcMessageHelper.armor(kemKey, "PQC KEM PUBLIC KEY", kemAlg);
            attachments.add(createTempAttachment(context, armored, KeyAttachment.PQC_KEM.filename, KeyAttachment.PQC_KEM.mimeType));
        }

        if (pgpKey != null && !pgpKey.trim().isEmpty()) {
            // Der Key muss bereits korrekt armoured sein (z.B. via exportArmoredPublicKey)
            attachments.add(createTempAttachment(
                context,
                pgpKey,
                KeyAttachment.PGP.filename,
                KeyAttachment.PGP.mimeType
            ));
        }
        List<Address> addressList = new ArrayList<>();
        for (String email : to) {
            addressList.add(new Address(email));
        }

        SimpleMessageBuilder builder = (SimpleMessageBuilder) SimpleMessageBuilder.newInstance()
            .setAccount(account)
            .setIdentity(identity)
            .setTo(addressList)
            .setSubject(plaintextSubject != null ? plaintextSubject : "Key Distribution")
            .setText("Attached are the public keys.")
            .setMessageFormat(SimpleMessageFormat.TEXT)
            .setDraft(false)
            .setSentDate(new Date())
            .setHideTimeZone(false)
            .setAttachments(attachments);

        builder.buildAsync(new MessageBuilder.Callback() {
            @Override
            public void onMessageBuildSuccess(MimeMessage message, boolean isDraft) {
                message.setHeader("X-Key-Distribution", "true");


                new KeySendTask(
                    messagingController,
                    preferences,
                    account,
                    contacts,
                    message,
                    draftId,
                    plaintextSubject,
                    messageReference,
                    flag
                ).execute();
            }

            @Override
            public void onMessageBuildCancel() {
                Timber.e("KeyDistributor: Message build cancelled.");
            }

            @Override
            public void onMessageBuildException(MessagingException exception) {
                Timber.e(exception, "KeyDistributor: Failed to build message.");
            }

            @Override
            public void onMessageBuildReturnPendingIntent(PendingIntent pendingIntent, int requestCode) {
                Timber.e("KeyDistributor: Unexpected pending intent.");
            }
        });
    }

    private static Attachment createTempAttachment(Context context, String content, String filename, String mimeType) throws IOException {
        File tempFile = File.createTempFile("key-attachment-", ".asc", context.getCacheDir());
        try (FileOutputStream fos = new FileOutputStream(tempFile)) {
            fos.write(content.getBytes(StandardCharsets.UTF_8));
        }

        return new Attachment() {
            @NonNull
            @Override
            public LoadingState getState() {
                return LoadingState.COMPLETE;
            }

            @Nullable
            @Override
            public String getFileName() {
                return tempFile.getAbsolutePath();
            }

            @Nullable
            @Override
            public String getContentType() {
                return mimeType;
            }

            @Nullable
            @Override
            public String getName() {
                return filename;
            }

            @Nullable
            @Override
            public Long getSize() {
                return tempFile.length();
            }

            @Override
            public boolean isInternalAttachment() {
                return false;
            }
        };
    }

    static class KeySendTask extends AsyncTask<Void, Void, Void> {
        final MessagingController messagingController;
        final Preferences preferences;
        final Account account;
        final Contacts contacts;
        final Message message;
        final Long draftId;
        final String plaintextSubject;
        final MessageReference messageReference;
        final Flag flag;

         KeySendTask(MessagingController messagingController, Preferences preferences, Account account,
             Contacts contacts, Message message, Long draftId, String plaintextSubject,
             MessageReference messageReference, Flag flag) {
            this.messagingController = messagingController;
            this.preferences = preferences;
            this.account = account;
            this.contacts = contacts;
            this.message = message;
            this.draftId = draftId;
            this.plaintextSubject = plaintextSubject;
            this.messageReference = messageReference;
            this.flag = flag;
        }

        @Override
        protected Void doInBackground(Void... params) {
            try {
                contacts.markAsContacted(message.getRecipients(RecipientType.TO));
                contacts.markAsContacted(message.getRecipients(RecipientType.CC));
                contacts.markAsContacted(message.getRecipients(RecipientType.BCC));
                addFlagToReferencedMessage();
            } catch (Exception e) {
                Timber.e(e, "Failed to mark contact as contacted.");
            }

            messagingController.sendMessage(account, message, plaintextSubject, null);
            if (draftId != null) {
                messagingController.deleteDraftSkippingTrashFolder(account, draftId);
            }

            return null;
        }

        /**
         * Set the flag on the referenced message(indicated we replied / forwarded the message)
         **/
        private void addFlagToReferencedMessage() {
            if (messageReference != null && flag != null) {
                String accountUuid = messageReference.getAccountUuid();
                Account account = preferences.getAccount(accountUuid);
                long folderId = messageReference.getFolderId();
                String sourceMessageUid = messageReference.getUid();

                Timber.d("Setting referenced message (%d, %s) flag to %s", folderId, sourceMessageUid, flag);

                messagingController.setFlag(account, folderId, sourceMessageUid, flag, true);
            }
        }
    }

}
