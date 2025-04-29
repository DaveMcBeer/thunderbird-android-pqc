package com.fsck.k9.message;


import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;

import android.annotation.SuppressLint;
import android.app.PendingIntent;
import android.content.Intent;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.VisibleForTesting;
import androidx.core.content.IntentCompat;
import app.k9mail.legacy.account.Account;
import com.fsck.k9.CoreResourceProvider;
import app.k9mail.legacy.di.DI;
import com.fsck.k9.K9;
import com.fsck.k9.autocrypt.AutocryptDraftStateHeader;
import com.fsck.k9.autocrypt.AutocryptOpenPgpApiInteractor;
import com.fsck.k9.autocrypt.AutocryptOperations;
import com.fsck.k9.mail.Address;
import com.fsck.k9.mail.Body;
import com.fsck.k9.mail.BodyPart;
import com.fsck.k9.mail.BoundaryGenerator;
import com.fsck.k9.mail.Message.RecipientType;
import com.fsck.k9.mail.MessagingException;
import com.fsck.k9.mail.filter.EOLConvertingOutputStream;
import com.fsck.k9.mail.internet.BinaryTempFileBody;
import com.fsck.k9.mail.internet.MessageIdGenerator;
import com.fsck.k9.mail.internet.MimeBodyPart;
import com.fsck.k9.mail.internet.MimeHeader;
import com.fsck.k9.mail.internet.MimeMessage;
import com.fsck.k9.mail.internet.MimeMessageHelper;
import com.fsck.k9.mail.internet.MimeMultipart;
import com.fsck.k9.mail.internet.MimeUtility;
import com.fsck.k9.mail.internet.TextBody;
import com.fsck.k9.mailstore.BinaryMemoryBody;
import com.fsck.k9.message.pqc.CryptoUtils;
import com.fsck.k9.message.pqc.PqcContactStore;
import com.fsck.k9.message.pqc.PqcKemHelper;
import com.fsck.k9.message.pqc.PqcMessageHelper;
import org.apache.commons.io.IOUtils;
import org.apache.james.mime4j.util.MimeUtil;
import org.openintents.openpgp.OpenPgpError;
import org.openintents.openpgp.util.OpenPgpApi;
import org.openintents.openpgp.util.OpenPgpApi.OpenPgpDataSource;
import org.openquantumsafe.Signature;
import timber.log.Timber;


public class PgpMessageBuilder extends MessageBuilder {
    private static final int REQUEST_USER_INTERACTION = 1;
    private static final String REPLACEMENT_SUBJECT = "[...]";


    private final AutocryptOperations autocryptOperations;
    private final AutocryptOpenPgpApiInteractor autocryptOpenPgpApiInteractor;


    private OpenPgpApi openPgpApi;

    private MimeMessage currentProcessedMimeMessage;
    private MimeBodyPart messageContentBodyPart;
    private CryptoStatus cryptoStatus;

    public static PgpMessageBuilder newInstance() {
        MessageIdGenerator messageIdGenerator = MessageIdGenerator.getInstance();
        BoundaryGenerator boundaryGenerator = BoundaryGenerator.getInstance();
        AutocryptOperations autocryptOperations = AutocryptOperations.getInstance();
        AutocryptOpenPgpApiInteractor autocryptOpenPgpApiInteractor = AutocryptOpenPgpApiInteractor.getInstance();
        CoreResourceProvider resourceProvider = DI.get(CoreResourceProvider.class);
        return new PgpMessageBuilder(messageIdGenerator, boundaryGenerator, autocryptOperations,
            autocryptOpenPgpApiInteractor, resourceProvider);
    }

    @VisibleForTesting
    PgpMessageBuilder(MessageIdGenerator messageIdGenerator, BoundaryGenerator boundaryGenerator,
        AutocryptOperations autocryptOperations, AutocryptOpenPgpApiInteractor autocryptOpenPgpApiInteractor,
        CoreResourceProvider resourceProvider) {
        super(messageIdGenerator, boundaryGenerator, resourceProvider);

        this.autocryptOperations = autocryptOperations;
        this.autocryptOpenPgpApiInteractor = autocryptOpenPgpApiInteractor;
    }


    public void setOpenPgpApi(OpenPgpApi openPgpApi) {
        this.openPgpApi = openPgpApi;
    }
        @Override
    protected void buildMessageInternal() {
        if (currentProcessedMimeMessage != null) {
            throw new IllegalStateException("message can only be built once!");
        }
        if (cryptoStatus == null) {
            throw new IllegalStateException("PgpMessageBuilder must have cryptoStatus set before building!");
        }

        Long openPgpKeyId = cryptoStatus.getOpenPgpKeyId();
        try {
            currentProcessedMimeMessage = build();
        } catch (MessagingException me) {
            queueMessageBuildException(me);
            return;
        }

        if (openPgpKeyId == null) {
            queueMessageBuildSuccess(currentProcessedMimeMessage);
            return;
        }

        if (!cryptoStatus.isProviderStateOk()) {
            queueMessageBuildException(new MessagingException("OpenPGP Provider is not ready!"));
            return;
        }

        addAutocryptHeaderIfAvailable(openPgpKeyId);
        if (isDraft()) {
            addDraftStateHeader();
        }
        startOrContinueBuildMessage(null);
    }

    private void addAutocryptHeaderIfAvailable(long openPgpKeyId) {
        Address address = currentProcessedMimeMessage.getFrom()[0];
        byte[] keyData = autocryptOpenPgpApiInteractor.getKeyMaterialForKeyId(
            openPgpApi, openPgpKeyId, address.getAddress());
        if (keyData != null) {
            autocryptOperations.addAutocryptHeaderToMessage(currentProcessedMimeMessage, keyData,
                address.getAddress(), cryptoStatus.isSenderPreferEncryptMutual());
        }
    }

    private void addDraftStateHeader() {
        AutocryptDraftStateHeader autocryptDraftStateHeader =
            AutocryptDraftStateHeader.fromCryptoStatus(cryptoStatus);
        currentProcessedMimeMessage.setHeader(AutocryptDraftStateHeader.AUTOCRYPT_DRAFT_STATE_HEADER,
            autocryptDraftStateHeader.toHeaderValue());
    }

    @Override
    public void buildMessageOnActivityResult(int requestCode, @NonNull Intent userInteractionResult) {
        if (currentProcessedMimeMessage == null) {
            throw new AssertionError("build message from activity result must not be called individually");
        }
        startOrContinueBuildMessage(userInteractionResult);
    }

    private void startOrContinueBuildMessage(@Nullable Intent pgpApiIntent) {
        try {

            boolean shouldSign = cryptoStatus.isSigningEnabled() && !isDraft();
            boolean shouldEncrypt = cryptoStatus.isEncryptionEnabled() || (isDraft() && cryptoStatus.isEncryptAllDrafts());
            boolean isPgpInlineMode = cryptoStatus.isPgpInlineModeEnabled() && !isDraft();

            if (!shouldSign && !shouldEncrypt) {
                queueMessageBuildSuccess(currentProcessedMimeMessage);
                return;
            }

            boolean isSimpleTextMessage =
                MimeUtility.isSameMimeType("text/plain", currentProcessedMimeMessage.getMimeType());
            if (isPgpInlineMode && !isSimpleTextMessage) {
                throw new MessagingException("Attachments are not supported in PGP/INLINE format!");
            }

            if (shouldEncrypt && !isDraft() && !cryptoStatus.hasRecipients()) {
                throw new MessagingException("Must have recipients to build message!");
            }

            if (messageContentBodyPart == null) {
                messageContentBodyPart = createBodyPartFromMessageContent();

                boolean payloadSupportsMimeHeaders = !isPgpInlineMode;
                if (payloadSupportsMimeHeaders) {
                    if (cryptoStatus.isEncryptSubject() && shouldEncrypt) {
                        moveSubjectIntoEncryptedPayload();
                    }
                    maybeAddGossipHeadersToBodyPart();

                    // unfortuntately, we can't store the Autocrypt-Draft-State header in the payload
                    // see https://github.com/autocrypt/autocrypt/pull/376#issuecomment-384293480
                }
            }

            if (pgpApiIntent == null) {
                boolean encryptToSelfOnly = isDraft();
                pgpApiIntent = buildOpenPgpApiIntent(shouldSign, shouldEncrypt, encryptToSelfOnly, isPgpInlineMode);
            }

            PendingIntent returnedPendingIntent = launchOpenPgpApiIntent(pgpApiIntent, messageContentBodyPart,
                shouldEncrypt || isPgpInlineMode, shouldEncrypt || !isPgpInlineMode, isPgpInlineMode);
            if (returnedPendingIntent != null) {
                queueMessageBuildPendingIntent(returnedPendingIntent, REQUEST_USER_INTERACTION);
                return;
            }

            queueMessageBuildSuccess(currentProcessedMimeMessage);
        } catch (MessagingException me) {
            queueMessageBuildException(me);
        }
    }

    private MimeBodyPart createBodyPartFromMessageContent() throws MessagingException {
        MimeBodyPart bodyPart = currentProcessedMimeMessage.toBodyPart();
        String[] contentType = currentProcessedMimeMessage.getHeader(MimeHeader.HEADER_CONTENT_TYPE);
        if (contentType.length > 0) {
            bodyPart.setHeader(MimeHeader.HEADER_CONTENT_TYPE, contentType[0]);
        }
        if (isDraft()) {
            String[] identityHeader = currentProcessedMimeMessage.getHeader(K9.IDENTITY_HEADER);
            bodyPart.setHeader(K9.IDENTITY_HEADER, identityHeader[0]);
            currentProcessedMimeMessage.removeHeader(K9.IDENTITY_HEADER);
        }

        return bodyPart;
    }

    private void moveSubjectIntoEncryptedPayload() {
        String[] subjects = currentProcessedMimeMessage.getHeader(MimeHeader.SUBJECT);
        if (subjects.length > 0) {
            messageContentBodyPart.setHeader(MimeHeader.HEADER_CONTENT_TYPE,
                messageContentBodyPart.getContentType() + "; protected-headers=\"v1\"");
            messageContentBodyPart.setHeader(MimeHeader.SUBJECT, subjects[0]);
            currentProcessedMimeMessage.setSubject(REPLACEMENT_SUBJECT);
        }
    }

    private void maybeAddGossipHeadersToBodyPart() {
        if (!cryptoStatus.isEncryptionEnabled()) {
            return;
        }
        String[] recipientAddresses = getCryptoRecipientsWithoutBcc();
        boolean hasMultipleOvertRecipients = recipientAddresses.length >= 2;
        if (hasMultipleOvertRecipients) {
            addAutocryptGossipHeadersToPart(messageContentBodyPart, recipientAddresses);
        }
    }

    private String[] getCryptoRecipientsWithoutBcc() {
        ArrayList<String> recipientAddresses = new ArrayList<>(Arrays.asList(cryptoStatus.getRecipientAddresses()));
        Address[] bccAddresses = currentProcessedMimeMessage.getRecipients(RecipientType.BCC);
        for (Address bccAddress : bccAddresses) {
            recipientAddresses.remove(bccAddress.getAddress());
        }
        return recipientAddresses.toArray(new String[recipientAddresses.size()]);
    }

    private void addAutocryptGossipHeadersToPart(MimeBodyPart bodyPart, String[] addresses) {
        for (String address : addresses) {
            byte[] keyMaterial = autocryptOpenPgpApiInteractor.getKeyMaterialForUserId(openPgpApi, address);
            if (keyMaterial == null) {
                Timber.e("Failed fetching gossip key material for address %s", address);
                continue;
            }
            autocryptOperations.addAutocryptGossipHeaderToPart(bodyPart, keyMaterial, address);
        }
    }

    @NonNull
    private Intent buildOpenPgpApiIntent(boolean shouldSign, boolean shouldEncrypt, boolean encryptToSelfOnly,
        boolean isPgpInlineMode) {
        Intent pgpApiIntent;

        Long openPgpKeyId = cryptoStatus.getOpenPgpKeyId();
        if (shouldEncrypt) {
            pgpApiIntent = new Intent(shouldSign ? OpenPgpApi.ACTION_SIGN_AND_ENCRYPT : OpenPgpApi.ACTION_ENCRYPT);

            long[] selfEncryptIds = { openPgpKeyId };
            pgpApiIntent.putExtra(OpenPgpApi.EXTRA_KEY_IDS, selfEncryptIds);

            if(!encryptToSelfOnly) {
                pgpApiIntent.putExtra(OpenPgpApi.EXTRA_USER_IDS, cryptoStatus.getRecipientAddresses());
//                pgpApiIntent.putExtra(OpenPgpApi.EXTRA_ENCRYPT_OPPORTUNISTIC, cryptoStatus.isEncryptionOpportunistic());
            }
        } else {
            pgpApiIntent = new Intent(isPgpInlineMode ? OpenPgpApi.ACTION_SIGN : OpenPgpApi.ACTION_DETACHED_SIGN);
        }

        if (shouldSign) {
            pgpApiIntent.putExtra(OpenPgpApi.EXTRA_SIGN_KEY_ID, openPgpKeyId);
        }

        pgpApiIntent.putExtra(OpenPgpApi.EXTRA_REQUEST_ASCII_ARMOR, true);
        return pgpApiIntent;
    }

    private PendingIntent launchOpenPgpApiIntent(@NonNull Intent openPgpIntent, MimeBodyPart bodyPart,
        boolean captureOutputPart, boolean capturedOutputPartIs7Bit, boolean writeBodyContentOnly) throws MessagingException {
        OpenPgpDataSource dataSource = createOpenPgpDataSourceFromBodyPart(bodyPart, writeBodyContentOnly);

        BinaryTempFileBody pgpResultTempBody = null;
        OutputStream outputStream = null;
        if (captureOutputPart) {
            try {
                pgpResultTempBody = new BinaryTempFileBody(
                    capturedOutputPartIs7Bit ? MimeUtil.ENC_7BIT : MimeUtil.ENC_8BIT);
                outputStream = pgpResultTempBody.getOutputStream();
                // OpenKeychain/BouncyCastle at this point use the system newline for formatting, which is LF on android.
                // we need this to be CRLF, so we convert the data after receiving.
                outputStream = new EOLConvertingOutputStream(outputStream);
            } catch (IOException e) {
                throw new MessagingException("could not allocate temp file for storage!", e);
            }
        }

        Intent result = openPgpApi.executeApi(openPgpIntent, dataSource, outputStream);

        switch (result.getIntExtra(OpenPgpApi.RESULT_CODE, OpenPgpApi.RESULT_CODE_ERROR)) {
            case OpenPgpApi.RESULT_CODE_SUCCESS:
                mimeBuildMessage(result, bodyPart, pgpResultTempBody);
                return null;

            case OpenPgpApi.RESULT_CODE_USER_INTERACTION_REQUIRED:
                PendingIntent returnedPendingIntent = IntentCompat.getParcelableExtra(
                    result,
                    OpenPgpApi.RESULT_INTENT,
                    PendingIntent.class
                );
                if (returnedPendingIntent == null) {
                    throw new MessagingException("openpgp api needs user interaction, but returned no pendingintent!");
                }
                return returnedPendingIntent;

            case OpenPgpApi.RESULT_CODE_ERROR:
                OpenPgpError error = IntentCompat.getParcelableExtra(
                    result,
                    OpenPgpApi.RESULT_ERROR,
                    OpenPgpError.class
                );
                if (error == null) {
                    throw new MessagingException("internal openpgp api error");
                }
                /*
                boolean isOpportunisticError = error.getErrorId() == OpenPgpError.OPPORTUNISTIC_MISSING_KEYS;
                if (isOpportunisticError) {
                    if (!cryptoStatus.isEncryptionOpportunistic()) {
                        throw new IllegalStateException(
                                "Got opportunistic error, but encryption wasn't supposed to be opportunistic!");
                    }
                    Timber.d("Skipping encryption due to opportunistic mode");
                    return null;
                }
                */
                throw new MessagingException(error.getMessage());
        }

        throw new IllegalStateException("unreachable code segment reached");
    }

    @NonNull
    private OpenPgpDataSource createOpenPgpDataSourceFromBodyPart(final MimeBodyPart bodyPart,
        final boolean writeBodyContentOnly)
        throws MessagingException {
        return new OpenPgpDataSource() {
            @Override
            public void writeTo(OutputStream os) throws IOException {
                try {
                    if (writeBodyContentOnly) {
                        Body body = bodyPart.getBody();
                        InputStream inputStream = body.getInputStream();
                        IOUtils.copy(inputStream, os);
                    } else {
                        bodyPart.writeTo(os);
                    }
                } catch (MessagingException e) {
                    throw new IOException(e);
                }
            }
        };
    }

    private void mimeBuildMessage(
        @NonNull Intent result, @NonNull MimeBodyPart bodyPart, @Nullable BinaryTempFileBody pgpResultTempBody)
        throws MessagingException {
        if (pgpResultTempBody == null) {
            boolean shouldHaveResultPart = cryptoStatus.isPgpInlineModeEnabled() || cryptoStatus.isEncryptionEnabled();
            if (shouldHaveResultPart) {
                throw new AssertionError("encryption or pgp/inline is enabled, but no output part!");
            }

            mimeBuildSignedMessage(bodyPart, result);
            return;
        }

        if (!isDraft() && cryptoStatus.isPgpInlineModeEnabled()) {
            mimeBuildInlineMessage(pgpResultTempBody);
            return;
        }

        mimeBuildEncryptedMessage(pgpResultTempBody);
    }

    private void mimeBuildSignedMessage(@NonNull BodyPart signedBodyPart, Intent result) throws MessagingException {
        if (!cryptoStatus.isSigningEnabled()) {
            throw new IllegalStateException("call to mimeBuildSignedMessage while signing isn't enabled!");
        }

        byte[] signedData = result.getByteArrayExtra(OpenPgpApi.RESULT_DETACHED_SIGNATURE);
        if (signedData == null) {
            throw new MessagingException("didn't find expected RESULT_DETACHED_SIGNATURE in api call result");
        }

        // === Multipart/Signed erstellen ===
        MimeMultipart multipartSigned = createMimeMultipart();
        multipartSigned.setSubType("signed");
        multipartSigned.addBodyPart(signedBodyPart);
        multipartSigned.addBodyPart(
            MimeBodyPart.create(new BinaryMemoryBody(signedData, MimeUtil.ENC_7BIT),
                "application/pgp-signature; name=\"signature.asc\""));

        String signedContentType = String.format(
            "multipart/signed; boundary=\"%s\";\r\n  protocol=\"application/pgp-signature\"",
            multipartSigned.getBoundary());

        if (result.hasExtra(OpenPgpApi.RESULT_SIGNATURE_MICALG)) {
            String micAlg = result.getStringExtra(OpenPgpApi.RESULT_SIGNATURE_MICALG);
            signedContentType += String.format("; micalg=\"%s\"", micAlg);
        } else {
            Timber.e("missing micalg parameter for pgp multipart/signed!");
        }

        // multipart/signed als BodyPart kapseln
        MimeBodyPart pgpSignedBodyPart = new MimeBodyPart(multipartSigned);
        pgpSignedBodyPart.setHeader(MimeHeader.HEADER_CONTENT_TYPE, signedContentType);


        //--- PQC Erweiterung ---
        Account account = getAccount();
        if (account != null && account.isPqcSigningEnabled()) {
            try {
                // PQC-Signatur berechnen
                byte[] canonicalBytes = PqcMessageHelper.canonicalize(this.messageContentBodyPart);
                byte[] pqcSignatureBytes = generateSignature(canonicalBytes);
                byte[] pqcPublicKeyBytes = generatePublicKey();

                String armoredSig = PqcMessageHelper.toAsciiArmor(pqcSignatureBytes, "PQC SIGNATURE");
                String armoredKey = PqcMessageHelper.toAsciiArmor(pqcPublicKeyBytes, "PQC PUBLIC KEY");



                MimeMultipart multipartMixed = createMimeMultipart();
                multipartMixed.setSubType("mixed");
                multipartMixed.addBodyPart(pgpSignedBodyPart);

                multipartMixed.addBodyPart(
                    MimeBodyPart.create(new BinaryMemoryBody(armoredSig.getBytes(StandardCharsets.US_ASCII), MimeUtil.ENC_7BIT),
                        "application/pqc-signature; name=\"pqc_signature.asc\""));

                multipartMixed.addBodyPart(
                    MimeBodyPart.create(new BinaryMemoryBody(armoredKey.getBytes(StandardCharsets.US_ASCII), MimeUtil.ENC_7BIT),
                        "application/pqc-signature; name=\"pqc_public_key.asc\""));

                MimeMessageHelper.setBody(currentProcessedMimeMessage, multipartMixed);

                currentProcessedMimeMessage.setHeader(MimeHeader.HEADER_CONTENT_TYPE,
                    String.format("multipart/mixed; boundary=\"%s\"", multipartMixed.getBoundary()));

                currentProcessedMimeMessage.setHeader("X-PQC-Signature-Algorithm", account.getPqcSigningAlgorithm());
                return;
            } catch (Exception e) {
                Timber.e(e, "Fehler beim Hinzufügen von PQC-Signaturen – sende nur PGP");
            }
        }

        // === Fallback nur PGP ===
        MimeMessageHelper.setBody(currentProcessedMimeMessage, multipartSigned);
        currentProcessedMimeMessage.setHeader(MimeHeader.HEADER_CONTENT_TYPE, signedContentType);
    }

    private void mimeBuildEncryptedMessage(@NonNull Body encryptedBodyPart) throws MessagingException {
        MimeMultipart multipartEncrypted = createMimeMultipart();
        multipartEncrypted.setSubType("encrypted");
        multipartEncrypted.addBodyPart(MimeBodyPart.create(new TextBody("Version: 1"), "application/pgp-encrypted"));
        MimeBodyPart encryptedPart = MimeBodyPart.create(encryptedBodyPart, "application/octet-stream; name=\"encrypted.asc\"");
        encryptedPart.addHeader(MimeHeader.HEADER_CONTENT_DISPOSITION, "inline; filename=\"encrypted.asc\"");
        multipartEncrypted.addBodyPart(encryptedPart);
        MimeMessageHelper.setBody(currentProcessedMimeMessage, multipartEncrypted);

        String contentType = String.format(
            "multipart/encrypted; boundary=\"%s\";\r\n  protocol=\"application/pgp-encrypted\"",
            multipartEncrypted.getBoundary());
        currentProcessedMimeMessage.setHeader(MimeHeader.HEADER_CONTENT_TYPE, contentType);


        //--- PQC Erweiterung---
        attachPqcKemCiphertextsForAllRecipients(currentProcessedMimeMessage);
        //--- ENDE ---
    }

    private void mimeBuildInlineMessage(@NonNull Body inlineBodyPart) throws MessagingException {
        if (!cryptoStatus.isPgpInlineModeEnabled()) {
            throw new IllegalStateException("call to mimeBuildInlineMessage while pgp/inline isn't enabled!");
        }

        boolean isCleartextSignature = !cryptoStatus.isEncryptionEnabled();
        if (isCleartextSignature) {
            inlineBodyPart.setEncoding(MimeUtil.ENC_QUOTED_PRINTABLE);
        }
        MimeMessageHelper.setBody(currentProcessedMimeMessage, inlineBodyPart);
    }

    public void setCryptoStatus(CryptoStatus cryptoStatus) {
        this.cryptoStatus = cryptoStatus;
    }


    //--- PQC Erweiterung ---

    /**
     * Signiert den normalisierten Nachrichtentext mit dem PQC-Algorithmus.
     */
    @SuppressLint("BinaryOperationInTimber")
    private byte[] generateSignature(byte[] dataToSign) throws MessagingException {
        ensureAccountConfigured();
        Account account = getAccount();
        byte[] secretKey = Base64.getMimeDecoder().decode(account.getPqcSecretSigningKey());
        Signature signature = new Signature(account.getPqcSigningAlgorithm(), secretKey);

        byte[] signatureArray = signature.sign(dataToSign);
        signature.dispose_sig();
        return signatureArray;
    }
    /**
     * Bereitet den öffentlichen Schlüssel als ASCII-armored Text auf.
     */
    private byte[] generatePublicKey() throws MessagingException {
        ensureAccountConfigured();
        Account account = getAccount();
        return Base64.getMimeDecoder().decode(account.getPqcPublicSigngingKey());
    }


    /**
     * Prüft, ob der Account korrekt für PQC konfiguriert ist.
     */
    private void ensureAccountConfigured() throws MessagingException {
        Account account = getAccount();
        if (account == null || account.getPqcSigningAlgorithm() == null || account.getPqcSigningAlgorithm().equals("None")) {
            throw new MessagingException("PQC Account or algorithm not properly configured");
        }
        if (account.getPqcKeysetExists() == null || !account.getPqcKeysetExists()) {
            throw new MessagingException("No PQC Keyset exists, please generate or import in account settings");
        }
    }

    private void attachPqcKemCiphertextsForAllRecipients(MimeMessage message) {
        try {
            Address[] recipients = message.getRecipients(RecipientType.TO);
            if (recipients == null || recipients.length == 0) {
                Timber.w("No recipients, skipping PQC KEM encapsulation.");
                return;
            }

            for (Address recipient : recipients) {
                String email = recipient.getAddress();

                byte[] publicKey = PqcContactStore.INSTANCE.getPublicKey(email);
                String kemAlgorithm = PqcContactStore.INSTANCE.getKemAlgorithm(email);

                if (publicKey == null || kemAlgorithm == null) {
                    Timber.w("No PQC KEM Public Key found for %s, skipping.", email);
                    continue;
                }

                // 1. PQC Encapsulation
                PqcKemHelper.EncapsulationResult encapsulation = PqcKemHelper.encapsulate(publicKey, kemAlgorithm);
                byte[] ciphertext = encapsulation.getCiphertext();
                byte[] rawSharedSecret = encapsulation.getSharedSecret();

                // 2. Session-Key durch HKDF ableiten (GENAU wie beim Empfang!)
                byte[] sessionKey = CryptoUtils.INSTANCE.hkdfSha256(rawSharedSecret, "PQC-KEM-OpenPGP", 32);
                String sessionKeyString = Base64.getEncoder().encodeToString(sessionKey);
                Timber.w("Pqc Kem sessionkey sender:%s",sessionKeyString);
                // 3. Session Key speichern
                PqcContactStore.INSTANCE.saveSharedSecret(email, sessionKey);

                // 4. Ciphertext base64 codieren und anhängen
                String base64Ciphertext = PqcMessageHelper.encodeBase64Mime(ciphertext);
                MimeBodyPart kemCiphertextPart = MimeBodyPart.create(
                    new BinaryMemoryBody(base64Ciphertext.getBytes(StandardCharsets.US_ASCII), MimeUtil.ENC_7BIT),
                    "application/pqc-kem-encapsulation; algorithm=" + kemAlgorithm + "; recipient=\"" + email + "\""
                );
                kemCiphertextPart.setHeader(MimeHeader.HEADER_CONTENT_DISPOSITION, "attachment; filename=\"kem_ct_" + email + ".bin\"");


                // Multipart hinzufügen
                Body body = message.getBody();
                if (body instanceof MimeMultipart) {
                    ((MimeMultipart) body).addBodyPart(kemCiphertextPart);
                } else {
                    MimeMultipart multipart = createMimeMultipart();
                    multipart.setSubType("mixed");

                    multipart.addBodyPart(MimeBodyPart.create(body));
                    multipart.addBodyPart(kemCiphertextPart);

                    MimeMessageHelper.setBody(message, multipart);
                }
            }
        } catch (Exception e) {
            Timber.e(e, "Error attaching PQC KEM ciphertexts");
        }
    }



    //--- ENDE ---
}
