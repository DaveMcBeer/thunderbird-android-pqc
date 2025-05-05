package com.fsck.k9.pqcExtension.message;

import android.content.Context;
import android.content.Intent;
import android.os.Build;
import androidx.annotation.RequiresApi;
import androidx.annotation.VisibleForTesting;

import app.k9mail.legacy.di.DI;
import com.fsck.k9.CoreResourceProvider;
import com.fsck.k9.K9;
import com.fsck.k9.autocrypt.AutocryptDraftStateHeader;
import com.fsck.k9.autocrypt.AutocryptOpenPgpApiInteractor;
import com.fsck.k9.autocrypt.AutocryptOperations;
import com.fsck.k9.logging.Timber;
import com.fsck.k9.mail.BoundaryGenerator;
import com.fsck.k9.mail.MessagingException;
import com.fsck.k9.mail.internet.MessageIdGenerator;
import com.fsck.k9.mail.internet.MimeBodyPart;
import com.fsck.k9.mail.internet.MimeHeader;
import com.fsck.k9.mail.internet.MimeMessage;
import com.fsck.k9.mail.internet.MimeMessageHelper;
import com.fsck.k9.mail.internet.MimeMultipart;
import com.fsck.k9.mailstore.BinaryMemoryBody;
import com.fsck.k9.message.CryptoStatus;
import com.fsck.k9.message.MessageBuilder;
import com.fsck.k9.pqcExtension.helper.signature.CompositeSignatureHelper;
import com.fsck.k9.pqcExtension.helper.PqcMessageHelper;
import org.apache.james.mime4j.util.MimeUtil;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;
import java.util.Map;

public class PqcMessagebuilder extends MessageBuilder {
    private MimeMessage currentProcessedMimeMessage;
    private MimeBodyPart messageContentBodyPart;
    private CryptoStatus cryptoStatus;
    private final Context context;

    public static PqcMessagebuilder newInstance(Context context) {
        MessageIdGenerator messageIdGenerator = MessageIdGenerator.getInstance();
        BoundaryGenerator boundaryGenerator = BoundaryGenerator.getInstance();
        AutocryptOperations autocryptOperations = AutocryptOperations.getInstance();
        AutocryptOpenPgpApiInteractor autocryptOpenPgpApiInteractor = AutocryptOpenPgpApiInteractor.getInstance();
        CoreResourceProvider resourceProvider = DI.get(CoreResourceProvider.class);
        return new PqcMessagebuilder(messageIdGenerator, boundaryGenerator, autocryptOperations,
            autocryptOpenPgpApiInteractor, resourceProvider, context);
    }

    @VisibleForTesting
    PqcMessagebuilder(MessageIdGenerator messageIdGenerator, BoundaryGenerator boundaryGenerator,
        AutocryptOperations autocryptOperations, AutocryptOpenPgpApiInteractor autocryptOpenPgpApiInteractor,
        CoreResourceProvider resourceProvider, Context context) {
        super(messageIdGenerator, boundaryGenerator, resourceProvider);
        this.context = context;
    }

    public void setCryptoStatus(CryptoStatus cryptoStatus) {
        this.cryptoStatus = cryptoStatus;
    }

    public MimeMessage getProcessedMimeMessage() {
        return currentProcessedMimeMessage;
    }

    @RequiresApi(api = Build.VERSION_CODES.O)
    private void mimeBuildSignedMessage(MimeBodyPart signedBodyPart, Map<String, byte[]> signatureMap) throws MessagingException {
        MimeMultipart multipartSigned = createMimeMultipart();
        multipartSigned.setSubType("signed");

        multipartSigned.addBodyPart(signedBodyPart);

        for (Map.Entry<String, byte[]> entry : signatureMap.entrySet()) {
            String algorithm = entry.getKey();
            byte[] sigData = entry.getValue();

            String armorLabel = algorithm.equals("pgp") ? "PGP SIGNATURE" : "PQC SIGNATURE";
            String algorithmName = algorithm.toUpperCase();

            String armored;
            if (algorithm.equals("pgp")) {
                // Signatur ist bereits ASCII-armiert erzeugt worden
                armored = new String(sigData, StandardCharsets.US_ASCII);
            } else {
                // PQC-Signatur: manuell armieren mit Base64 + Header
                armored = PqcMessageHelper.armor(
                    Base64.getEncoder().encodeToString(sigData),
                    armorLabel,
                    getAccount().getPqcSigningAlgorithm()
                );
            }

            String filename = "signature-" + algorithm + ".asc";

            MimeBodyPart sigPart = MimeBodyPart.create(
                new BinaryMemoryBody(armored.getBytes(StandardCharsets.US_ASCII), MimeUtil.ENC_7BIT),
                "application/pgp-signature; name=\"" + filename + "\""
            );
            sigPart.setHeader("Content-Disposition", "inline; filename=\"" + filename + "\"");

            multipartSigned.addBodyPart(sigPart);
        }

        String signedContentType = String.format(
            "multipart/signed; boundary=\"%s\";\r\n  protocol=\"application/pgp-signature\"; micalg=\"pgp-sha512,pqc-%s\"",
            multipartSigned.getBoundary(),
            getAccount().getPqcSigningAlgorithm()
        );


        MimeMessageHelper.setBody(currentProcessedMimeMessage, multipartSigned);
        currentProcessedMimeMessage.setHeader(MimeHeader.HEADER_CONTENT_TYPE, signedContentType);
    }

    private MimeBodyPart createBodyPartFromMessageContent() throws MessagingException {
        MimeBodyPart bodyPart = currentProcessedMimeMessage.toBodyPart();
        String[] contentType = currentProcessedMimeMessage.getHeader(MimeHeader.HEADER_CONTENT_TYPE);
        if (contentType.length > 0) {
            bodyPart.setHeader(MimeHeader.HEADER_CONTENT_TYPE, contentType[0]);
        }
        if (isDraft()) {
            String[] identityHeader = currentProcessedMimeMessage.getHeader(K9.IDENTITY_HEADER);
            if (identityHeader.length > 0) {
                bodyPart.setHeader(K9.IDENTITY_HEADER, identityHeader[0]);
                currentProcessedMimeMessage.removeHeader(K9.IDENTITY_HEADER);
            }
        }
        return bodyPart;
    }

    @Override
    protected void buildMessageInternal() {
        if (currentProcessedMimeMessage != null) {
            throw new IllegalStateException("Message can only be built once!");
        }

        if (cryptoStatus == null || getAccount() == null) {
            throw new IllegalStateException("PqcMessagebuilder must have cryptoStatus and account set before building!");
        }

        try {
            currentProcessedMimeMessage = build();
            messageContentBodyPart = createBodyPartFromMessageContent();

            boolean shouldSign = cryptoStatus.isSignPqcHybridEnabled();
            boolean shouldEncrypt = cryptoStatus.isEncryptPqcHybridEnabled();

            if (shouldSign) {
                byte[] canonicalData = PqcMessageHelper.canonicalize(messageContentBodyPart);
                Timber.d("PQC: Canonicalized data (sign): %s", new String(canonicalData, StandardCharsets.UTF_8));
                CompositeSignatureHelper signatureHelper = new CompositeSignatureHelper(getAccount().getUuid(), context);
                Map<String, byte[]> signatureMap = signatureHelper.signAll(canonicalData);

                mimeBuildSignedMessage(messageContentBodyPart, signatureMap);
            } else if (shouldEncrypt) {
                queueMessageBuildException(new MessagingException("PQC encryption not yet implemented"));
                return;
            } else {
                MimeMessageHelper.setBody(currentProcessedMimeMessage, messageContentBodyPart.getBody());
            }

            if (isDraft()) {
                AutocryptDraftStateHeader draftStateHeader = AutocryptDraftStateHeader.fromCryptoStatus(cryptoStatus);
                currentProcessedMimeMessage.setHeader(
                    AutocryptDraftStateHeader.AUTOCRYPT_DRAFT_STATE_HEADER,
                    draftStateHeader.toHeaderValue()
                );
            }

            currentProcessedMimeMessage.setSentDate(new Date(), false);
            queueMessageBuildSuccess(currentProcessedMimeMessage);

        } catch (Exception e) {
            queueMessageBuildException(new MessagingException("Fehler beim Signieren mit PQC", e));
        }
    }

    @Override
    protected void buildMessageOnActivityResult(int requestCode, Intent data) {
        if (currentProcessedMimeMessage == null) {
            throw new AssertionError("Build must not be called individually from activity result");
        }

        try {
            byte[] canonicalData = null;
            canonicalData = PqcMessageHelper.canonicalize(messageContentBodyPart);
            CompositeSignatureHelper signatureHelper = new CompositeSignatureHelper(getAccount().getUuid(), context);
            Map<String, byte[]> signatureMap = null;

            signatureMap = signatureHelper.signAll(canonicalData);

            mimeBuildSignedMessage(messageContentBodyPart, signatureMap);
            queueMessageBuildSuccess(currentProcessedMimeMessage);

        } catch (Exception e) {
            queueMessageBuildException(new MessagingException("Fehler beim Signieren im ActivityResult", e));
        }
    }
}
