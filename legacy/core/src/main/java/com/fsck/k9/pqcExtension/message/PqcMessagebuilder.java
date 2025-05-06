package com.fsck.k9.pqcExtension.message;

import android.content.Context;
import android.content.Intent;
import android.os.Build;

import androidx.annotation.Nullable;
import androidx.annotation.RequiresApi;
import androidx.annotation.VisibleForTesting;

import app.k9mail.legacy.di.DI;
import com.fsck.k9.CoreResourceProvider;
import com.fsck.k9.K9;
import com.fsck.k9.autocrypt.AutocryptDraftStateHeader;
import com.fsck.k9.autocrypt.AutocryptOpenPgpApiInteractor;
import com.fsck.k9.autocrypt.AutocryptOperations;
import com.fsck.k9.logging.Timber;
import com.fsck.k9.mail.Body;
import com.fsck.k9.mail.BodyPart;
import com.fsck.k9.mail.BoundaryGenerator;
import com.fsck.k9.mail.MessagingException;
import com.fsck.k9.mail.internet.MessageIdGenerator;
import com.fsck.k9.mail.internet.MimeBodyPart;
import com.fsck.k9.mail.internet.MimeHeader;
import com.fsck.k9.mail.internet.MimeMessage;
import com.fsck.k9.mail.internet.MimeMessageHelper;
import com.fsck.k9.mail.internet.MimeMultipart;
import com.fsck.k9.mail.internet.MimeUtility;
import com.fsck.k9.mail.internet.TextBody;
import com.fsck.k9.mailstore.BinaryMemoryBody;
import com.fsck.k9.message.CryptoStatus;
import com.fsck.k9.message.MessageBuilder;
import com.fsck.k9.pqcExtension.helper.encryption.HybridEncryptionHelper;
import com.fsck.k9.pqcExtension.helper.signature.CompositeSignatureHelper;
import com.fsck.k9.pqcExtension.helper.PqcMessageHelper;
import com.fsck.k9.pqcExtension.keyManagement.manager.PgpSimpleKeyManager;
import com.fsck.k9.pqcExtension.keyManagement.SimpleKeyStoreFactory;
import org.apache.james.mime4j.util.MimeUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;


public class PqcMessagebuilder extends MessageBuilder {
    private MimeMessage currentProcessedMimeMessage;
    private MimeBodyPart messageContentBodyPart;
    private CryptoStatus cryptoStatus;
    private final Context context;
    private final String recipientEmail;
    public static PqcMessagebuilder newInstance(Context context,String recipientEmail) {
        MessageIdGenerator messageIdGenerator = MessageIdGenerator.getInstance();
        BoundaryGenerator boundaryGenerator = BoundaryGenerator.getInstance();
        AutocryptOperations autocryptOperations = AutocryptOperations.getInstance();
        AutocryptOpenPgpApiInteractor autocryptOpenPgpApiInteractor = AutocryptOpenPgpApiInteractor.getInstance();
        CoreResourceProvider resourceProvider = DI.get(CoreResourceProvider.class);
        return new PqcMessagebuilder(messageIdGenerator, boundaryGenerator, autocryptOperations,
            autocryptOpenPgpApiInteractor, resourceProvider, context,recipientEmail);
    }

    @VisibleForTesting
    PqcMessagebuilder(MessageIdGenerator messageIdGenerator, BoundaryGenerator boundaryGenerator,
        AutocryptOperations autocryptOperations, AutocryptOpenPgpApiInteractor autocryptOpenPgpApiInteractor,
        CoreResourceProvider resourceProvider, Context context,String recipientEmail) {
        super(messageIdGenerator, boundaryGenerator, resourceProvider);
        this.context = context;
        this.recipientEmail=recipientEmail;
    }

    public void setCryptoStatus(CryptoStatus cryptoStatus) {
        this.cryptoStatus = cryptoStatus;
    }

    @RequiresApi(api = Build.VERSION_CODES.O)
    private MimeBodyPart mimeBuildSignedMessage(MimeBodyPart signedBodyPart, Map<String, byte[]> signatureMap) throws MessagingException {
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
                new BinaryMemoryBody(sigData, MimeUtil.ENC_7BIT),
                "application/pgp-signature; name=\"" + filename + "\""
            );
            sigPart.setHeader("Content-Transfer-Encoding", "7bit");
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
        return currentProcessedMimeMessage.toBodyPart();
    }

    private MimeBodyPart extractBodyPartFromCurrentMessage() throws MessagingException {
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

    private void mimeBuildEncryptedMessageHybridRFC(MimeBodyPart signedBodyPart) throws MessagingException {
        try {
            byte[] canonicalData = PqcMessageHelper.canonicalize(signedBodyPart);
            JSONObject keyData = SimpleKeyStoreFactory.getKeyStore(SimpleKeyStoreFactory.KeyType.PQC_KEM)
                .loadRemotePublicKey(context, recipientEmail);

            String pqcAlg = keyData.getString("algorithm");
            byte[] pqcPubKey = Base64.getDecoder().decode(keyData.getString("publicKey"));

            String pgpPublicKeyArmored = SimpleKeyStoreFactory.getKeyStore(SimpleKeyStoreFactory.KeyType.PGP)
                .loadRemotePublicKeyArmoredString(context, recipientEmail);
            if (Security.getProvider("BC") == null) {
                Security.addProvider(new BouncyCastleProvider());
            }
            PGPPublicKeyRing pgpRing = PgpSimpleKeyManager.parsePublicKeyRing(pgpPublicKeyArmored);
            PGPPublicKey rsaPubKey = null;
            for (PGPPublicKey key : pgpRing) {
                if (key.isEncryptionKey()) {
                    rsaPubKey = key;
                    break;
                }
            }
            if (rsaPubKey == null) throw new MessagingException("Kein gültiger RSA-Schlüssel gefunden");

            // 1. Verschlüsseln mit Hybrid-KEM (RSA + PQC) + AES
            HybridEncryptionHelper.HybridKEMResult kemResult = HybridEncryptionHelper.encapsulateBoth(rsaPubKey, pqcPubKey, pqcAlg);
            byte[] encryptedPayload = HybridEncryptionHelper.encryptWithAes(canonicalData, kemResult.sessionKey);

            // 2. multipart/encrypted erstellen (RFC 4880)
            MimeMultipart multipartEncrypted = createMimeMultipart();
            multipartEncrypted.setSubType("encrypted");

            // Part 1: "Version: 1"
            MimeBodyPart versionPart = MimeBodyPart.create(
                new TextBody("Version: 1"), "application/pgp-encrypted"
            );
            multipartEncrypted.addBodyPart(versionPart);

            // Part 2: verschlüsselter Body
            String base64Encoded = Base64.getEncoder().encodeToString(encryptedPayload);
            BinaryMemoryBody body = new BinaryMemoryBody(base64Encoded.getBytes(StandardCharsets.US_ASCII), MimeUtil.ENC_7BIT);
            MimeBodyPart encryptedPart = new MimeBodyPart();
            encryptedPart.setBody(body);
            encryptedPart.setHeader("Content-Type", "application/octet-stream; name=\"encrypted.asc\"");
            encryptedPart.setHeader("Content-Disposition", "inline; filename=\"encrypted.asc\"");
            encryptedPart.setHeader("Content-Transfer-Encoding", "base64");
            multipartEncrypted.addBodyPart(encryptedPart);

            // 3. Setze Body + Content-Type
            MimeMessageHelper.setBody(currentProcessedMimeMessage, multipartEncrypted);
            String contentType = String.format(
                "multipart/encrypted; boundary=\"%s\";\r\n  protocol=\"application/pgp-encrypted\"",
                multipartEncrypted.getBoundary()
            );
            currentProcessedMimeMessage.setHeader(MimeHeader.HEADER_CONTENT_TYPE, contentType);

            // 4. Optional: KEM-Info als Header (nicht als eigene MIME-Parts!)
            String foldedRsa = HybridEncryptionHelper.foldHeaderValue(Base64.getEncoder().encodeToString(kemResult.rsaCiphertext));
            String foldedPqc = HybridEncryptionHelper.foldHeaderValue(Base64.getEncoder().encodeToString(kemResult.pqcCiphertext));
            currentProcessedMimeMessage.setHeader("X-Hybrid-RSA", foldedRsa);
            currentProcessedMimeMessage.setHeader("X-Hybrid-PQC", foldedPqc);

            // (Optional) besser lesbar:
            currentProcessedMimeMessage.setHeader("X-Pgp-Hybrid-Pqc", "true");
            currentProcessedMimeMessage.setHeader("MIME-Version", "1.0");
            currentProcessedMimeMessage.setHeader("Content-Transfer-Encoding", "7bit");

        } catch (Exception e) {
            throw new MessagingException("Hybrid-RFC-Verschlüsselung fehlgeschlagen", e);
        }
    }


    @Override
    protected void buildMessageInternal() {
        try {
            currentProcessedMimeMessage = build();

            if (messageContentBodyPart == null) {
                messageContentBodyPart = extractBodyPartFromCurrentMessage();
            }
            startOrContinueBuildMessage(null);
        } catch (MessagingException me) {
            queueMessageBuildException(me);
            return;
        }
    }

    private void startOrContinueBuildMessage(@Nullable Intent intent) {
        if (currentProcessedMimeMessage == null) {
            throw new IllegalStateException("currentProcessedMimeMessage must be built before continuing!");
        }

        if (cryptoStatus == null || getAccount() == null) {
            throw new IllegalStateException("PqcMessagebuilder must have cryptoStatus and account set before building!");
        }

        try {
            boolean shouldSign = cryptoStatus.isSignPqcHybridEnabled();
            boolean shouldEncrypt = cryptoStatus.isEncryptPqcHybridEnabled();

            if (shouldSign && shouldEncrypt) {
                // 1. Signieren
                byte[] canonicalData = PqcMessageHelper.canonicalize(messageContentBodyPart);
                CompositeSignatureHelper signatureHelper = new CompositeSignatureHelper(getAccount().getUuid(), context);
                Map<String, byte[]> signatureMap = signatureHelper.signAll(canonicalData);

                mimeBuildEncryptedMessageHybridRFC(mimeBuildSignedMessage(messageContentBodyPart, signatureMap));

            } else if (shouldSign) {
                byte[] canonicalData = PqcMessageHelper.canonicalize(messageContentBodyPart);
                Timber.d("PQC: Canonicalized data (sign): %s", new String(canonicalData, StandardCharsets.UTF_8));
                CompositeSignatureHelper signatureHelper = new CompositeSignatureHelper(getAccount().getUuid(), context);
                Map<String, byte[]> signatureMap = signatureHelper.signAll(canonicalData);
                mimeBuildSignedMessage(messageContentBodyPart, signatureMap);
            } else if (shouldEncrypt) {
                mimeBuildEncryptedMessageHybridRFC(messageContentBodyPart);
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
        startOrContinueBuildMessage(data);
    }
}
