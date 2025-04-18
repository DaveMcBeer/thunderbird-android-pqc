package com.fsck.k9.message.pqc;

import android.content.Intent;
import androidx.annotation.NonNull;
import androidx.annotation.VisibleForTesting;
import app.k9mail.legacy.account.Account;
import com.fsck.k9.CoreResourceProvider;
import app.k9mail.legacy.di.DI;
import com.fsck.k9.logging.Timber;
import com.fsck.k9.mail.BodyPart;
import com.fsck.k9.mail.BoundaryGenerator;
import com.fsck.k9.mail.MessagingException;
import com.fsck.k9.mail.internet.MimeUtility;
import com.fsck.k9.mailstore.BinaryMemoryBody;
import com.fsck.k9.mail.internet.MessageIdGenerator;
import com.fsck.k9.mail.internet.MimeBodyPart;
import com.fsck.k9.mail.internet.MimeHeader;
import com.fsck.k9.mail.internet.MimeMessage;
import com.fsck.k9.mail.internet.MimeMessageHelper;
import com.fsck.k9.mail.internet.MimeMultipart;
import com.fsck.k9.message.CryptoStatus;
import com.fsck.k9.message.MessageBuilder;
import org.openquantumsafe.Signature;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Objects;

/**
 * Erweiterung des MessageBuilder für Post-Quantum-Kryptografie (PQC).
 * Unterstützt das Signieren und Verschlüsseln von Nachrichten mit PQC-Algorithmen (z. B. über liboqs).
 */
public class PqcMessageBuilder extends MessageBuilder {

    private static final String REPLACEMENT_SUBJECT = "[...]"; // Platzhalter, wenn Betreff verschlüsselt wird

    private MimeMessage currentProcessedMimeMessage;
    private MimeBodyPart messageContentBodyPart;

    private Account account;
    private CryptoStatus cryptoStatus;

    // Factory-Methode zum Erzeugen einer Instanz mit allen benötigten Abhängigkeiten
    public static PqcMessageBuilder newInstance() {
        MessageIdGenerator messageIdGenerator = MessageIdGenerator.getInstance();
        BoundaryGenerator boundaryGenerator = BoundaryGenerator.getInstance();
        CoreResourceProvider resourceProvider = DI.get(CoreResourceProvider.class);
        return new PqcMessageBuilder(messageIdGenerator, boundaryGenerator, resourceProvider);
    }

    // Konstruktor für Tests
    @VisibleForTesting
    PqcMessageBuilder(MessageIdGenerator messageIdGenerator, BoundaryGenerator boundaryGenerator,
        CoreResourceProvider resourceProvider) {
        super(messageIdGenerator, boundaryGenerator, resourceProvider);
    }

    public void setAccount(Account account) {
        this.account = account;
    }

    public void setCryptoStatus(CryptoStatus cryptoStatus) {
        this.cryptoStatus = cryptoStatus;
    }

    /**
     * Hauptmethode zum Erstellen der Nachricht.
     * Führt PQC-Signatur oder -Verschlüsselung durch, wenn konfiguriert.
     */
    @Override
    protected void buildMessageInternal() {
        if (currentProcessedMimeMessage != null) {
            throw new IllegalStateException("Message can only be built once!");
        }

        try {
            currentProcessedMimeMessage = build();
            messageContentBodyPart = createBodyPartFromMessageContent();

            if (cryptoStatus.isEncryptionEnabled() || cryptoStatus.isSigningEnabled()) {
                processCryptoMessage(); // PQC-Kryptografie anwenden
            } else {
                queueMessageBuildSuccess(currentProcessedMimeMessage);
            }

        } catch (MessagingException e) {
            queueMessageBuildException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Für PQC wird keine Benutzerinteraktion benötigt – direkte Weiterverarbeitung.
     */
    @Override
    protected void buildMessageOnActivityResult(int requestCode, Intent userInteractionResult) {
        try {
            processCryptoMessage();
        } catch (MessagingException e) {
            queueMessageBuildException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Entscheidet, ob verschlüsselt oder signiert werden soll, und ruft entsprechende Methode auf.
     */
    private void processCryptoMessage() throws MessagingException, IOException {
        if (cryptoStatus.isEncryptSubject() && cryptoStatus.isEncryptionEnabled()) {
            moveSubjectIntoEncryptedPayload(); // Betreff in verschlüsselten Teil verschieben
        }

        if (cryptoStatus.isEncryptionEnabled()) {
            mimeBuildEncryptedMessage(messageContentBodyPart);
        } else if (cryptoStatus.isSigningEnabled()) {
            mimeBuildSignedMessage(messageContentBodyPart);
        } else {
            queueMessageBuildSuccess(currentProcessedMimeMessage);
        }
    }

    /**
     * Erstellt ein BodyPart-Objekt aus der zusammengesetzten Nachricht.
     */
    private MimeBodyPart createBodyPartFromMessageContent() throws MessagingException {
        MimeBodyPart bodyPart = currentProcessedMimeMessage.toBodyPart();
        String[] contentType = currentProcessedMimeMessage.getHeader(MimeHeader.HEADER_CONTENT_TYPE);
        if (contentType.length > 0) {
            bodyPart.setHeader(MimeHeader.HEADER_CONTENT_TYPE, contentType[0]);
        }
        return bodyPart;
    }

    /**
     * Wenn der Betreff verschlüsselt werden soll, wird er aus der Headerzeile entfernt und in den Body verschoben.
     */
    private void moveSubjectIntoEncryptedPayload() {
        String[] subjects = currentProcessedMimeMessage.getHeader(MimeHeader.SUBJECT);
        if (subjects.length > 0) {
            messageContentBodyPart.setHeader(MimeHeader.HEADER_CONTENT_TYPE,
                messageContentBodyPart.getContentType() + "; protected-headers=\"v1\"");
            messageContentBodyPart.setHeader(MimeHeader.SUBJECT, subjects[0]);
            currentProcessedMimeMessage.setSubject(REPLACEMENT_SUBJECT);
        }
    }

    /**
     * Baut eine multipart/signed MIME-Struktur mit PQC-Signatur und Public Key.
     */
    private void mimeBuildSignedMessage(@NonNull BodyPart signedBodyPart) throws MessagingException, IOException {
        MimeMultipart multipartSigned = createMimeMultipart();
        multipartSigned.setSubType("signed");
        multipartSigned.addBodyPart(signedBodyPart);

        multipartSigned.addBodyPart(
            MimeBodyPart.create(new BinaryMemoryBody(generateSignatureText(), "7bit"),
                "application/pqc-signature; name=\"signature.asc\""));

        multipartSigned.addBodyPart(
            MimeBodyPart.create(new BinaryMemoryBody(generatePublicKey(), "7bit"),
                "application/pqc-signature; name=\"public_key.asc\""));

        MimeMessageHelper.setBody(currentProcessedMimeMessage, multipartSigned);

        String contentType = String.format(
            "multipart/signed; boundary=\"%s\"; protocol=\"application/pqc-signature\"; micalg=\"%s\"",
            multipartSigned.getBoundary(),
            Objects.requireNonNull(account.getPqcSigningAlgorithm()));

        currentProcessedMimeMessage.setHeader(MimeHeader.HEADER_CONTENT_TYPE, contentType);

        queueMessageBuildSuccess(currentProcessedMimeMessage);
    }

    /**
     * Baut eine multipart/encrypted MIME-Struktur mit dem verschlüsselten Payload.
     */
    private void mimeBuildEncryptedMessage(@NonNull BodyPart encryptedBodyPart) throws MessagingException {
        MimeMultipart multipartEncrypted = createMimeMultipart();
        multipartEncrypted.setSubType("encrypted");

        multipartEncrypted.addBodyPart(
            MimeBodyPart.create(new BinaryMemoryBody("Version: 1".getBytes(), "7bit"),
                "application/pqc-encrypted"));

        multipartEncrypted.addBodyPart(
            MimeBodyPart.create(encryptedBodyPart.getBody(),
                "application/octet-stream; name=\"encrypted.asc\""));

        MimeMessageHelper.setBody(currentProcessedMimeMessage, multipartEncrypted);

        String contentType = String.format(
            "multipart/encrypted; boundary=\"%s\"; protocol=\"application/pqc-encrypted\"",
            multipartEncrypted.getBoundary());

        currentProcessedMimeMessage.setHeader(MimeHeader.HEADER_CONTENT_TYPE, contentType);

        queueMessageBuildSuccess(currentProcessedMimeMessage);
    }

    /**
     * Signiert den normalisierten Nachrichtentext mit dem PQC-Algorithmus.
     */
    private byte[] generateSignatureText() throws MessagingException, IOException {
        ensureAccountConfigured();

        byte[] secretKey = Base64.getMimeDecoder().decode(account.getPqcSecretSigningKey());
        Signature signature = new Signature(account.getPqcSigningAlgorithm(), secretKey);

        byte[] canonicalMessage = canonicalize(messageContentBodyPart);
        byte[] signatureArray = signature.sign(canonicalMessage);
        signature.dispose_sig();

        return buildAsciiArmored("POST QUANTUM SIGNATURE", signatureArray).getBytes();
    }

    /**
     * Bereitet den öffentlichen Schlüssel als ASCII-armored Text auf.
     */
    private byte[] generatePublicKey() throws MessagingException {
        ensureAccountConfigured();

        byte[] rawPublicKey = Base64.getMimeDecoder().decode(account.getPqcPublicSigngingKey());

        return buildAsciiArmored("POST QUANTUM PUBLIC KEY", rawPublicKey).getBytes();
    }

    /**
     * Normalisiert den MIME-Body zur Signaturbildung (Zeilenenden, Whitespace etc.).
     */
    private byte[] canonicalize(BodyPart part) throws IOException, MessagingException {
        Charset charset = getCharsetFromBodyPart(part);
        byte[] inputBytes = getBytes(part);
        String input = new String(inputBytes, charset);

        // Normalisiere Zeilenenden und entferne überflüssige Leerzeichen am Ende
        String normalized = input.replaceAll("(?<!\r)\n", "\r\n");
        String[] lines = normalized.split("\r\n");
        StringBuilder canonicalizedBuilder = new StringBuilder();
        for (String line : lines) {
            canonicalizedBuilder.append(line.stripTrailing()).append("\r\n");
        }

        return canonicalizedBuilder.toString().getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Extrahiert Charset aus dem Content-Type-Header.
     */
    private Charset getCharsetFromBodyPart(BodyPart part) {
        try {
            String contentType = part.getContentType();
            String charsetName = MimeUtility.getHeaderParameter(contentType, "charset");
            if (charsetName != null) {
                return Charset.forName(charsetName);
            }
        } catch (Exception e) {
            Timber.w(e, "Failed to get charset from body part, falling back to UTF-8");
        }
        return StandardCharsets.UTF_8;
    }

    /**
     * Wandelt Binärdaten in ASCII-armorierten PQC-Text.
     */
    private String buildAsciiArmored(String title, byte[] content) {
        return String.format("------ BEGIN %s USING %s ------\r\n%s\r\n------ END %s USING %s ------",
            title,
            account.getPqcSigningAlgorithm().toUpperCase(),
            Base64.getMimeEncoder().encodeToString(content),
            title,
            account.getPqcSigningAlgorithm().toUpperCase()
        );
    }

    /**
     * Liest die binären Daten aus einem MIME BodyPart.
     */
    private byte[] getBytes(BodyPart part) throws IOException, MessagingException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        part.getBody().writeTo(outputStream);
        return outputStream.toByteArray();
    }

    /**
     * Prüft, ob der Account korrekt für PQC konfiguriert ist.
     */
    private void ensureAccountConfigured() throws MessagingException {
        if (account == null || account.getPqcSigningAlgorithm() == null || account.getPqcSigningAlgorithm().equals("None")) {
            throw new MessagingException("PQC Account or algorithm not properly configured");
        }
        if (account.getPqcKeysetExists() == null || !account.getPqcKeysetExists()) {
            throw new MessagingException("No PQC Keyset exists, please generate or import in account settings");
        }
    }
}
