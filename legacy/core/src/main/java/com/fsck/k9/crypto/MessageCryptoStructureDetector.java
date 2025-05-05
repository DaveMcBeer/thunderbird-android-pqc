package com.fsck.k9.crypto;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Stack;

import androidx.annotation.Nullable;
import androidx.annotation.VisibleForTesting;

import com.fsck.k9.helper.StringHelper;
import com.fsck.k9.mail.Body;
import com.fsck.k9.mail.BodyPart;
import com.fsck.k9.mail.MessagingException;
import com.fsck.k9.mail.Multipart;
import com.fsck.k9.mail.Part;
import com.fsck.k9.mail.internet.MessageExtractor;
import com.fsck.k9.mail.internet.MimeBodyPart;
import com.fsck.k9.mail.internet.MimeMultipart;
import com.fsck.k9.mail.internet.MimeUtility;
import com.fsck.k9.mailstore.CryptoResultAnnotation;
import com.fsck.k9.mailstore.MessageCryptoAnnotations;

import static com.fsck.k9.mail.internet.MimeUtility.isSameMimeType;

public class MessageCryptoStructureDetector {

    private static final String MULTIPART_ENCRYPTED = "multipart/encrypted";
    private static final String MULTIPART_SIGNED = "multipart/signed";
    private static final String PROTOCOL_PARAMETER = "protocol";
    private static final String APPLICATION_PGP_ENCRYPTED = "application/pgp-encrypted";
    private static final String APPLICATION_PGP_SIGNATURE = "application/pgp-signature";
    private static final String APPLICATION_PQC_ENCRYPTED = "application/pqc-encrypted";
    private static final String TEXT_PLAIN = "text/plain";
    private static final String APPLICATION_PGP = "application/pgp";
    private static final String PGP_INLINE_START_MARKER = "-----BEGIN PGP MESSAGE-----";
    private static final String PGP_INLINE_SIGNED_START_MARKER = "-----BEGIN PGP SIGNED MESSAGE-----";
    private static final int TEXT_LENGTH_FOR_INLINE_CHECK = 36;

    public static Part findPrimaryEncryptedOrSignedPart(Part part, List<Part> outputExtraParts) {
        if (isPartEncryptedOrSigned(part)) {
            return part;
        }

        Part foundPart = findPrimaryPartInAlternative(part);
        if (foundPart != null) {
            return foundPart;
        }

        foundPart = findPrimaryPartInMixed(part, outputExtraParts);
        return foundPart;
    }

    @Nullable
    private static Part findPrimaryPartInMixed(Part part, List<Part> outputExtraParts) {
        Body body = part.getBody();

        if (!part.isMimeType("multipart/mixed") || !(body instanceof Multipart)) {
            return null;
        }

        Multipart multipart = (Multipart) body;
        if (multipart.getCount() == 0) {
            return null;
        }

        BodyPart firstBodyPart = multipart.getBodyPart(0);
        Part foundPart = isPartEncryptedOrSigned(firstBodyPart) ? firstBodyPart : findPrimaryPartInAlternative(firstBodyPart);

        if (foundPart != null && outputExtraParts != null) {
            for (int i = 1; i < multipart.getCount(); i++) {
                outputExtraParts.add(multipart.getBodyPart(i));
            }
        }

        return foundPart;
    }

    private static Part findPrimaryPartInAlternative(Part part) {
        Body body = part.getBody();
        if (part.isMimeType("multipart/alternative") && body instanceof Multipart) {
            Multipart multipart = (Multipart) body;
            if (multipart.getCount() == 0) {
                return null;
            }

            BodyPart firstBodyPart = multipart.getBodyPart(0);
            if (isPartPgpInlineEncryptedOrSigned(firstBodyPart)) {
                return firstBodyPart;
            }
        }
        return null;
    }

    public static List<Part> findMultipartEncryptedParts(Part startPart) {
        List<Part> encryptedParts = new ArrayList<>();
        Stack<Part> partsToCheck = new Stack<>();
        partsToCheck.push(startPart);

        while (!partsToCheck.isEmpty()) {
            Part part = partsToCheck.pop();
            Body body = part.getBody();

            if (isPartMultipartEncrypted(part) || isPartMultipartPqcEncrypted(part)) {
                encryptedParts.add(part);
                continue;
            }

            if (body instanceof Multipart) {
                Multipart multipart = (Multipart) body;
                for (int i = multipart.getCount() - 1; i >= 0; i--) {
                    partsToCheck.push(multipart.getBodyPart(i));
                }
            }
        }

        return encryptedParts;
    }

    public static List<Part> findMultipartSignedParts(Part startPart, MessageCryptoAnnotations messageCryptoAnnotations) {
        List<Part> signedParts = new ArrayList<>();
        Stack<Part> partsToCheck = new Stack<>();
        partsToCheck.push(startPart);

        while (!partsToCheck.isEmpty()) {
            Part part = partsToCheck.pop();

            if (messageCryptoAnnotations.has(part)) {
                CryptoResultAnnotation resultAnnotation = messageCryptoAnnotations.get(part);
                MimeBodyPart replacementData = resultAnnotation.getReplacementData();
                if (replacementData != null) {
                    part = replacementData;
                }
            }

            Body body = part.getBody();

            if (isMultipartSignedWithMultipleSignatures(part) || isPartMultipartSigned(part)) {
                signedParts.add(part);
                continue;
            }

            if (body instanceof Multipart) {
                Multipart multipart = (Multipart) body;
                for (int i = multipart.getCount() - 1; i >= 0; i--) {
                    partsToCheck.push(multipart.getBodyPart(i));
                }
            }
        }

        return signedParts;
    }

    public static List<Part> findPgpInlineParts(Part startPart) {
        List<Part> inlineParts = new ArrayList<>();
        Stack<Part> partsToCheck = new Stack<>();
        partsToCheck.push(startPart);

        while (!partsToCheck.isEmpty()) {
            Part part = partsToCheck.pop();
            Body body = part.getBody();

            if (isPartPgpInlineEncryptedOrSigned(part)) {
                inlineParts.add(part);
                continue;
            }

            if (body instanceof Multipart) {
                Multipart multipart = (Multipart) body;
                for (int i = multipart.getCount() - 1; i >= 0; i--) {
                    partsToCheck.push(multipart.getBodyPart(i));
                }
            }
        }

        return inlineParts;
    }

    public static byte[] getSignatureData(Part part) throws IOException, MessagingException {
        // Direkter multipart/signed Fall
        if (isSameMimeType(part.getMimeType(), "multipart/signed") && part.getBody() instanceof MimeMultipart) {
            MimeMultipart signedMultipart = (MimeMultipart) part.getBody();
            if (signedMultipart.getCount() > 1) {
                BodyPart signatureBody = signedMultipart.getBodyPart(1);
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                signatureBody.getBody().writeTo(bos);
                return bos.toByteArray();
            }
        }

        // Eingebetteter multipart/signed in multipart/mixed
        if (isSameMimeType(part.getMimeType(), "multipart/mixed") && part.getBody() instanceof MimeMultipart) {
            MimeMultipart mixedMultipart = (MimeMultipart) part.getBody();
            for (int i = 0; i < mixedMultipart.getCount(); i++) {
                BodyPart innerPart = mixedMultipart.getBodyPart(i);
                if (isSameMimeType(innerPart.getMimeType(), "multipart/signed") &&
                    innerPart.getBody() instanceof MimeMultipart) {

                    MimeMultipart signedMultipart = (MimeMultipart) innerPart.getBody();
                    if (signedMultipart.getCount() > 1) {
                        BodyPart signatureBody = signedMultipart.getBodyPart(1);
                        ByteArrayOutputStream bos = new ByteArrayOutputStream();
                        signatureBody.getBody().writeTo(bos);
                        return bos.toByteArray();
                    }
                }
            }
        }

        return null;

    }

    private static boolean isPartEncryptedOrSigned(Part part) {
        return isMultipartSignedWithMultipleSignatures(part) || isPartMultipartPqcEncrypted(part)
            || isPartMultipartEncrypted(part) || isPartMultipartSigned(part)
            || isPartPgpInlineEncryptedOrSigned(part);
    }

    private static boolean isPartMultipartSigned(Part part) {
        if (!isSameMimeType(part.getMimeType(), MULTIPART_SIGNED)) {
            return false;
        }

        if (!(part.getBody() instanceof MimeMultipart)) {
            return false;
        }

        MimeMultipart mimeMultipart = (MimeMultipart) part.getBody();
        if (mimeMultipart.getCount() != 2) {
            return false;
        }

        String protocolParameter = MimeUtility.getHeaderParameter(part.getContentType(), PROTOCOL_PARAMETER);

        boolean dataUnavailable = protocolParameter == null && mimeMultipart.getBodyPart(0).getBody() == null;
        boolean protocolMatches = isSameMimeType(protocolParameter, mimeMultipart.getBodyPart(1).getMimeType());



        int pgpSigCount = 0;
        int compositeCount = 0;

        for (int i = 1; i < mimeMultipart.getCount(); i++) {
            BodyPart bp;
            bp = mimeMultipart.getBodyPart(i);

            if (bp.isMimeType("application/pgp-signature")) {
                pgpSigCount++;
                String filename = MimeUtility.getHeaderParameter(bp.getContentType(), "name");
                if (filename != null && filename.toLowerCase().startsWith("signature-")) {
                    compositeCount++;
                }
            }
        }

        boolean pqcPgpCombination =
            "application/pgp-signature".equalsIgnoreCase(protocolParameter) &&
                pgpSigCount >= 2 && compositeCount > 0;

        return dataUnavailable || protocolMatches||pqcPgpCombination;
    }

    public static boolean isPartMultipartEncrypted(Part part) {
        if (!isSameMimeType(part.getMimeType(), MULTIPART_ENCRYPTED)) {
            return false;
        }

        if (!(part.getBody() instanceof MimeMultipart)) {
            return false;
        }

        MimeMultipart mimeMultipart = (MimeMultipart) part.getBody();
        if (mimeMultipart.getCount() != 2) {
            return false;
        }

        String protocolParameter = MimeUtility.getHeaderParameter(part.getContentType(), PROTOCOL_PARAMETER);
        boolean dataUnavailable = protocolParameter == null && mimeMultipart.getBodyPart(1).getBody() == null;
        boolean protocolMatches = isSameMimeType(protocolParameter, mimeMultipart.getBodyPart(0).getMimeType());

        return dataUnavailable || protocolMatches;
    }

    public static boolean isMultipartEncryptedOpenPgpProtocol(Part part) {
        String protocolParameter = MimeUtility.getHeaderParameter(part.getContentType(), PROTOCOL_PARAMETER);
        return APPLICATION_PGP_ENCRYPTED.equalsIgnoreCase(protocolParameter);
    }

    public static boolean isMultipartSignedOpenPgpProtocol(Part part) {
        String protocolParameter = MimeUtility.getHeaderParameter(part.getContentType(), PROTOCOL_PARAMETER);
        return APPLICATION_PGP_SIGNATURE.equalsIgnoreCase(protocolParameter);
    }

    @VisibleForTesting
    static boolean isPartPgpInlineEncryptedOrSigned(Part part) {
        if (!part.isMimeType(TEXT_PLAIN) && !part.isMimeType(APPLICATION_PGP)) {
            return false;
        }
        String text = MessageExtractor.getTextFromPart(part, TEXT_LENGTH_FOR_INLINE_CHECK);
        if (StringHelper.isNullOrEmpty(text)) {
            return false;
        }
        text = text.trim();
        return text.startsWith(PGP_INLINE_START_MARKER) || text.startsWith(PGP_INLINE_SIGNED_START_MARKER);
    }

    public static boolean isPartPgpInlineEncrypted(@Nullable Part part) {
        if (part == null) {
            return false;
        }

        if (!part.isMimeType(TEXT_PLAIN) && !part.isMimeType(APPLICATION_PGP)) {
            return false;
        }

        String text = MessageExtractor.getTextFromPart(part, TEXT_LENGTH_FOR_INLINE_CHECK);
        if (StringHelper.isNullOrEmpty(text)) {
            return false;
        }

        return text.trim().startsWith(PGP_INLINE_START_MARKER);
    }

    public static boolean isMultipartSignedWithMultipleSignatures(Part part) {
        if (!isSameMimeType(part.getMimeType(), "multipart/signed")) {
            return false;
        }

        if (!(part.getBody() instanceof MimeMultipart)) {
            return false;
        }

        MimeMultipart multipart = (MimeMultipart) part.getBody();

        // multipart/signed benötigt mindestens 3 Teile:
        if (multipart.getCount() < 3) {
            return false;
        }

        int signatureCount = 0;

        for (int i = 1; i < multipart.getCount(); i++) {
            BodyPart bodyPart = multipart.getBodyPart(i);

            if (bodyPart.isMimeType("application/pgp-signature")) {
                String filename = MimeUtility.getHeaderParameter(bodyPart.getContentType(), "name");
                if (filename != null && filename.toLowerCase().startsWith("signature-") && filename.endsWith(".asc")) {
                    signatureCount++;
                }
            }
        }

        return signatureCount >= 2;
    }

    public static boolean isPartMultipartPqcEncrypted(Part part) {
        if (!isSameMimeType(part.getMimeType(), MULTIPART_ENCRYPTED)) {
            return false;
        }

        if (!(part.getBody() instanceof MimeMultipart)) {
            return false;
        }

        MimeMultipart mimeMultipart = (MimeMultipart) part.getBody();
        if (mimeMultipart.getCount() < 2) {
            return false;
        }

        String protocolParameter = MimeUtility.getHeaderParameter(part.getContentType(), PROTOCOL_PARAMETER);
        return APPLICATION_PQC_ENCRYPTED.equalsIgnoreCase(protocolParameter);
    }
    //--- ENDE ---
}
