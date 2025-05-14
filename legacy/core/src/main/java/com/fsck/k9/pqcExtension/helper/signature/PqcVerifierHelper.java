package com.fsck.k9.pqcExtension.helper.signature;

import android.content.Context;
import android.os.Build.VERSION_CODES;

import androidx.annotation.Nullable;
import androidx.annotation.RequiresApi;

import com.fsck.k9.mail.BodyPart;
import com.fsck.k9.mail.MessagingException;
import com.fsck.k9.mail.Multipart;
import com.fsck.k9.mail.Part;
import com.fsck.k9.mail.internet.MimeBodyPart;
import com.fsck.k9.mail.internet.MimeUtility;
import com.fsck.k9.mailstore.CryptoResultAnnotation;
import com.fsck.k9.pqcExtension.helper.PqcMessageHelper;
import com.fsck.k9.pqcExtension.keyManagement.SimpleKeyStoreFactory;
import com.fsck.k9.pqcExtension.keyManagement.SimpleKeyStoreFactory.KeyType;
import com.fsck.k9.pqcExtension.keyManagement.manager.PgpSimpleKeyManager;
import com.fsck.k9.pqcExtension.message.results.PqcDecryptionResult;
import com.fsck.k9.pqcExtension.message.results.PqcError;
import com.fsck.k9.pqcExtension.message.results.PqcSignatureResult;
import com.fsck.k9.pqcExtension.message.results.PqcSignatureResult.SenderStatusResult;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.json.JSONObject;
import org.openquantumsafe.Signature;
import timber.log.Timber;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.ArrayList;
import java.util.Base64;

public class PqcVerifierHelper {

    /**
     * Verifies both PQC and PGP signatures of a multipart-signed MIME message.
     * Returns appropriate CryptoResultAnnotation depending on validity of signatures and decryption result.
     */
    @RequiresApi(api = VERSION_CODES.TIRAMISU)
    public static CryptoResultAnnotation verifyAll(Context context, Part part, String senderEmail, String accountId, @Nullable PqcDecryptionResult decryptionResult) {
        try {
            Multipart multipart = (Multipart) part.getBody();
            if (multipart.getCount() < 2) {
                throw new MessagingException("Expected at least 2 parts for signed PQC message");
            }

            // Extract the content and prepare it for signature verification
            BodyPart signedContentPart = multipart.getBodyPart(0);
            byte[] signedData = PqcMessageHelper.canonicalize(signedContentPart);


            // Load PQC public key and algorithm from remote key store
            JSONObject keyData = SimpleKeyStoreFactory.getKeyStore(KeyType.PQC_SIG).loadRemotePublicKey(context, senderEmail);
            String declaredSigAlgorithm = keyData.optString("algorithm", "DEFAULT_ALGO");
            String pqcSigPk = keyData.optString("publicKey", "");

            if (pqcSigPk.isEmpty()) {
                return CryptoResultAnnotation.createPqcSignatureErrorAnnotation(
                    new PqcError(PqcError.KEY_MISSING, "PQC public key is missing for sender " + senderEmail),
                    null
                );
            }

            byte[] pqcPubKey = Base64.getDecoder().decode(pqcSigPk);

            // Load PGP public key
            String pgpPublicKeyArmored = SimpleKeyStoreFactory.getKeyStore(KeyType.PGP)
                .loadRemotePublicKeyArmoredString(context, senderEmail);

            if (Security.getProvider("BC") == null) {
                Security.addProvider(new BouncyCastleProvider());
            }

            PGPPublicKeyRing pgpRing = PgpSimpleKeyManager.parsePublicKeyRing(pgpPublicKeyArmored);
            PGPPublicKey pgpPubKey = pgpRing.getPublicKey();

            if (pgpPubKey == null) {
                return CryptoResultAnnotation.createPqcSignatureErrorAnnotation(
                    new PqcError(PqcError.KEY_MISSING, "PGP public key is missing or invalid for sender " + senderEmail),
                    null
                );
            }

            boolean edValid = false;
            boolean pqcValid = false;


            // Loop through signature parts to verify each one
            for (int i = 1; i < multipart.getCount(); i++) {
                BodyPart signaturePart = multipart.getBodyPart(i);
                String asciiSig = new String(PqcMessageHelper.canonicalize(signaturePart), StandardCharsets.US_ASCII);
                String contentType = signaturePart.getContentType();
                String filename = MimeUtility.getHeaderParameter(contentType, "name");

                if (filename == null) {
                    Timber.w("No filename in Content-Type of signature part");
                    continue;
                }

                boolean isPgp = filename.toLowerCase().contains("pgp");

                if (isPgp) {
                    byte[] sigBytes = asciiSig.getBytes(StandardCharsets.US_ASCII);
                    edValid = verifyPgpSignature(signedData, sigBytes, pgpPubKey);
                } else if (filename.toLowerCase().contains("pqc")) {
                    String sigContent = PqcMessageHelper.extractContent(asciiSig, "PQC SIGNATURE");
                    byte[] sigBytes = PqcMessageHelper.decodeCleanBase64(sigContent);
                    pqcValid = verifyPqcSignature(signedData, sigBytes, pqcPubKey, declaredSigAlgorithm);
                }
            }

            MimeBodyPart replacementData = (MimeBodyPart) signedContentPart;


            // If both signatures are valid, return success result
            if (edValid && pqcValid) {
                PqcSignatureResult signatureResult = PqcSignatureResult.createWithValidSignature(
                    PqcSignatureResult.RESULT_VALID_KEY_CONFIRMED,
                    senderEmail, 0L, new ArrayList<>(), new ArrayList<>(),
                    SenderStatusResult.USER_ID_CONFIRMED
                );

                if (decryptionResult != null && decryptionResult.getResult() == PqcDecryptionResult.RESULT_DECRYPTED) {
                    return CryptoResultAnnotation.createPqcEncryptionSignatureSuccessAnnotation(
                        decryptionResult,
                        signatureResult,
                        replacementData
                    );
                }

                return CryptoResultAnnotation.createPqcSignatureSuccessAnnotation(
                    null,
                    signatureResult,
                    replacementData
                );
            }


            // If signature verification failed
            return CryptoResultAnnotation.createPqcEncryptionErrorAnnotation(
                decryptionResult != null ? decryptionResult : new PqcDecryptionResult(PqcDecryptionResult.RESULT_DECRYPTED),
                (MimeBodyPart) signedContentPart,
                new PqcError(PqcError.INVALID_SIGNATURE, "Invalid signature(s) in PQC or PGP")
            );

        } catch (Exception e) {
            return CryptoResultAnnotation.createPqcSignatureErrorAnnotation(
                new PqcError(PqcError.CLIENT_SIDE_ERROR, e.getMessage()),
                null
            );
        }
    }

    /**
     * Verifies a classic PGP signature using the given public key.
     */
    private static boolean verifyPgpSignature(byte[] data, byte[] sigBytes, PGPPublicKey pubKey) {
        try {
            InputStream sigIn = PGPUtil.getDecoderStream(new ByteArrayInputStream(sigBytes));
            PGPObjectFactory pgpFactory = new PGPObjectFactory(sigIn, new JcaKeyFingerprintCalculator());
            Object obj = pgpFactory.nextObject();

            PGPSignature sig;

            if (obj instanceof PGPSignatureList) {
                sig = ((PGPSignatureList) obj).get(0);
            } else if (obj instanceof PGPSignature) {
                sig = (PGPSignature) obj;
            } else {
                return false;
            }

            sig.init(new JcaPGPContentVerifierBuilderProvider().setProvider(new BouncyCastleProvider()), pubKey);
            sig.update(data);
            return sig.verify();
        } catch (Exception e) {
            return false;
        }
    }


    /**
     * Verifies a post-quantum signature using OpenQuantumSafe API.
     */
    private static boolean verifyPqcSignature(byte[] data, byte[] signature, byte[] pubKeyBytes, String algorithm) {
        try {
            Signature pqcVerifier = new Signature(algorithm);
            boolean valid = pqcVerifier.verify(data, signature, pubKeyBytes);
            pqcVerifier.dispose_sig();
            return valid;
        } catch (Exception e) {
            return false;
        }
    }
}
