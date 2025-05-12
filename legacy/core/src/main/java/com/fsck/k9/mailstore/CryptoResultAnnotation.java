package com.fsck.k9.mailstore;

import android.app.PendingIntent;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.fsck.k9.mail.internet.MimeBodyPart;
import com.fsck.k9.pqcExtension.message.results.PqcDecryptionResult;
import com.fsck.k9.pqcExtension.message.results.PqcError;
import com.fsck.k9.pqcExtension.message.results.PqcSignatureResult;
import org.openintents.openpgp.OpenPgpDecryptionResult;
import org.openintents.openpgp.OpenPgpError;
import org.openintents.openpgp.OpenPgpSignatureResult;

public final class CryptoResultAnnotation {
    @NonNull private final CryptoError errorType;
    private final MimeBodyPart replacementData;

    private final OpenPgpDecryptionResult openPgpDecryptionResult;
    private final OpenPgpSignatureResult openPgpSignatureResult;
    private final OpenPgpError openPgpError;
    private final PendingIntent openPgpPendingIntent;
    private final PendingIntent openPgpInsecureWarningPendingIntent;
    private final boolean overrideCryptoWarning;

    private final CryptoResultAnnotation encapsulatedResult;
//--- PQC Erweiterung ---
    private final PqcDecryptionResult pqcDecryptionResult;
    private final PqcSignatureResult pqcSignatureResult;
    private  final PqcError pqcError;
//--- ENDE ---

    private CryptoResultAnnotation(
        @NonNull CryptoError errorType,
        MimeBodyPart replacementData,
        OpenPgpDecryptionResult openPgpDecryptionResult,
        OpenPgpSignatureResult openPgpSignatureResult,
        PendingIntent openPgpPendingIntent,
        PendingIntent openPgpInsecureWarningPendingIntent,
        OpenPgpError openPgpError,
        boolean overrideCryptoWarning,
        PqcDecryptionResult pqcDecryptionResult,    //--- PQC Erweiterung ---
        PqcSignatureResult pqcSignatureResult,
        PqcError pqcError//--- PQC Erweiterung ---
    ) {
        this.errorType = errorType;
        this.replacementData = replacementData;

        this.openPgpDecryptionResult = openPgpDecryptionResult;
        this.openPgpSignatureResult = openPgpSignatureResult;
        this.openPgpPendingIntent = openPgpPendingIntent;
        this.openPgpError = openPgpError;
        this.openPgpInsecureWarningPendingIntent = openPgpInsecureWarningPendingIntent;
        this.overrideCryptoWarning = overrideCryptoWarning;

        this.encapsulatedResult = null;

        //--- PQC Erweiterung ---
        this.pqcDecryptionResult = pqcDecryptionResult;
        this.pqcSignatureResult = pqcSignatureResult;
        this.pqcError = pqcError;
        //--- ENDE ---
    }

    private CryptoResultAnnotation(CryptoResultAnnotation annotation, CryptoResultAnnotation encapsulatedResult) {
        if (annotation.encapsulatedResult != null) {
            throw new AssertionError("cannot replace an encapsulated result, this is a bug!");
        }

        this.errorType = annotation.errorType;
        this.replacementData = annotation.replacementData;

        this.openPgpDecryptionResult = annotation.openPgpDecryptionResult;
        this.openPgpSignatureResult = annotation.openPgpSignatureResult;
        this.openPgpPendingIntent = annotation.openPgpPendingIntent;
        this.openPgpInsecureWarningPendingIntent = annotation.openPgpInsecureWarningPendingIntent;
        this.openPgpError = annotation.openPgpError;
        this.overrideCryptoWarning = annotation.overrideCryptoWarning;

        this.encapsulatedResult = encapsulatedResult;

        //--- PQC Erweiterung ---
        this.pqcDecryptionResult = annotation.pqcDecryptionResult;
        this.pqcSignatureResult = annotation.pqcSignatureResult;
        this.pqcError = annotation.pqcError;
        //--- ENDE ---
    }

    // OpenPGP Factories
    public static CryptoResultAnnotation createOpenPgpResultAnnotation(OpenPgpDecryptionResult decryptionResult,
            OpenPgpSignatureResult signatureResult, PendingIntent pendingIntent,
            PendingIntent insecureWarningPendingIntent, MimeBodyPart replacementPart,
            boolean overrideCryptoWarning) {
        return new CryptoResultAnnotation(CryptoError.OPENPGP_OK, replacementPart,
                decryptionResult, signatureResult, pendingIntent, insecureWarningPendingIntent, null,
                overrideCryptoWarning, null, null,null);  //--- PQC Erweiterung: null,null zusätzlich ---
    }

    public static CryptoResultAnnotation createErrorAnnotation(CryptoError error, MimeBodyPart replacementData) {
        if (error == CryptoError.OPENPGP_OK || error == CryptoError.PQC_ENCRYPTED_OK || error == CryptoError.PQC_SIGNED_OK) { //--- PQC Erweiterung ---
            throw new AssertionError("CryptoError must be an actual error state!");
        }
        return new CryptoResultAnnotation(error, replacementData, null, null, null, null, null, false, null, null,null);
    }

    public static CryptoResultAnnotation createOpenPgpCanceledAnnotation() {
        return new CryptoResultAnnotation(CryptoError.OPENPGP_UI_CANCELED, null, null, null, null, null, null, false, null, null,null);  //--- PQC Erweiterung: null,null zusätzlich ---
    }

    public static CryptoResultAnnotation createOpenPgpSignatureErrorAnnotation(
            OpenPgpError error, MimeBodyPart replacementData) {
        return new CryptoResultAnnotation(
                CryptoError.OPENPGP_SIGNED_API_ERROR, replacementData, null, null, null, null, error, false, null, null,null);    //--- PQC Erweiterung: null,null zusätzlich ---
    }

    public static CryptoResultAnnotation createOpenPgpEncryptionErrorAnnotation(OpenPgpError error) {
        return new CryptoResultAnnotation(
                CryptoError.OPENPGP_ENCRYPTED_API_ERROR, null, null, null, null, null, error, false, null, null,null);   //--- PQC Erweiterung: null,null zusätzlich ---
    }

    public boolean isOpenPgpResult() {
        return openPgpDecryptionResult != null && openPgpSignatureResult != null;
    }

    public boolean hasSignatureResult() {
        return openPgpSignatureResult != null &&
                openPgpSignatureResult.getResult() != OpenPgpSignatureResult.RESULT_NO_SIGNATURE || pqcSignatureResult != null && pqcSignatureResult.getResult() != PqcSignatureResult.RESULT_NO_SIGNATURE;
    }

    @Nullable
    public OpenPgpDecryptionResult getOpenPgpDecryptionResult() {
        return openPgpDecryptionResult;
    }

    public boolean isEncrypted() {
        return openPgpDecryptionResult != null && openPgpDecryptionResult.result == OpenPgpDecryptionResult.RESULT_ENCRYPTED;
    }

    @Nullable
    public OpenPgpSignatureResult getOpenPgpSignatureResult() {
        return openPgpSignatureResult;
    }

    @Nullable
    public PendingIntent getOpenPgpSigningKeyIntentIfAny() {
        if (hasSignatureResult()) {
            return getOpenPgpPendingIntent();
        }
        if (encapsulatedResult != null && encapsulatedResult.hasSignatureResult()) {
            return encapsulatedResult.getOpenPgpPendingIntent();
        }
        return null;
    }

    @Nullable
    public PendingIntent getOpenPgpPendingIntent() {
        return openPgpPendingIntent;
    }

    public boolean hasOpenPgpInsecureWarningPendingIntent() {
        return openPgpInsecureWarningPendingIntent != null;
    }

    @Nullable
    public PendingIntent getOpenPgpInsecureWarningPendingIntent() {
        return openPgpInsecureWarningPendingIntent;
    }

    @Nullable
    public OpenPgpError getOpenPgpError() {
        return openPgpError;
    }

    @NonNull
    public CryptoError getErrorType() {
        return errorType;
    }

    public boolean hasReplacementData() {
        return replacementData != null;
    }

    @Nullable
    public MimeBodyPart getReplacementData() {
        return replacementData;
    }

    public boolean isOverrideSecurityWarning() {
        return overrideCryptoWarning;
    }

    @NonNull
    public CryptoResultAnnotation withEncapsulatedResult(CryptoResultAnnotation resultAnnotation) {
        return new CryptoResultAnnotation(this, resultAnnotation);
    }

    public boolean hasEncapsulatedResult() {
        return encapsulatedResult != null;
    }

    public CryptoResultAnnotation getEncapsulatedResult() {
        return encapsulatedResult;
    }

    //--- PQC Erweiterung ---
    public boolean isPqcResult() {
        return pqcDecryptionResult != null || pqcSignatureResult != null;
    }

    @Nullable
    public PqcDecryptionResult getPqcDecryptionResult() {
        return pqcDecryptionResult;
    }

    @Nullable
    public PqcError getPqcError() {
        return pqcError;
    }
    @Nullable
    public PqcSignatureResult getPqcSignatureResult() {
        return pqcSignatureResult;
    }

    public boolean isPqcEncrypted() {
        return pqcDecryptionResult != null && pqcDecryptionResult.result == PqcDecryptionResult.RESULT_ENCRYPTED; //--- PQC Erweiterung ---
    }

    public static CryptoResultAnnotation createPqcSignatureSuccessAnnotation(
        @Nullable PqcDecryptionResult decryptionResult,
        @NonNull PqcSignatureResult signatureResult,
        @Nullable MimeBodyPart replacementData
    ) {
        return new CryptoResultAnnotation(
            CryptoError.PQC_SIGNED_OK,
            replacementData,
            null, // OpenPGP Decryption
            null, // OpenPGP Signature
            null,
            null,
            null,
            false,
            decryptionResult,
            signatureResult,
            null
        );
    }
    public static CryptoResultAnnotation createPqcSignatureErrorAnnotation(
        @Nullable PqcError error,
        @Nullable MimeBodyPart replacementData
    ) {
        return new CryptoResultAnnotation(
            CryptoError.PQC_SIGNATURE_ERROR,
            replacementData,
            null,
            null,
            null,
            null,
            null,
            false,
            null,
            null,
            error
        );
    }
    public static CryptoResultAnnotation createPqcEncryptionSuccessAnnotation(
        @NonNull PqcDecryptionResult decryptionResult,
        @Nullable MimeBodyPart replacementData
    ) {
        return new CryptoResultAnnotation(
            CryptoError.PQC_ENCRYPTED_OK,
            replacementData,
            null,
            null,
            null,
            null,
            null,
            false,
            decryptionResult,
            null,
            null
        );
    }

    public static CryptoResultAnnotation createPqcEncryptionSignatureSuccessAnnotation(
        @NonNull PqcDecryptionResult decryptionResult,
        @NonNull PqcSignatureResult signatureResult,
        @Nullable MimeBodyPart replacementData
    ) {
        return new CryptoResultAnnotation(
            CryptoError.PQC_SIGNED_AND_ENCRYPT_OK,
            replacementData,
            null,
            null,
            null,
            null,
            null,
            false,
            decryptionResult,
            signatureResult,
            null
        );
    }
    public static CryptoResultAnnotation createPqcEncryptionErrorAnnotation(
        @NonNull PqcDecryptionResult decryptionResult,
        @Nullable MimeBodyPart replacementData,
        @Nullable PqcError pqcError
    ) {
        return new CryptoResultAnnotation(
            CryptoError.PQC_ENCRYPTED_ERROR,
            replacementData,
            null,       // OpenPGP Decryption
            null,       // OpenPGP Signature
            null,
            null,
            null,
            false,
            decryptionResult,
            null,
            pqcError
        );
    }


    //--- ENDE ---

    public enum CryptoError {
        OPENPGP_OK,
        OPENPGP_UI_CANCELED,
        OPENPGP_SIGNED_API_ERROR,
        OPENPGP_ENCRYPTED_API_ERROR,
        OPENPGP_SIGNED_BUT_INCOMPLETE,
        OPENPGP_ENCRYPTED_BUT_INCOMPLETE,
        SIGNED_BUT_UNSUPPORTED,
        ENCRYPTED_BUT_UNSUPPORTED,
        OPENPGP_ENCRYPTED_NO_PROVIDER,

        //--- PQC Erweiterung ---
        PQC_SIGNED_OK,
        PQC_SIGNATURE_ERROR,
        PQC_ENCRYPTED_OK,
        PQC_ENCRYPTED_ERROR,
        PQC_SIGNED_AND_ENCRYPT_OK,

        //--- ENDE ---
    }
}
