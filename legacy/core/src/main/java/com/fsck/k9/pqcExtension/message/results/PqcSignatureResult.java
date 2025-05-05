package com.fsck.k9.pqcExtension.message.results;

import android.os.Parcel;
import android.os.Parcelable;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Repräsentiert das Ergebnis einer PQC-Signaturprüfung.
 *
 * Diese Klasse enthält:
 * - Signaturstatus (gültig, ungültig, Schlüssel fehlt etc.)
 * - Informationen über verwendete Schlüssel (Key-ID, User IDs)
 * - Status des Absenders (bestätigt, unbestätigt)
 *
 * Unterstützt das Parcelable-Interface für IPC oder Speicherung.
 */

@SuppressWarnings("unused")
public class PqcSignatureResult implements Parcelable {

    private static final int PARCELABLE_VERSION = 1;

    // Mögliche Ergebnis-Codes für Signaturprüfung
    public static final int RESULT_NO_SIGNATURE = -1;
    public static final int RESULT_INVALID_SIGNATURE = 0;
    public static final int RESULT_VALID_KEY_CONFIRMED = 1;
    public static final int RESULT_KEY_MISSING = 2;
    public static final int RESULT_VALID_KEY_UNCONFIRMED = 3;
    public static final int RESULT_INVALID_KEY_REVOKED = 4;
    public static final int RESULT_INVALID_KEY_EXPIRED = 5;
    public static final int RESULT_INVALID_KEY_INSECURE = 6;

    // Felder des Ergebnisses
    private final int result;
    private final long keyId;
    private final String primaryUserId;
    private final ArrayList<String> userIds;
    private final ArrayList<String> confirmedUserIds;
    private final SenderStatusResult senderStatusResult;

    /**
     * Konstruktor für ein vollständiges Ergebnisobjekt.
     */
    public PqcSignatureResult(int result, String primaryUserId, long keyId,
        ArrayList<String> userIds, ArrayList<String> confirmedUserIds,
        SenderStatusResult senderStatusResult) {
        this.result = result;
        this.primaryUserId = primaryUserId;
        this.keyId = keyId;
        this.userIds = userIds != null ? userIds : new ArrayList<>();
        this.confirmedUserIds = confirmedUserIds != null ? confirmedUserIds : new ArrayList<>();
        this.senderStatusResult = senderStatusResult != null ? senderStatusResult : SenderStatusResult.UNKNOWN;
    }

    /**
     * Konstruktor für Deserialisierung aus einem Parcel.
     */
    private PqcSignatureResult(Parcel source, int version) {
        this.result = source.readInt();
        this.primaryUserId = source.readString();
        this.keyId = source.readLong();
        this.userIds = source.createStringArrayList();
        this.senderStatusResult = readEnumWithNullAndFallback(source, SenderStatusResult.values(), SenderStatusResult.UNKNOWN);
        this.confirmedUserIds = source.createStringArrayList();
    }

    // Getter
    public int getResult() {
        return result;
    }

    public SenderStatusResult getSenderStatusResult() {
        return senderStatusResult;
    }

    public String getPrimaryUserId() {
        return primaryUserId;
    }

    public List<String> getUserIds() {
        return Collections.unmodifiableList(userIds);
    }

    public List<String> getConfirmedUserIds() {
        return Collections.unmodifiableList(confirmedUserIds);
    }

    public long getKeyId() {
        return keyId;
    }

    @Override
    public int describeContents() {
        return 0;
    }

    /**
     * Serialisiert dieses Objekt in ein Parcel.
     */
    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeInt(PARCELABLE_VERSION);
        int sizePosition = dest.dataPosition();
        dest.writeInt(0); // Placeholder für Größe
        int startPosition = dest.dataPosition();

        dest.writeInt(result);
        dest.writeString(primaryUserId);
        dest.writeLong(keyId);
        dest.writeStringList(userIds);
        writeEnumWithNull(dest, senderStatusResult);
        dest.writeStringList(confirmedUserIds);

        int parcelableSize = dest.dataPosition() - startPosition;
        dest.setDataPosition(sizePosition);
        dest.writeInt(parcelableSize);
        dest.setDataPosition(startPosition + parcelableSize);
    }

    /**
     * Parcelable-Creator zur Erstellung von Instanzen aus einem Parcel.
     */
    public static final Creator<PqcSignatureResult> CREATOR = new Creator<PqcSignatureResult>() {
        public PqcSignatureResult createFromParcel(final Parcel source) {
            int version = source.readInt();
            int parcelableSize = source.readInt();
            int startPosition = source.dataPosition();

            PqcSignatureResult result = new PqcSignatureResult(source, version);

            source.setDataPosition(startPosition + parcelableSize);
            return result;
        }

        public PqcSignatureResult[] newArray(final int size) {
            return new PqcSignatureResult[size];
        }
    };

    @Override
    public String toString() {
        return "\nresult: " + result +
            "\nprimaryUserId: " + primaryUserId +
            "\nuserIds: " + userIds +
            "\nkeyId: " + keyId;
    }

    /**
     * Fabrikmethode für gültige Signaturen mit vollständigen Daten.
     */
    public static PqcSignatureResult createWithValidSignature(int signatureStatus, String primaryUserId,
        long keyId, ArrayList<String> userIds,
        ArrayList<String> confirmedUserIds,
        SenderStatusResult senderStatusResult) {
        if (signatureStatus == RESULT_NO_SIGNATURE || signatureStatus == RESULT_KEY_MISSING ||
            signatureStatus == RESULT_INVALID_SIGNATURE) {
            throw new IllegalArgumentException("Can only use this method for valid signature statuses");
        }
        return new PqcSignatureResult(signatureStatus, primaryUserId, keyId, userIds, confirmedUserIds, senderStatusResult);
    }

    /**
     * Fabrikmethode für "keine Signatur vorhanden".
     */
    public static PqcSignatureResult createWithNoSignature() {
        return new PqcSignatureResult(RESULT_NO_SIGNATURE, null, 0L, null, null, null);
    }

    /**
     * Fabrikmethode für "Schlüssel fehlt".
     */
    public static PqcSignatureResult createWithKeyMissing(long keyId) {
        return new PqcSignatureResult(RESULT_KEY_MISSING, null, keyId, null, null, null);
    }

    /**
     * Fabrikmethode für "ungültige Signatur".
     */
    public static PqcSignatureResult createWithInvalidSignature() {
        return new PqcSignatureResult(RESULT_INVALID_SIGNATURE, null, 0L, null, null, null);
    }

    /**
     * Hilfsmethode zur sicheren Enum-Deserialisierung.
     */
    private static <T extends Enum<T>> T readEnumWithNullAndFallback(Parcel source, T[] enumValues, T fallback) {
        int valueOrdinal = source.readInt();
        if (valueOrdinal == -1) {
            return null;
        }
        if (valueOrdinal >= enumValues.length) {
            return fallback;
        }
        return enumValues[valueOrdinal];
    }

    /**
     * Hilfsmethode zur Enum-Serialisierung.
     */
    private static void writeEnumWithNull(Parcel dest, Enum<?> enumValue) {
        if (enumValue == null) {
            dest.writeInt(-1);
        } else {
            dest.writeInt(enumValue.ordinal());
        }
    }

    /**
     * Enum zur Darstellung des Status des Senders in Bezug auf die Signatur.
     */
    public enum SenderStatusResult {
        UNKNOWN,
        USER_ID_CONFIRMED,
        USER_ID_UNCONFIRMED,
        USER_ID_MISSING;

        public static final SenderStatusResult[] VALUES = values();
    }
}
