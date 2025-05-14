package com.fsck.k9.pqcExtension.message.results;

import android.os.Parcel;
import android.os.Parcelable;

/**
 * Represents the result of a PQC (Post-Quantum Cryptography) decryption operation.
 *
 * This class is Parcelable, allowing it to be passed between Android components.
 * It stores the result status and optionally the session key and its decrypted counterpart.
 */
public class PqcDecryptionResult implements Parcelable {
    public static final int PARCELABLE_VERSION = 1;

    // Constants representing the encryption status
    public static final int RESULT_NOT_DECRYPTED = -1; // The content was not decrypted
    public static final int RESULT_DECRYPTED = 1;       // The content was decrypted

    public final int result;                  // Status/result of the decryption

    /**
     * Returns the result status code.
     */
    public int getResult() {
        return result;
    }

    /**
     * Constructor for minimal result status (e.g., not encrypted).
     */
    public PqcDecryptionResult(int result) {
        this.result = result;
    }

    /**
     * Constructor for encrypted content with session key information.
     */
    public PqcDecryptionResult(int result, byte[] sessionKey, byte[] decryptedSessionKey) {
        this.result = result;
        if ((sessionKey == null) != (decryptedSessionKey == null)) {
            throw new AssertionError("sessionKey must be null iff decryptedSessionKey is null");
        }
    }

    /**
     * Copy constructor.
     */
    public PqcDecryptionResult(PqcDecryptionResult other) {
        this.result = other.result;
    }

    @Override
    public int describeContents() {
        return 0;
    }

    /**
     * Serializes this object into a Parcel (e.g., for IPC or Intent transfer).
     * Includes versioning for future compatibility.
     */
    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeInt(PARCELABLE_VERSION); // Write current version
        int sizePosition = dest.dataPosition(); // Mark position to insert size later
        dest.writeInt(0); // Placeholder for size
        int startPosition = dest.dataPosition();

        // Version 1 data
        dest.writeInt(result);

        // Calculate and write actual size
        int parcelableSize = dest.dataPosition() - startPosition;
        dest.setDataPosition(sizePosition);
        dest.writeInt(parcelableSize);
        dest.setDataPosition(startPosition + parcelableSize);
    }

    /**
     * Reconstructs the object from a Parcel (used in Android IPC).
     * Supports versioning for backward compatibility.
     */
    public static final Creator<PqcDecryptionResult> CREATOR = new Creator<PqcDecryptionResult>() {
        public PqcDecryptionResult createFromParcel(final Parcel source) {
            int version = source.readInt();          // Read version
            int parcelableSize = source.readInt();   // Read data block size
            int startPosition = source.dataPosition();

            // Read versioned values
            int result = source.readInt();
            byte[] sessionKey = version >= 1 ? source.createByteArray() : null;
            byte[] decryptedSessionKey = version >= 1 ? source.createByteArray() : null;

            PqcDecryptionResult pqcResult = new PqcDecryptionResult(result, sessionKey, decryptedSessionKey);

            // Restore parcel position
            source.setDataPosition(startPosition + parcelableSize);

            return pqcResult;
        }

        public PqcDecryptionResult[] newArray(final int size) {
            return new PqcDecryptionResult[size];
        }
    };

    @Override
    public String toString() {
        return "\nresult: " + result;
    }
}
