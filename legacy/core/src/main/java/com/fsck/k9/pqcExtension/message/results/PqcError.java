package com.fsck.k9.pqcExtension.message.results;

import android.os.Parcel;
import android.os.Parcelable;

/**
 * Represents an error that occurred during a PQC operation such as encryption, decryption, or signature validation.
 * Implements Parcelable to allow easy transfer across Android components.
 */
public class PqcError implements Parcelable {
    public static final int PARCELABLE_VERSION = 1;

    // Predefined error codes
    public static final int CLIENT_SIDE_ERROR = -1;
    public static final int GENERIC_ERROR = 0;
    public static final int INVALID_SIGNATURE = 1;
    public static final int KEY_MISSING = 2;
    public static final int UNSUPPORTED_ALGORITHM = 3;
    public static final int DECRYPTION_FAILED = 4;
    public static final int MALFORMED_SIGNATURE = 5;

    private int errorId;
    private String message;

    /**
     * Default constructor (required for Parcelable).
     */
    public PqcError() {
    }

    /**
     * Constructs a new PqcError with specified ID and message.
     */
    public PqcError(int errorId, String message) {
        this.errorId = errorId;
        this.message = message;
    }

    /**
     * Copy constructor.
     */
    public PqcError(PqcError other) {
        this.errorId = other.errorId;
        this.message = other.message;
    }

    public int getErrorId() {
        return errorId;
    }

    public void setErrorId(int errorId) {
        this.errorId = errorId;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    @Override
    public int describeContents() {
        return 0;
    }

    @Override
    public String toString() {
        return "PQC Error (" + errorId + "): " + message;
    }

    /**
     * Serializes this error into a Parcel.
     */
    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeInt(PARCELABLE_VERSION);
        int sizePosition = dest.dataPosition();
        dest.writeInt(0); // placeholder for size
        int startPosition = dest.dataPosition();

        dest.writeInt(errorId);
        dest.writeString(message);

        int parcelableSize = dest.dataPosition() - startPosition;
        dest.setDataPosition(sizePosition);
        dest.writeInt(parcelableSize);
        dest.setDataPosition(startPosition + parcelableSize);
    }

    /**
     * Reconstructs a PqcError from a Parcel.
     */
    public static final Creator<PqcError> CREATOR = new Creator<PqcError>() {
        @Override
        public PqcError createFromParcel(Parcel source) {
            source.readInt(); // version
            int parcelableSize = source.readInt();
            int startPosition = source.dataPosition();

            PqcError error = new PqcError();
            error.errorId = source.readInt();
            error.message = source.readString();

            source.setDataPosition(startPosition + parcelableSize);
            return error;
        }

        @Override
        public PqcError[] newArray(int size) {
            return new PqcError[size];
        }
    };
}
