package com.fsck.k9.mailstore.pqc;

/*
 * Klasse zur Repräsentation des Ergebnisses einer PQC-Entschlüsselung.
 * Wird z. B. beim Parsen verschlüsselter E-Mails genutzt.
 *
 * Unterstützt das Android-Parcelable-Interface, damit sie zwischen Prozessen oder Komponenten übergeben werden kann.
 * Enthält sowohl den Entschlüsselungsstatus als auch optionale Session Keys.
 */

import android.os.Parcel;
import android.os.Parcelable;

public class PqcDecapsulationResult implements Parcelable {
    public static final int PARCELABLE_VERSION = 1;

    // Konstanten zur Ergebniskennung
    public static final int RESULT_NOT_ENCRYPTED = -1; // Inhalt war nicht verschlüsselt
    public static final int RESULT_ENCRYPTED = 1;       // Inhalt war verschlüsselt

    public final int result;                  // Status des Entschlüsselungsvorgangs
    public final byte[] sessionKey;           // (Optional) ursprünglicher Session Key
    public final byte[] decryptedSessionKey;  // (Optional) entschlüsselter Session Key

    public int getResult() {
        return result;
    }

    // Konstruktor für "nicht verschlüsselt" oder minimalen Status
    public PqcDecapsulationResult(int result) {
        this.result = result;
        this.sessionKey = null;
        this.decryptedSessionKey = null;
    }

    // Konstruktor für "verschlüsselt", inkl. Session Keys
    public PqcDecapsulationResult(int result, byte[] sessionKey, byte[] decryptedSessionKey) {
        this.result = result;
        if ((sessionKey == null) != (decryptedSessionKey == null)) {
            throw new AssertionError("sessionKey must be null iff decryptedSessionKey is null");
        }
        this.sessionKey = sessionKey;
        this.decryptedSessionKey = decryptedSessionKey;
    }

    // Copy-Konstruktor
    public PqcDecapsulationResult(PqcDecapsulationResult other) {
        this.result = other.result;
        this.sessionKey = other.sessionKey;
        this.decryptedSessionKey = other.decryptedSessionKey;
    }

    @Override
    public int describeContents() {
        return 0;
    }

    /**
     * Serialisiert dieses Objekt in ein Parcel (für IPC oder Intents).
     * Beinhaltet eine Versionierung zur späteren Kompatibilität.
     */
    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeInt(PARCELABLE_VERSION); // Schreib die aktuelle Version
        int sizePosition = dest.dataPosition(); // Marker für spätere Größe
        dest.writeInt(0); // Platzhalter für Größe
        int startPosition = dest.dataPosition();

        // Version 1: Inhalt
        dest.writeInt(result);
        dest.writeByteArray(sessionKey);
        dest.writeByteArray(decryptedSessionKey);

        // Schreibe tatsächliche Größe
        int parcelableSize = dest.dataPosition() - startPosition;
        dest.setDataPosition(sizePosition);
        dest.writeInt(parcelableSize);
        dest.setDataPosition(startPosition + parcelableSize);
    }

    /**
     * Erzeugt ein Objekt aus einem Parcel (Deserialisierung).
     * Unterstützt verschiedene Versionen zur Abwärtskompatibilität.
     */
    public static final Creator<PqcDecapsulationResult> CREATOR = new Creator<PqcDecapsulationResult>() {
        public PqcDecapsulationResult createFromParcel(final Parcel source) {
            int version = source.readInt();          // Lese Version
            int parcelableSize = source.readInt();   // Lese Datenblockgröße
            int startPosition = source.dataPosition();

            // Lese Werte je nach Version
            int result = source.readInt();
            byte[] sessionKey = version >= 1 ? source.createByteArray() : null;
            byte[] decryptedSessionKey = version >= 1 ? source.createByteArray() : null;

            // Erzeuge Objekt
            PqcDecapsulationResult pqcResult = new PqcDecapsulationResult(result, sessionKey, decryptedSessionKey);

            // Position nach Leseblock wiederherstellen
            source.setDataPosition(startPosition + parcelableSize);

            return pqcResult;
        }

        public PqcDecapsulationResult[] newArray(final int size) {
            return new PqcDecapsulationResult[size];
        }
    };

    @Override
    public String toString() {
        return "\nresult: " + result;
    }
}
