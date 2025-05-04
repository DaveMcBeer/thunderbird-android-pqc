package com.fsck.k9.pqcExtension.keyManagement;

public class KeyRegistryFactory {

    public enum KeyType {
        PGP,

        PQC,        // Kombiniert
        PQC_SIG,    // Nur Signatur
        PQC_KEM     // Nur KEM
    }

    public static IKeyRegistry getRegistry(KeyType type) {
        switch (type) {
            case PGP:
                return new PgpKeyRegistry();
            case PQC:
                return new PqcKeyRegistry(); // Kombiniert
            case PQC_SIG:
                return new PqcSigKeyRegistry();
            case PQC_KEM:
                return new PqcKemKeyRegistry();
            default:
                throw new IllegalArgumentException("Unsupported KeyType: " + type);
        }
    }
}
