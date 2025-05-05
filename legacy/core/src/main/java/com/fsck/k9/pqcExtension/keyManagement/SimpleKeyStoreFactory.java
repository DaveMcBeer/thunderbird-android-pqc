package com.fsck.k9.pqcExtension.keyManagement;

public class SimpleKeyStoreFactory {

    public enum KeyType {
        PGP,
        PQC_SIG,
        PQC_KEM
    }

    /**
     * Liefert den passenden SimpleKeyStore für einen Algorithmustyp.
     */
    public static SimpleKeyStore getKeyStore(KeyType type) {
        switch (type) {
            case PGP:
                return new PgpSimpleKeyStore();
            case PQC_SIG:
                return new PqcSigSimpleKeyStore();
            case PQC_KEM:
                return new PqcKemSimpleKeyStore();
            default:
                throw new IllegalArgumentException("Unsupported KeyType: " + type);
        }
    }
}
