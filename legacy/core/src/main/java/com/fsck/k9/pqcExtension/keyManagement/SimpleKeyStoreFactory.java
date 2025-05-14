package com.fsck.k9.pqcExtension.keyManagement;

public class SimpleKeyStoreFactory {

    /**
     * Enumeration of the supported key types.
     * - PGP: Classical PGP encryption/signature key
     * - PQC_SIG: Post-quantum signature key
     * - PQC_KEM: Post-quantum key encapsulation mechanism (KEM) key
     */
    public enum KeyType {
        PGP,
        PQC_SIG,
        PQC_KEM
    }


    /**
     * Returns the appropriate implementation of {@link SimpleKeyStore} for the given key type.
     *
     * @param type The desired key type (PGP, PQC_SIG, PQC_KEM)
     * @return A {@link SimpleKeyStore} instance that handles the requested key type
     * @throws IllegalArgumentException if the key type is not supported
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
