package com.fsck.k9.pqcExtension.helper.signature;

import android.content.Context;

import com.fsck.k9.pqcExtension.keyManagement.SimpleKeyStoreFactory;
import com.fsck.k9.pqcExtension.keyManagement.SimpleKeyStoreFactory.KeyType;
import com.fsck.k9.pqcExtension.keyManagement.manager.PgpSimpleKeyManager;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.*;
import org.json.JSONObject;
import org.openquantumsafe.Signature;

import java.io.ByteArrayOutputStream;
import java.security.Security;
import java.util.*;

public class PqcSignatureHelper {

    private final String userId;
    private final Context context;


    /**
     * Constructs a signature helper for a specific user and Android context.
     * Adds the BouncyCastle provider if not already registered.
     */
    public PqcSignatureHelper(String userId, Context context) {
        this.userId = userId;
        this.context = context;
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Generates both PGP and PQC signatures for the given data.
     *
     * @param data  The input data to sign
     * @return      A map containing both signatures ("pgp" and "pqc-sig")
     * @throws Exception If signing fails
     */
    public Map<String, byte[]> signAll(byte[] data) throws Exception {
        Map<String, byte[]> result = new HashMap<>();
        result.put("pgp", signWithPgp(data));
        result.put("pqc-sig", signWithPqcSig(data));
        return result;
    }


    /**
     * Signs data using the user's PGP private key.
     *
     * @param data  The data to sign
     * @return      The ASCII-armored PGP signature
     * @throws Exception If PGP signing fails or key is missing
     */
    private byte[] signWithPgp(byte[] data) throws Exception {
        JSONObject json = SimpleKeyStoreFactory.getKeyStore(KeyType.PGP).loadLocalPrivateKey(context,userId);
        String armoredPriv = "";
        if(json.has("privateKey")) {
            armoredPriv=json.getString("privateKey");
        }

        // Load the secret key ring
        PGPSecretKeyRing secretKeyRing = PgpSimpleKeyManager.parseSecretKeyRing(armoredPriv);
        if (secretKeyRing == null) throw new Exception("PGP priv key missing");

        // Find signing key from key ring
        PGPSecretKey signingKey = null;
        for (PGPSecretKey key : secretKeyRing) {
            if (key.isSigningKey()) {
                signingKey = key;
                break;
            }
        }
        if (signingKey == null) throw new Exception("No signing key found in PGP key ring");

        // Extract private key
        PGPPrivateKey privateKey = signingKey.extractPrivateKey(
            new JcePBESecretKeyDecryptorBuilder()
                .setProvider(new BouncyCastleProvider())
                .build(new char[0])
        );

        // Create signature generator
        PGPSignatureGenerator sigGen = new PGPSignatureGenerator(
            new JcaPGPContentSignerBuilder(
                signingKey.getPublicKey().getAlgorithm(),
                PGPUtil.SHA512
            ).setProvider(new BouncyCastleProvider())
        );

        sigGen.init(PGPSignature.BINARY_DOCUMENT, privateKey);
        sigGen.update(data);

        // Encode signature in ASCII-armored format
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ArmoredOutputStream aos = new ArmoredOutputStream(baos)) {
            sigGen.generate().encode(aos);
        }

        return baos.toByteArray();
    }

    /**
     * Signs data using a post-quantum signature algorithm from OpenQuantumSafe.
     *
     * @param data  The data to sign
     * @return      The binary PQC signature
     * @throws RuntimeException if signing fails
     */
    private byte[] signWithPqcSig(byte[] data) {
        Signature signer = null;
        try {
            JSONObject obj = SimpleKeyStoreFactory.getKeyStore(KeyType.PQC_SIG).loadLocalPrivateKey(context, userId);
            String algorithm = obj.getString("algorithm");
            String privB64 = obj.getString("privateKey");

            byte[] privateKeyBytes = Base64.getDecoder().decode(privB64);

            signer = new Signature(algorithm, privateKeyBytes);
            return signer.sign(data);

        } catch (Exception e) {
            throw new RuntimeException("Error during PQC signature generation", e);

        } finally {
            if (signer != null) {
                signer.dispose_sig();
            }
        }
    }
}
