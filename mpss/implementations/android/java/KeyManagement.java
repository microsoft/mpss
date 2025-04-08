package com.microsoft.research.mpss;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.security.keystore.StrongBoxUnavailableException;
import android.util.Log;

import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;


/**
 * The {@code KeyManagement} class contains the functionality necessary to manage long-term
 * key storage. It is used by the MPSS library.
 */
public class KeyManagement {
    private static final ThreadLocal<String> _lastError = ThreadLocal.withInitial(() -> "");

    private static KeyPair CreateKey(String keyName, Algorithm algorithm, Boolean useStrongbox) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        if (null == keyName) {
            throw new IllegalArgumentException("keyName is null");
        }

        KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");

        ECGenParameterSpec paramSpec = Utils.GetParamSpec(algorithm);
        String digest = KeyProperties.DIGEST_NONE;

        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
                keyName,
                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setAlgorithmParameterSpec(paramSpec)
                .setDigests(digest)
                .setUserAuthenticationRequired(false);
        if (useStrongbox) {
            builder.setIsStrongBoxBacked(true);
        }

        kpg.initialize(builder.build());

        return kpg.generateKeyPair();
    }

    /**
     * Create a new long-term key.
     * Tries to create first in StrongBox, will create in TEE if StrongBox is not available.
     * @param keyName Name of the key to create
     * @param algorithm Algorithm for the key
     * @return True if key was created successfully, False otherwise.
     */
    public static Boolean CreateKey(String keyName, Algorithm algorithm) {
        if (null == keyName) throw new IllegalArgumentException("keyName is null");
        if (null == algorithm) throw new IllegalArgumentException("algorithm is null");


        try {
            if (OpenKey(keyName)) {
                String msg = "Key with same name already exists: " + keyName;
                Log.e("MPSSKeyGen", msg);
                SetError(msg);
                return false;
            }

            KeyPair kp = null;

            try {
                kp = CreateKey(keyName, algorithm, /* useStrongBox */ true);
            } catch (StrongBoxUnavailableException ex) {
                Log.w("MPSSKeyGen", "Strong box is not available");
            }

            // Try again without StrongBox
            if (null == kp) {
                kp = CreateKey(keyName, algorithm, /* useStrongBox */ false);
            }

            if (null != kp) {
                MemKeyStore.AddKey(keyName, kp);
            }

            return true;
        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException |
                 NoSuchProviderException ex) {
            String msg = "Error creating key: " + ex.toString();
            Log.e("MPSSKeyGen", msg);
            SetError(msg);
            return false;
        }
    }

    /**
     * Sign a hash using the given key
     * @param keyName Name of the key to use
     * @param hash Hash to sign
     * @return Signature, or null if signature could not be created
     */
    public static byte[] SignHash(String keyName, byte[] hash) {
        if (null == keyName) throw new IllegalArgumentException("keyName is null");
        if (null == hash) throw new IllegalArgumentException("hash is null");

        try {
            KeyPair kp = GetExistingKeyPair(keyName);
            if (null == kp) {
                return null;
            }

            Signature signature = Signature.getInstance("NONEwithECDSA");
            signature.initSign(kp.getPrivate());
            signature.update(hash);

            return signature.sign();
        } catch (InvalidKeyException | SignatureException | NoSuchAlgorithmException ex) {
            String msg = "Error signing hash: " + ex.toString();
            Log.e("MPSSSign", msg);
            SetError(msg);
            return null;
        }
    }

    /**
     * Verify that the given signature for the give hash is correct
     * @param keyName Name of the key used to verify signature
     * @param hash Hash whose signature should be verified
     * @param sig Signature to verify
     * @return True if signature verifies correctly, False otherwise
     */
    public static Boolean VerifySignature(String keyName, byte[] hash, byte[] sig) {
        if (null == keyName) throw new IllegalArgumentException("keyName is null");
        if (null == hash) throw new IllegalArgumentException("hash is null");
        if (null == sig) throw new IllegalArgumentException("sig is null");

        try {
            KeyPair kp = GetExistingKeyPair(keyName);
            if (null == kp) {
                return false;
            }

            return VerifySignature(hash, sig, kp.getPublic());
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException ex) {
            String msg = "Error verifying signature: " + ex.toString();
            Log.e("MPSSVerifySig", msg);
            SetError(msg);
            return false;
        }
    }

    /**
     * Verify that the given signature for the given hash is correct, using the given
     * public key.
     * @param hash Hash whose signature should be verified
     * @param sig Signature to verify
     * @param pk Public key used to verify signature
     * @return True if signature verifies correctly, False otherwise
     */
    public static Boolean VerifySignature(byte[] hash, byte[] sig, byte[] pk) {
        if (null == hash) throw new IllegalArgumentException("hash is null");
        if (null == sig) throw new IllegalArgumentException("sig is null");
        if (null == pk) throw new IllegalArgumentException("pk is null");

        try {
            PublicKey publicKey = FromUncompressedPoint(pk);
            return VerifySignature(hash, sig, publicKey);
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException |
                 InvalidKeySpecException | InvalidParameterSpecException ex) {
            String msg = "Error verifying signature: " + ex.toString();
            Log.e("MPSSVerifySig", msg);
            SetError(msg);
            return false;
        }
    }

    private static Boolean VerifySignature(byte[] hash, byte[] sig, PublicKey pk) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("NONEwithECDSA");
        signature.initVerify(pk);
        signature.update(hash);

        return signature.verify(sig);
    }

    /**
     * Get a representation of the public key of the given key pair
     * @param keyName Name of the key pair whose public key we need to get
     * @return Representation of the public key
     */
    public static byte[] GetPublicKey(String keyName) {
        if (null == keyName) throw new IllegalArgumentException("keyName is null");

        try {
            KeyPair kp = GetExistingKeyPair(keyName);
            if (null == kp) {
                return null;
            }

            // Parse X509
            KeyFactory kf = KeyFactory.getInstance("EC");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(kp.getPublic().getEncoded());
            ECPublicKey ecpk = (ECPublicKey) kf.generatePublic(keySpec);

            // Get coordinates
            ECPoint point = ecpk.getW();
            BigInteger x = point.getAffineX();
            BigInteger y = point.getAffineY();

            int fieldSize = ecpk.getParams().getCurve().getField().getFieldSize();
            int coordinateSize = (fieldSize + 7) / 8;

            // Pad and format
            byte[] xBytes = PadToSize(x.toByteArray(), coordinateSize);
            byte[] yBytes = PadToSize(y.toByteArray(), coordinateSize);

            byte[] uncompressed = new byte[1 + (coordinateSize * 2)];
            uncompressed[0] = 0x04;
            System.arraycopy(xBytes, 0, uncompressed, 1, coordinateSize);
            System.arraycopy(yBytes, 0, uncompressed, 1 + coordinateSize, coordinateSize);

            return uncompressed;
        } catch (InvalidKeySpecException | NoSuchAlgorithmException ex) {
            String msg = "Error getting public key: " + ex.toString();
            Log.e("MPSSGetPK", msg);
            SetError(msg);
            return null;
        }
    }

    /**
     * Close the given key
     * @param keyName Name of the key to close.
     */
    public static void CloseKey(String keyName) {
        if (null == keyName) throw new IllegalArgumentException("keyName is null");
        MemKeyStore.RemoveKey(keyName);
    }

    /**
     * Delete the given key
     * @param keyName Name of the key to delete
     */
    public static void DeleteKey(String keyName) {
        if (null == keyName) throw new IllegalArgumentException("keyName is null");

        try {
            KeyPair kp = GetExistingKeyPair(keyName);
            if (null == kp) {
                String msg = "Could not get existing KeyPair";
                Log.w("MPSSDelKey", msg);
                SetError(msg);
                return;
            }

            CloseKey(keyName);

            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(/* param */ null);
            ks.deleteEntry(keyName);
        } catch (KeyStoreException | IOException | CertificateException |
                 NoSuchAlgorithmException ex) {
            String msg = "Error deleting key: " + ex.toString();
            Log.e("MPSSDelKey", msg);
            SetError(msg);
        }
    }

    /**
     * Open the key pair with the given name
     * @param keyName Name of the key pair to open
     * @return True if the key pair was opened successfully, False otherwise
     */
    public static Boolean OpenKey(String keyName) {
        if (null == keyName) throw new IllegalArgumentException("keyName is null");
        return null != GetExistingKeyPair(keyName);
    }

    private static KeyPair GetExistingKeyPair(String keyName) {
        try {
            // Check mem store first
            KeyPair kp = MemKeyStore.GetKey(keyName);
            if (null != kp) {
                return kp;
            }

            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            PrivateKey pk = (PrivateKey) ks.getKey(keyName, /* password */ null);
            if (null == pk) {
                String msg = "Failed to get private key from AndroidKeyStore";
                Log.w("MPSSGetKey", msg);
                SetError(msg);
                return null;
            }

            PublicKey pubKey = ks.getCertificate(keyName).getPublicKey();
            kp = new KeyPair(pubKey, pk);
            MemKeyStore.AddKey(keyName, kp);

            return kp;
        } catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException |
                 CertificateException | IOException ex) {
            String msg = "Error opening key: " + ex.toString();
            Log.e("MPSSOpenKey", msg);
            SetError(msg);
            return null;
        }
    }

    /**
     * Get the text of the last error that occurred
     * @return Last error that occurred
     */
    public static String GetError() {
        return _lastError.get();
    }

    private static void SetError(String error) {
        _lastError.set(error);
    }

    private static byte[] PadToSize(byte[] src, int size) {
        if (src.length == size) return src;
        byte[] padded = new byte[size];
        int start = Math.max(0, src.length - size);
        System.arraycopy(src, start, padded, size - (src.length - start), src.length - start);
        return padded;
    }

    private static PublicKey FromUncompressedPoint(byte[] uncompressed) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidParameterSpecException {
        if (uncompressed[0] != 0x04) {
            throw new IllegalArgumentException("Invalid EC point format");
        }

        String curveName = null;
        int coordLength = 0;

        switch (uncompressed.length) {
            case 65:  // 1 + 32 + 32
                curveName = "secp256r1";
                coordLength = 32;
                break;
            case 97:  // 1 + 48 + 48
                curveName = "secp384r1";
                coordLength = 48;
                break;
            case 133: // 1 + 66 + 66
                curveName = "secp521r1";
                coordLength = 66;
                break;
            default:
                throw new IllegalArgumentException("Unsupported EC key length: " + uncompressed.length);
        }

        byte[] xBytes = Arrays.copyOfRange(uncompressed, 1, 1 + coordLength);
        byte[] yBytes = Arrays.copyOfRange(uncompressed, 1 + coordLength, 1 + 2 * coordLength);

        ECPoint point = new ECPoint(new BigInteger(1, xBytes), new BigInteger(1, yBytes));

        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec(curveName));
        ECParameterSpec ecSpec = parameters.getParameterSpec(ECParameterSpec.class);

        ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, ecSpec);
        KeyFactory kf = KeyFactory.getInstance("EC");
        return kf.generatePublic(pubKeySpec);
    }
}
