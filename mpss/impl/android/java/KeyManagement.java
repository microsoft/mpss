// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

package com.microsoft.mpss;

import android.annotation.TargetApi;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.security.keystore.StrongBoxUnavailableException;
import android.util.Log;

import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
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
import java.security.cert.Certificate;
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
 * key storage.
 */
public class KeyManagement {
    private static final ThreadLocal<String> _lastError = ThreadLocal.withInitial(() -> "");
    private static final Object _keyLock = new Object();

    private static KeyPair CreateKey(String keyName, Algorithm algorithm, Boolean useStrongbox)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeySpecException {
        if (null == keyName) {
            throw new IllegalArgumentException("keyName is null.");
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
        builder.setIsStrongBoxBacked(useStrongbox);

        kpg.initialize(builder.build());

        return kpg.generateKeyPair();
    }

    @TargetApi(Build.VERSION_CODES.S)
    private static final class Api31Impl {
        private Api31Impl() {
        }

        private static int GetKeySecurityLevel(KeyInfo keyInfo, String keyName) {
            int level = keyInfo.getSecurityLevel();
            switch(level) {
                case KeyProperties.SECURITY_LEVEL_UNKNOWN:
                    Log.i("MPSS", "Key has security level Unknown: " + keyName);
                    return 0;
                case KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE:
                    Log.i("MPSS", "Key has security level UnknownSecure: " + keyName);
                    return 2;
                case KeyProperties.SECURITY_LEVEL_SOFTWARE:
                    Log.i("MPSS", "Key has security level Software: " + keyName);
                    return 1;
                case KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT:
                    Log.i("MPSS", "Key has security level TrustedEnvironment: " + keyName);
                    return 3;
                case KeyProperties.SECURITY_LEVEL_STRONGBOX:
                    Log.i("MPSS", "Key has security level StrongBox: " + keyName);
                    return 4;
                default:
                    Log.i("MPSS", "Key has unknown security level: " + keyName);
                    return 0;
            }
        }
    }

    /**
     * Whether this key is one MPSS can vouch for.
     * @param keyInfo Properties read back from the key store.
     * @return Null when the key is usable, otherwise why it is refused.
     */
    private static String GetKeyRefusalReason(KeyInfo keyInfo) {
        // Where a key is now says nothing about where it came from. A key imported into the key
        // store genuinely resides in secure hardware, so it reports hardware backing while whoever
        // imported it still holds the private material.
        final int origin = keyInfo.getOrigin();
        if (KeyProperties.ORIGIN_GENERATED != origin) {
            return "was not generated inside the key store (origin: " + DescribeOrigin(origin) + ")";
        }

        return null;
    }

    /**
     * Name an origin for a log message, since the framework values are easy to misread as flags.
     * @param origin Origin value read back from the key store.
     * @return Name of the origin.
     */
    private static String DescribeOrigin(int origin) {
        switch (origin) {
            case KeyProperties.ORIGIN_GENERATED:
                return "generated";
            case KeyProperties.ORIGIN_IMPORTED:
                return "imported";
            case KeyProperties.ORIGIN_SECURELY_IMPORTED:
                return "securely imported";
            case KeyProperties.ORIGIN_UNKNOWN:
                return "unknown";
            default:
                return "unrecognized value " + origin;
        }
    }

    /**
     * Report the capabilities a key needs in order to sign here.
     *
     * These are reported rather than refused. A key store that honors a capability at generation
     * but does not echo it back would otherwise make its own keys permanently unopenable, and a
     * key that genuinely lacks one cannot produce a signature regardless.
     * @param keyName Name of the key.
     * @param keyInfo Properties read back from the key store.
     */
    private static void LogMissingKeyCapabilities(String keyName, KeyInfo keyInfo) {
        if (0 == (keyInfo.getPurposes() & KeyProperties.PURPOSE_SIGN)) {
            Log.w("MPSS", "Key '" + keyName + "' does not report a signing purpose.");
        }

        final String[] digests = keyInfo.getDigests();
        if (null == digests || !Arrays.asList(digests).contains(KeyProperties.DIGEST_NONE)) {
            Log.w("MPSS", "Key '" + keyName + "' does not report accepting pre-hashed input.");
        }

        if (keyInfo.isUserAuthenticationRequired()) {
            Log.w("MPSS", "Key '" + keyName + "' reports requiring user authentication.");
        }
    }

    /**
     * Get security level for the given key pair.
     * @param keyName Name of the keypair.
     * @return Integer indicating security level of the key. Possible values are:
     *         0: Unknown
     *         1: Software
     *         2: Unknown Secure
     *         3: Trusted Environment
     *         4: StrongBox
     *         -1: Error getting security level
     */
    @SuppressWarnings("deprecation")
    public static int GetKeySecurityLevel(String keyName) {
        ClearError();
        try {
            if (null == keyName) throw new IllegalArgumentException("keyName is null.");

            KeyPair kp = GetExistingKeyPair(keyName);
            if (null == kp) {
                String msg = "Could not get key: " + keyName;
                Log.e("MPSS", msg);
                SetError(msg);
                return -1;
            }

            PrivateKey pk = kp.getPrivate();

            KeyFactory keyFactory = KeyFactory.getInstance(pk.getAlgorithm(), "AndroidKeyStore");
            KeyInfo keyInfo = keyFactory.getKeySpec(pk, KeyInfo.class);

            String refusal = GetKeyRefusalReason(keyInfo);
            if (null != refusal) {
                String msg = "Refusing key '" + keyName + "': it " + refusal + ".";
                Log.e("MPSS", msg);
                SetError(msg);
                return -1;
            }

            LogMissingKeyCapabilities(keyName, keyInfo);

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                return Api31Impl.GetKeySecurityLevel(keyInfo, keyName);
            } else {
                if (keyInfo.isInsideSecureHardware()) {
                    Log.i("MPSS", "Key is inside secure hardware: " + keyName);
                    return 2; // Unknown secure
                }

                Log.i("MPSS", "Key is not inside secure hardware: " + keyName);
                return 0; // Unknown
            }
        } catch (NoSuchProviderException e) {
            String msg = "No such provider.";
            Log.e("MPSS", msg);
            SetError(msg);
            return -1;
        } catch (NoSuchAlgorithmException e) {
            String msg = "No such algorithm.";
            Log.e("MPSS", msg);
            SetError(msg);
            return -1;
        } catch (InvalidKeySpecException e) {
            String msg = "Invalid Key Spec.";
            Log.e("MPSS", msg);
            SetError(msg);
            return -1;
        } catch (RuntimeException e) {
            String msg = "Unexpected error getting key security level: " + e.toString();
            Log.e("MPSS", msg);
            SetError(msg);
            return -1;
        }
    }

    /**
     * Create a new long-term key.
     * Tries to create first in StrongBox when supported, then falls back to AndroidKeyStore.
     * @param keyName Name of the key to create.
     * @param algorithm Algorithm for the key.
     * @return The generation the hold was taken on, or null if the key could not be created. The
     *         handle keeps it and presents it with every operation it makes, the release that gives
     *         the hold back included.
     */
    public static Long CreateKey(String keyName, Algorithm algorithm) {
        ClearError();
        synchronized (_keyLock) {
            try {
                if (null == keyName) throw new IllegalArgumentException("keyName is null.");
                if (null == algorithm) throw new IllegalArgumentException("algorithm is null.");

                // Fail-closed existence check. containsAlias tests presence without loading the key, so
                // a transiently unloadable key still reports as present, and if existence cannot be
                // determined we refuse to create rather than overwriting a live key.
                try {
                    KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
                    ks.load(null);
                    if (ks.containsAlias(keyName)) {
                        String msg = "Key with same name already exists: " + keyName;
                        Log.e("MPSS", msg);
                        SetError(msg);
                        return null;
                    }
                } catch (KeyStoreException | IOException | CertificateException | NoSuchAlgorithmException ex) {
                    String msg = "Could not determine whether key exists; refusing to create: " + ex.toString();
                    Log.e("MPSS", msg);
                    SetError(msg);
                    return null;
                }

                KeyPair kp = null;
                boolean useStrongbox = false;

                // Only P-256 is supported in StrongBox.
                if (algorithm == Algorithm.secp256r1) {
                    useStrongbox = true;
                }

                try {
                    kp = CreateKey(keyName, algorithm, useStrongbox);
                } catch (StrongBoxUnavailableException ex) {
                    Log.w("MPSS", "StrongBox is not available.");
                }

                if (!useStrongbox && null == kp) {
                    // If we are not using StrongBox, no need to try again.
                    String msg = "Failed to create key in TEE.";
                    Log.w("MPSS", msg);
                    SetError(msg);
                    return null;
                }

                // Try again without StrongBox.
                if (null == kp) {
                    kp = CreateKey(keyName, algorithm, /* useStrongBox */ false);
                }

                if (null == kp) {
                    String msg = "Failed to create key: " + keyName;
                    Log.e("MPSS", msg);
                    SetError(msg);
                    return null;
                }

                MemKeyStore.AddKey(keyName, kp);
                return MemKeyStore.RetainKey(keyName);
            } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException |
                     NoSuchProviderException | InvalidKeySpecException ex) {
                String msg = "Error creating key: " + ex.toString();
                Log.e("MPSS", msg);
                SetError(msg);
                return null;
            } catch (RuntimeException ex) {
                String msg = "Unexpected error creating key: " + ex.toString();
                Log.e("MPSS", msg);
                SetError(msg);
                return null;
            }
        }
    }

    /**
     * Sign a hash using the given key.
     * @param keyName Name of the key to use.
     * @param hash Hash to sign.
     * @return Signature, or null if signature could not be created.
     */
    public static byte[] SignHash(String keyName, byte[] hash, long generation) {
        ClearError();
        try {
            if (null == keyName) throw new IllegalArgumentException("keyName is null.");
            if (null == hash) throw new IllegalArgumentException("hash is null.");

            KeyPair kp;
            synchronized (_keyLock) {
                kp = MemKeyStore.GetKeyForGeneration(keyName, generation);
            }
            if (null == kp) {
                String msg = "Key '" + keyName + "' is no longer the key this handle opened.";
                Log.e("MPSS", msg);
                SetError(msg);
                return null;
            }

            Signature signature = Signature.getInstance("NONEwithECDSA");
            signature.initSign(kp.getPrivate());
            signature.update(hash);

            return signature.sign();
        } catch (InvalidKeyException | SignatureException | NoSuchAlgorithmException ex) {
            String msg = "Error signing hash: " + ex.toString();
            Log.e("MPSS", msg);
            SetError(msg);
            return null;
        } catch (RuntimeException ex) {
            String msg = "Unexpected error signing hash: " + ex.toString();
            Log.e("MPSS", msg);
            SetError(msg);
            return null;
        }
    }

    /**
     * Verify that the given signature for the given hash is correct.
     * @param keyName Name of the key used to verify signature.
     * @param hash Hash whose signature should be verified.
     * @param sig Signature to verify.
     * @return True if signature verifies correctly, False otherwise.
     */
    public static Boolean VerifySignature(String keyName, byte[] hash, byte[] sig, long generation) {
        ClearError();
        try {
            if (null == keyName) throw new IllegalArgumentException("keyName is null.");
            if (null == hash) throw new IllegalArgumentException("hash is null.");
            if (null == sig) throw new IllegalArgumentException("sig is null.");

            KeyPair kp;
            synchronized (_keyLock) {
                kp = MemKeyStore.GetKeyForGeneration(keyName, generation);
            }
            if (null == kp) {
                String msg = "Key '" + keyName + "' is no longer the key this handle opened.";
                Log.e("MPSS", msg);
                SetError(msg);
                return null;
            }

            return VerifySignature(hash, sig, kp.getPublic());
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException ex) {
            String msg = "Error verifying signature: " + ex.toString();
            Log.e("MPSS", msg);
            SetError(msg);
            return null;
        } catch (RuntimeException ex) {
            String msg = "Unexpected error verifying signature: " + ex.toString();
            Log.e("MPSS", msg);
            SetError(msg);
            return null;
        }
    }

    /**
     * Verify that the given signature for the given hash is correct, using the given
     * public key.
     * @param hash Hash whose signature should be verified.
     * @param sig Signature to verify.
     * @param pk Public key used to verify signature.
     * @return True if signature verifies correctly, False otherwise.
     */
    public static Boolean VerifySignature(byte[] hash, byte[] sig, byte[] pk) {
        ClearError();
        try {
            if (null == hash) throw new IllegalArgumentException("hash is null.");
            if (null == sig) throw new IllegalArgumentException("sig is null.");
            if (null == pk) throw new IllegalArgumentException("pk is null.");

            PublicKey publicKey = FromUncompressedPoint(pk);
            return VerifySignature(hash, sig, publicKey);
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException |
                 InvalidKeySpecException | InvalidParameterSpecException ex) {
            String msg = "Error verifying signature: " + ex.toString();
            Log.e("MPSS", msg);
            SetError(msg);
            return null;
        } catch (RuntimeException ex) {
            String msg = "Unexpected error verifying signature: " + ex.toString();
            Log.e("MPSS", msg);
            SetError(msg);
            return null;
        }
    }

    private static Boolean VerifySignature(byte[] hash, byte[] sig, PublicKey pk)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("NONEwithECDSA");
        signature.initVerify(pk);
        signature.update(hash);

        return signature.verify(sig);
    }

    /**
     * Get a representation of the public key of the given key pair.
     * @param keyName Name of the key pair whose public key we need to get.
     * @return Representation of the public key.
     */
    public static byte[] GetPublicKey(String keyName, long generation) {
        ClearError();
        if (null == keyName) throw new IllegalArgumentException("keyName is null.");

        KeyPair kp;
        synchronized (_keyLock) {
            kp = MemKeyStore.GetKeyForGeneration(keyName, generation);
        }
        if (null == kp) {
            String msg = "Key '" + keyName + "' is no longer the key this handle opened.";
            Log.e("MPSS", msg);
            SetError(msg);
            return null;
        }
        return EncodePublicKey(kp);
    }

    /**
     * Encode a key pair's public key as an uncompressed point.
     * @param kp The key pair whose public key to encode.
     * @return The uncompressed point, or null on failure.
     */
    private static byte[] EncodePublicKey(KeyPair kp) {
        try {
            // Parse X509.
            KeyFactory kf = KeyFactory.getInstance("EC");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(kp.getPublic().getEncoded());
            ECPublicKey ecpk = (ECPublicKey) kf.generatePublic(keySpec);

            // Get coordinates.
            ECPoint point = ecpk.getW();
            BigInteger x = point.getAffineX();
            BigInteger y = point.getAffineY();

            int fieldSize = ecpk.getParams().getCurve().getField().getFieldSize();
            int coordinateSize = (fieldSize + 7) / 8;

            // Pad and format.
            byte[] xBytes = PadToSize(x.toByteArray(), coordinateSize);
            byte[] yBytes = PadToSize(y.toByteArray(), coordinateSize);

            byte[] uncompressed = new byte[1 + (coordinateSize * 2)];
            uncompressed[0] = 0x04;
            System.arraycopy(xBytes, 0, uncompressed, 1, coordinateSize);
            System.arraycopy(yBytes, 0, uncompressed, 1 + coordinateSize, coordinateSize);

            return uncompressed;
        } catch (InvalidKeySpecException | NoSuchAlgorithmException ex) {
            String msg = "Error getting public key: " + ex.toString();
            Log.e("MPSS", msg);
            SetError(msg);
            return null;
        } catch (RuntimeException ex) {
            String msg = "Unexpected error getting public key: " + ex.toString();
            Log.e("MPSS", msg);
            SetError(msg);
            return null;
        }
    }

    /**
     * Close the given key.
     * @param keyName Name of the key to close.
     * @param generation The generation the hold was taken on, as returned by OpenKey or CreateKey.
     */
    public static void CloseKey(String keyName, long generation) {
        ClearError();
        if (null == keyName) throw new IllegalArgumentException("keyName is null.");
        synchronized (_keyLock) {
            MemKeyStore.RemoveKey(keyName, generation);
        }
    }

    /**
     * Delete the key a handle opened, refusing once the name has moved on.
     *
     * Deleting addresses the alias rather than the cached entry, so a handle whose key is gone
     * would otherwise delete whatever key now holds its name.
     * @param keyName Name of the key to delete.
     * @param generation The generation the handle recorded when it opened.
     * @return True if the key was deleted, False otherwise.
     */
    public static Boolean DeleteKey(String keyName, long generation) {
        ClearError();
        synchronized (_keyLock) {
            if (null == keyName) throw new IllegalArgumentException("keyName is null.");
            if (!MemKeyStore.GenerationIsCurrent(keyName, generation)) {
                String msg = "Key '" + keyName + "' is no longer the key this handle opened.";
                Log.e("MPSS", msg);
                SetError(msg);
                return false;
            }
        }
        return DeleteKey(keyName);
    }

    public static Boolean DeleteKey(String keyName) {
        ClearError();
        synchronized (_keyLock) {
            try {
                if (null == keyName) throw new IllegalArgumentException("keyName is null.");

                // Deleting needs the alias, not the key. Requiring the key pair to load first would
                // leave an entry whose key or certificate cannot be read impossible to remove, which
                // is the state a caller most needs to clear.
                KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
                ks.load(/* param */ null);
                if (!ks.containsAlias(keyName)) {
                    // The alias holds nothing, which is the requested state.
                    MemKeyStore.PurgeKey(keyName);
                    return true;
                }

                ks.deleteEntry(keyName);
                MemKeyStore.PurgeKey(keyName);

                if (ks.containsAlias(keyName)) {
                    String msg = "Key still present after deletion: " + keyName;
                    Log.e("MPSS", msg);
                    SetError(msg);
                    return false;
                }
                return true;
            } catch (KeyStoreException | IOException | CertificateException |
                     NoSuchAlgorithmException ex) {
                String msg = "Error deleting key: " + ex.toString();
                Log.e("MPSS", msg);
                SetError(msg);
                return false;
            } catch (RuntimeException ex) {
                String msg = "Unexpected error deleting key: " + ex.toString();
                Log.e("MPSS", msg);
                SetError(msg);
                return false;
            }
        }
    }

    /**
     * Open the key pair with the given name.
     * @param keyName Name of the key pair to open.
     * @return The generation the hold was taken on, -1 if no such key exists, or null on error. The
     *         handle keeps it and presents it with every operation it makes, the release that gives
     *         the hold back included.
     */
    public static Long OpenKey(String keyName) {
        ClearError();
        try {
            if (null == keyName) throw new IllegalArgumentException("keyName is null.");
            synchronized (_keyLock) {
                KeyPair kp = GetExistingKeyPair(keyName);
                if (null != kp) {
                    // Taking the hold under the same lock the lookup uses keeps a concurrent close
                    // or delete from evicting the entry between the two.
                    return MemKeyStore.RetainKey(keyName);
                }
            }
            return _lastError.get().isEmpty() ? -1L : null;
        } catch (RuntimeException ex) {
            String msg = "Unexpected error opening key: " + ex.toString();
            Log.e("MPSS", msg);
            SetError(msg);
            return null;
        }
    }

    /**
     * Get the Algorithm that was used to create the given key.
     * @param keyName Name of the key pair.
     * @return Algorithm used to create the key pair.
     */
    public static Algorithm GetKeyAlgorithm(String keyName) {
        ClearError();
        try {
            if (null == keyName) throw new IllegalArgumentException("keyName is null.");

            // Deduce the type from the length of the public key.
            KeyPair kp = GetExistingKeyPair(keyName);
            if (null == kp) {
                return Algorithm.undefined;
            }
            byte[] pk = EncodePublicKey(kp);
            if (null == pk) {
                return Algorithm.undefined;
            }

            switch(pk.length) {
                case 65:
                    return Algorithm.secp256r1;
                case 97:
                    return Algorithm.secp384r1;
                case 133:
                    return Algorithm.secp521r1;
                default:
                    String msg = "Unsupported public key length: " + pk.length;
                    Log.e("MPSS", msg);
                    SetError(msg);
                    return Algorithm.undefined;
            }
        } catch (RuntimeException ex) {
            String msg = "Unexpected error getting key algorithm: " + ex.toString();
            Log.e("MPSS", msg);
            SetError(msg);
            return Algorithm.undefined;
        }
    }

    private static KeyPair GetExistingKeyPair(String keyName) {
        synchronized (_keyLock) {
            try {
                // Check mem store first.
                KeyPair kp = MemKeyStore.GetKey(keyName);
                if (null != kp) {
                    return kp;
                }

                KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
                ks.load(null);
                if (!ks.containsAlias(keyName)) {
                    return null;
                }
                Key key = ks.getKey(keyName, /* password */ null);
                if (!(key instanceof PrivateKey)) {
                    String msg = "AndroidKeyStore entry is not a private key: " + keyName;
                    Log.w("MPSS", msg);
                    SetError(msg);
                    return null;
                }
                PrivateKey pk = (PrivateKey) key;

                Certificate cert = ks.getCertificate(keyName);
                if (null == cert) {
                    String msg = "Key present but has no certificate: " + keyName;
                    Log.w("MPSS", msg);
                    SetError(msg);
                    return null;
                }
                PublicKey pubKey = cert.getPublicKey();
                kp = new KeyPair(pubKey, pk);
                MemKeyStore.AddKey(keyName, kp);

                return kp;
            } catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException |
                     CertificateException | IOException ex) {
                String msg = "Error opening key: " + ex.toString();
                Log.e("MPSS", msg);
                SetError(msg);
                return null;
            } catch (RuntimeException ex) {
                String msg = "Unexpected error opening key: " + ex.toString();
                Log.e("MPSS", msg);
                SetError(msg);
                return null;
            }
        }
    }

    /**
     * Get and clear the text of the last error that occurred.
     * @return Last error that occurred.
     */
    public static String TakeError() {
        String error = _lastError.get();
        _lastError.remove();
        return error;
    }

    private static void SetError(String error) {
        _lastError.set(error);
    }

    private static void ClearError() {
        _lastError.remove();
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
            throw new IllegalArgumentException("Invalid EC point format.");
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
