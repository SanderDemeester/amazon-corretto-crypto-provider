// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider;

import static com.amazon.corretto.crypto.provider.Utils.EMPTY_ARRAY;

import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;

import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

/**
 * TODO [childw]
 */
final class AesKeyWrapSpi extends CipherSpi {
    private static final int BLOCK_SIZE = 128 / 8;
    private static final byte[] ICV2 = { (byte) 0xa6, (byte) 0x59, (byte) 0x59, (byte) 0xa6 };

    static {
        Loader.load();
    }
    private final AmazonCorrettoCryptoProvider provider;
    private NativeResource context = null;
    private SecretKey jceKey;
    private byte[] keyBytes;
    private int opmode = -1;    // must be set by init(..)

    AesKeyWrapSpi(final AmazonCorrettoCryptoProvider provider) {
        Loader.checkNativeLibraryAvailability();
        this.provider = provider;
    }

    private static native int wrapKey(byte[] key, byte[] input, byte[] output);

    private static native int unwrapKey(byte[] key, byte[] input, byte[] output);

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        if (mode != null && !"KWP".equals(mode)) {
            throw new NoSuchAlgorithmException(mode + " cannot be used");
        }
    }

    @Override
    protected void engineSetPadding(String padding)
            throws NoSuchPaddingException {
        if (padding != null && !"NoPadding".equalsIgnoreCase(padding)) {
            throw new NoSuchPaddingException("Unsupported padding " + padding);
        }
    }

    @Override
    protected int engineGetBlockSize() {
        return BLOCK_SIZE;
    }

    @Override
    protected int engineGetKeySize(final Key key) throws InvalidKeyException {
        return key.getEncoded().length * 8;
    }

    @Override
    protected int engineGetOutputSize(final int inputLen) {
        // TODO [childw] is below valid?
        // return inputLen + 15;
        throw new UnsupportedOperationException();
    }

    @Override
    protected byte[] engineGetIV() {
        return ICV2.clone();
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        try {
            AlgorithmParameters parameters = AlgorithmParameters.getInstance("IV");
            parameters.init(new IvParameterSpec(ICV2.clone()));
            return parameters;
        } catch (InvalidParameterSpecException | NoSuchAlgorithmException e) {
            throw new Error("Unexpected error", e);
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random)
        throws InvalidKeyException {
        try {
            implInit(opmode, key, random);
        } catch (InvalidAlgorithmParameterException iae) {
            // should never happen
            throw new AssertionError(iae);
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        AlgorithmParameterSpec paramSpec = null;
        if (params != null) {
            try {
                paramSpec = params.getParameterSpec(IvParameterSpec.class);
            } catch (InvalidParameterSpecException ispe) {
                throw new InvalidAlgorithmParameterException("Only IvParameterSpec is accepted");
            }
        }
        engineInit(opmode, key, paramSpec, random);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params != null && !(params instanceof IvParameterSpec)
                && !Arrays.equals(ICV2, ((IvParameterSpec) params).getIV())) {
            throw new InvalidAlgorithmParameterException("Only ICV2 IvParameterSpec is accepted");
        }
        implInit(opmode, key, random);
    }

    private void implInit(int opmode, Key key, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (opmode != Cipher.UNWRAP_MODE && opmode != Cipher.WRAP_MODE) {
            throw new UnsupportedOperationException("Cipher only supports un/wrap modes");
        }
        if (key == null) {
            throw new InvalidKeyException("Null key");
        }
        if (key != jceKey) {
            if (!(key instanceof  SecretKey)) {
                throw new InvalidKeyException("Need a SecretKey");
            }
            if (!"RAW".equalsIgnoreCase(key.getFormat())) {
                throw new InvalidKeyException("Need a raw format key");
            }
            if (!"AES".equalsIgnoreCase(key.getAlgorithm())) {
                throw new InvalidKeyException("Expected an AES key");
            }
            if (keyBytes != null) {
                Arrays.fill(keyBytes, (byte) 0);
                keyBytes = null;
            }
            keyBytes = key.getEncoded();
            if (keyBytes == null) {
                throw new InvalidKeyException("Key doesn't support encoding");
            }
            jceKey = (SecretKey) key;
        }
        this.opmode = opmode;
        // TODO [childw] do something with |random| here?
    }

    @Override
    protected byte[] engineWrap(final Key key) throws IllegalBlockSizeException, InvalidKeyException {
        if (opmode != Cipher.WRAP_MODE || keyBytes == null) {
            throw new IllegalStateException("Cipher must be init'd in WRAP_MODE");
        }
        try {
            final byte[] encoded = Utils.encodeForWrapping(provider, key);
            final byte[] wrappedKey = new byte[4096];
            int wrappedKeyLen = wrapKey(keyBytes, encoded, wrappedKey);
            final byte[] wrappedKeyTruncated = new byte[wrappedKeyLen];
            System.arraycopy(wrappedKey, 0, wrappedKeyTruncated, 0, wrappedKeyLen);
            return wrappedKeyTruncated;
        // TODO [childw] make this exception more specific, perhaps BadPaddingException?
        } catch (final Exception ex) {
            throw new InvalidKeyException("Wrapping failed", ex);
        }
    }

    @Override
    protected Key engineUnwrap(final byte[] wrappedKey, final String wrappedKeyAlgorithm, final int wrappedKeyType)
            throws InvalidKeyException, NoSuchAlgorithmException {
        if (opmode != Cipher.UNWRAP_MODE || keyBytes == null) {
            throw new IllegalStateException("Cipher must be init'd in WRAP_MODE");
        }
        try {
            final byte[] unwrappedKey = new byte[wrappedKey.length];
            int unwrappedKeyLen = unwrapKey(keyBytes, wrappedKey, unwrappedKey);
            final byte[] unwrappedKeyTruncated = new byte[unwrappedKeyLen];
            System.arraycopy(unwrappedKey, 0, unwrappedKeyTruncated, 0, unwrappedKeyLen);
            return Utils.buildUnwrappedKey(provider, unwrappedKeyTruncated, wrappedKeyAlgorithm, wrappedKeyType);
        // TODO [childw] make this exception more specific, perhaps BadPaddingException?
        } catch (final Exception ex) {
            throw new InvalidKeyException("Unwrapping failed", ex);
        }
    }

    @Override
    protected byte[] engineUpdate(byte[] in, int inOffset, int inLen) {
        throw new UnsupportedOperationException();
    }

    @Override
    protected int engineUpdate(byte[] in, int inOffset, int inLen,
            byte[] out, int outOffset) throws ShortBufferException {
        throw new UnsupportedOperationException();
    }

    @Override
    protected byte[] engineDoFinal(byte[] in, int inOfs, int inLen) {
        throw new UnsupportedOperationException();
    }

    protected int engineDoFinal(byte[] in, int inOfs, int inLen, byte[] out, int outOfs) {
        throw new UnsupportedOperationException();
    }
}
