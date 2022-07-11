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
 * This class is the impl class for AES KeyWrap algorithms as defined in
 * <a href=https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38F.pdf>
 * "Recommendation for Block Cipher Modes of Operation: Methods for Key Wrapping"
 */

final class AesKeyWrapSpi extends CipherSpi {
    private static final int BLOCK_SIZE = 128 / 8;

    static {
        Loader.load();
    }
    private final AmazonCorrettoCryptoProvider provider;
    private NativeResource context = null;
    private SecretKey jceKey;
    private byte[] iv, key;
    private int opmode = -1;    // must be set by init(..)

    AesKeyWrapSpi(final AmazonCorrettoCryptoProvider provider) {
        Loader.checkNativeLibraryAvailability();
        this.provider = provider;
    }


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
        return iv.clone();
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        try {
            AlgorithmParameters parameters = AlgorithmParameters.getInstance("IV");
            parameters.init(new IvParameterSpec(iv));
            return parameters;
        } catch (InvalidParameterSpecException | NoSuchAlgorithmException e) {
            throw new Error("Unexpected error", e);
        }
    }

    // actual impl for various engineInit(...) methods
    private void implInit(int opmode, Key key, byte[] iv, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        byte[] keyBytes = key.getEncoded();
        if (keyBytes == null) {
            throw new InvalidKeyException("Null key");
        }
        this.opmode = opmode;
        boolean decrypting = opmode == Cipher.UNWRAP_MODE;
        try {
            // TODO [childw]
            //cipher.init(decrypting, key.getAlgorithm(), keyBytes, iv);
            //dataBuf = null;
            //dataIdx = 0;
        } finally {
            Arrays.fill(keyBytes, (byte) 0);
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random)
        throws InvalidKeyException {
        try {
            implInit(opmode, key, (byte[])null, random);
        } catch (InvalidAlgorithmParameterException iae) {
            // should never happen
            throw new AssertionError(iae);
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params != null && !(params instanceof IvParameterSpec)) {
            throw new InvalidAlgorithmParameterException(
                "Only IvParameterSpec is accepted");
        }
        byte[] iv = (params == null? null : ((IvParameterSpec)params).getIV());
        implInit(opmode, key, iv, random);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
        throws InvalidKeyException, InvalidAlgorithmParameterException {
        byte[] iv = null;
        if (params != null) {
            try {
                AlgorithmParameterSpec spec =
                        params.getParameterSpec(IvParameterSpec.class);
                iv = ((IvParameterSpec)spec).getIV();
            } catch (InvalidParameterSpecException ispe) {
                throw new InvalidAlgorithmParameterException(
                    "Only IvParameterSpec is accepted");
            }
        }
        try {
            implInit(opmode, key, iv, random);
        } catch (IllegalArgumentException iae) {
            throw new InvalidAlgorithmParameterException(iae.getMessage());
        }
    }

    @Override
    protected byte[] engineWrap(final Key key) throws IllegalBlockSizeException, InvalidKeyException {
        if (opmode != Cipher.WRAP_MODE) {
            throw new IllegalStateException("Cipher must be in WRAP_MODE");
        }
        // TODO [childw] native call to wrap
        return null;
        //try {
            //final byte[] encoded = Utils.encodeForWrapping(provider, key);
            //return engineDoFinal(encoded, 0, encoded.length);
        //} catch (final BadPaddingException ex) {
            //throw new InvalidKeyException("Wrapping failed", ex);
        //}
    }

    @Override
    protected Key engineUnwrap(final byte[] wrappedKey, final String wrappedKeyAlgorithm, final int wrappedKeyType)
            throws InvalidKeyException, NoSuchAlgorithmException {
        if (opmode != Cipher.UNWRAP_MODE) {
            throw new IllegalStateException("Cipher must be in UNWRAP_MODE");
        }
        // TODO [childw] native call to unwrap
        return null;
        //try {
            //final byte[] unwrappedKey = engineDoFinal(wrappedKey, 0, wrappedKey.length);
            //return Utils.buildUnwrappedKey(provider, unwrappedKey, wrappedKeyAlgorithm, wrappedKeyType);
        //} catch (final BadPaddingException | IllegalBlockSizeException | InvalidKeySpecException ex) {
            //throw new InvalidKeyException("Unwrapping failed", ex);
        //}
    }

    //private static final class NativeContext extends NativeResource {
    //    private NativeContext(final long ptr) {
    //        super(ptr, AesKeyWrapSpi::releaseContext);
    //    }
    //}

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

//     @Override
//     protected void engineInit(final int opmode, final Key key, final SecureRandom secureRandom)
//             throws InvalidKeyException {
//         if (opmode != Cipher.ENCRYPT_MODE && opmode != Cipher.WRAP_MODE) {
//             throw new InvalidKeyException("IV required for decrypt");
//         }
// 
//         final byte[] iv = new byte[12];
//         secureRandom.nextBytes(iv);
// 
//         try {
//             engineInit(opmode, key, new GCMParameterSpec(DEFAULT_TAG_LENGTH, iv), secureRandom);
//         } catch (InvalidAlgorithmParameterException e) {
//             throw new AssertionError(e);
//         }
//     }
// 
//     @Override
//     protected void engineInit(
//         final int jceOpMode,
//         final Key key,
//         final AlgorithmParameterSpec algorithmParameterSpec,
//         final SecureRandom secureRandom
//     ) throws InvalidKeyException, InvalidAlgorithmParameterException {
//         if (key == null) {
//             throw new InvalidKeyException("Key can't be null");
//         }
// 
//         final GCMParameterSpec spec;
//         if (algorithmParameterSpec instanceof GCMParameterSpec) {
//             spec = (GCMParameterSpec) algorithmParameterSpec;
//         } else if (algorithmParameterSpec instanceof IvParameterSpec) {
//             spec = new GCMParameterSpec(DEFAULT_TAG_LENGTH,
//                     ((IvParameterSpec) algorithmParameterSpec).getIV());
//         } else {
//             throw new InvalidAlgorithmParameterException(
//                 "I don't know how to handle a " + algorithmParameterSpec.getClass());
//         }
// 
//         byte[] encodedKey = null;
//         if (jceKey != key) {
//             if (!(key instanceof  SecretKey)) {
//                 throw new InvalidKeyException("Need a SecretKey");
//             }
//             String keyAlgorithm = key.getAlgorithm();
//             if (!"RAW".equalsIgnoreCase(key.getFormat())) {
//                 throw new InvalidKeyException("Need a raw format key");
//             }
//             if (!keyAlgorithm.equalsIgnoreCase("AES")) {
//                 throw new InvalidKeyException("Expected an AES key");
//             }
//             encodedKey = key.getEncoded();
//             if (encodedKey == null) {
//                 throw new InvalidKeyException("Key doesn't support encoding");
//             }
// 
//             if (!MessageDigest.isEqual(encodedKey, this.key)) {
//                 if (encodedKey.length != 128 / 8 && encodedKey.length != 192 / 8 && encodedKey.length != 256 / 8) {
//                     throw new InvalidKeyException("Bad key length of " + (encodedKey.length * 8)
//                         + " bits; expected 128, 192, or 256 bits");
//                 }
// 
//                 keyUsageCount = 0;
//                 if (context != null) {
//                     context.release();
//                 }
// 
//                 context = null;
//             } else {
//                 encodedKey = null;
//             }
//         }
// 
//         final byte[] iv = spec.getIV();
// 
//         if ((spec.getTLen() % 8 != 0) || spec.getTLen() > 128 || spec.getTLen() < 96) {
//             throw new InvalidAlgorithmParameterException(
//                 "Unsupported TLen value; must be one of {128, 120, 112, 104, 96}");
//         }
// 
// 
//         if (this.iv != null && this.key != null
//                 && (jceOpMode == Cipher.ENCRYPT_MODE || jceOpMode == Cipher.WRAP_MODE)) {
//             if (Arrays.equals(this.iv, iv) && (encodedKey == null || MessageDigest.isEqual(this.key, encodedKey))) {
//                 throw new InvalidAlgorithmParameterException("Cannot reuse same iv and key for GCM encryption");
//             }
//         }
// 
//         if (iv == null || iv.length == 0) {
//             throw new InvalidAlgorithmParameterException("IV must be at least one byte long");
//         }
// 
//         switch (jceOpMode) {
//             case Cipher.ENCRYPT_MODE:
//             case Cipher.WRAP_MODE:
//                 this.opmode = NATIVE_MODE_ENCRYPT:
//             {
//                 checkOutputBuffer(length, output, outputOffset);
// 
//                 lazyInit();
// 
//                 // If we have an overlap, we'll need to clone the input buffer before we potentially start overwriting
//                 // it.
//                 final byte[] finalBytes;
//                 final int finalOffset;
//                 if (Utils.arraysOverlap(bytes, offset, output, outputOffset, engineGetOutputSize(length))) {
//                     finalBytes = Arrays.copyOfRange(bytes, offset, offset + length);
//                     finalOffset = 0;
//                 } else {
//                     finalBytes = bytes;
//                     finalOffset = offset;
//                 }
// 
//                 return context.use(ptr->encryptUpdate(ptr, finalBytes, finalOffset, length, output, outputOffset));
//             }
//             default:
//                 throw new IllegalStateException("Cipher not initialized");
//         }
//     }
