package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.assertArraysHexEquals;
import static com.amazon.corretto.crypto.provider.test.TestUtil.assertThrows;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

@ExtendWith(TestResultLogger.class)
@Execution(ExecutionMode.CONCURRENT)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ)
public final class AesKeyWrapTest {
    private static final List<String> KWP_CIPHER_ALIASES = Arrays.asList(
            "AESWRAPPAD",
            "AesWrapPad",
            "AES/KWP/NoPadding"
    );

    private static final List<Integer> AES_KEY_SIZES = Arrays.asList(16, 24, 32);

    public static List<Arguments> getParamsGeneric() {
        final int[] secretSizes = {
            8,                          // https://datatracker.ietf.org/doc/html/rfc5649#section-4.1
            16, 24, 32,                 // AES keys
            512, 1024, 2048, 4096,      // RSA keys
            4, 123, 900, 81, 99, 37,    // weird sizes to exercise padding logic
        };
        List<Arguments> args = new ArrayList<>();
        for (int wrappingKeySize : AES_KEY_SIZES) {
            for (int secretSize : secretSizes) {
                args.add(Arguments.of(wrappingKeySize, secretSize-1));
                args.add(Arguments.of(wrappingKeySize, secretSize));
                args.add(Arguments.of(wrappingKeySize, secretSize+1));
            }
        }
        return args;
    }

    private void roundtripGeneric(int wrappingKeySize, int secretSize, Provider wrappingProvider, Provider unwrappingProvider, boolean reuseCipher) throws Exception {
        final SecureRandom ignored = null;
        final SecretKey wrappingKey = getAesKey(wrappingKeySize);

        byte[] secretBytes = TestUtil.getRandomBytes(secretSize);
        final SecretKey secret = new SecretKeySpec(secretBytes, "Generic");

        Cipher c = getCipher(wrappingProvider);
        c.init(Cipher.WRAP_MODE, wrappingKey, ignored);
        byte[] wrappedKey = c.wrap(secret);
        assertFalse(Arrays.equals(secretBytes, wrappedKey));
        if (!reuseCipher) {
            c = getCipher(unwrappingProvider);
        } else {
            assertTrue(unwrappingProvider == null);
        }
        c.init(Cipher.UNWRAP_MODE, wrappingKey, ignored);
        final int mode;
        Key unwrappedKey = c.unwrap(wrappedKey, "Generic", Cipher.SECRET_KEY);
        assertArraysHexEquals(secret.getEncoded(), unwrappedKey.getEncoded());
        assertEquals(secret, unwrappedKey);
    }

    @ParameterizedTest
    @MethodSource("getParamsGeneric")
    public void roundtripNativeSameCipherGeneric(int wrappingKeySize, int secretSize) throws Exception {
        roundtripGeneric(wrappingKeySize, secretSize, TestUtil.NATIVE_PROVIDER, null, true);
    }

    @ParameterizedTest
    @MethodSource("getParamsGeneric")
    public void roundtripNativeNewCipherGeneric(int wrappingKeySize, int secretSize) throws Exception {
        roundtripGeneric(wrappingKeySize, secretSize, TestUtil.NATIVE_PROVIDER, TestUtil.NATIVE_PROVIDER, false);
    }

    @ParameterizedTest
    @MethodSource("getParamsGeneric")
    public void roundtripNative2BouncyGeneric(int wrappingKeySize, int secretSize) throws Exception {
        roundtripGeneric(wrappingKeySize, secretSize, TestUtil.NATIVE_PROVIDER, TestUtil.BC_PROVIDER, false);
    }

    @ParameterizedTest
    @MethodSource("getParamsGeneric")
    public void roundtripBouncy2nativeGeneric(int wrappingKeySize, int secretSize) throws Exception {
        roundtripGeneric(wrappingKeySize, secretSize, TestUtil.BC_PROVIDER, TestUtil.NATIVE_PROVIDER, false);
    }

    @ParameterizedTest
    @MethodSource("getParamsGeneric")
    public void roundtripNative2JCEGeneric(int wrappingKeySize, int secretSize) throws Exception {
        TestUtil.assumeMinimumJavaVersion(17);  // KWP added to JCE in 17 https://bugs.openjdk.org/browse/JDK-8248268
        roundtripGeneric(wrappingKeySize, secretSize, TestUtil.NATIVE_PROVIDER, null, false);
    }

    @ParameterizedTest
    @MethodSource("getParamsGeneric")
    public void roundtripJCE2nativeGeneric(int wrappingKeySize, int secretSize) throws Exception {
        TestUtil.assumeMinimumJavaVersion(17);  // KWP added to JCE in 17 https://bugs.openjdk.org/browse/JDK-8248268
        roundtripGeneric(wrappingKeySize, secretSize, null, TestUtil.NATIVE_PROVIDER, false);
    }

    public static List<Arguments> getParamsAsymmetric() throws GeneralSecurityException {
        final String[] ecCurveNames = {"secp224r1", "secp256r1", "secp384r1", "secp521r1"};
        final int[] rsaKeySizes = {512, 1024, 2048, 4096};
        List<Arguments> args = new ArrayList<>();
        KeyPairGenerator kpg;
        for (int wrappingKeySize : AES_KEY_SIZES) {
            kpg = KeyPairGenerator.getInstance("EC", TestUtil.NATIVE_PROVIDER);
            for (String curve : ecCurveNames) {
                kpg.initialize(new ECGenParameterSpec(curve));
                String display = String.format("EC(%s)", curve);
                args.add(Arguments.of(wrappingKeySize, kpg.generateKeyPair(), display));
            }
            kpg = KeyPairGenerator.getInstance("RSA", TestUtil.NATIVE_PROVIDER);
            for (int bits : rsaKeySizes) {
                kpg.initialize(bits);
                String display = String.format("RSA(%d)", bits);
                args.add(Arguments.of(wrappingKeySize, kpg.generateKeyPair(), display));
            }
        }
        return args;
    }

    private void roundtripAsymmetric(int wrappingKeySize, KeyPair keyPair, Provider wrappingProvider, Provider unwrappingProvider, boolean reuseCipher) throws Exception {
        final SecureRandom ignored = null;
        final SecretKey wrappingKey = getAesKey(wrappingKeySize);

        Cipher c = getCipher(wrappingProvider);
        c.init(Cipher.WRAP_MODE, wrappingKey);
        byte[] wrappedPublicKey = c.wrap(keyPair.getPublic());
        byte[] wrappedPrivateKey = c.wrap(keyPair.getPrivate());
        assertFalse(Arrays.equals(keyPair.getPublic().getEncoded(), wrappedPublicKey));
        assertFalse(Arrays.equals(keyPair.getPrivate().getEncoded(), wrappedPrivateKey));
        if (!reuseCipher) {
            c = getCipher(unwrappingProvider);
        } else {
            assertTrue(unwrappingProvider == null);
        }
        c.init(Cipher.UNWRAP_MODE, wrappingKey);
        Key unwrappedPublicKey = c.unwrap(wrappedPublicKey, keyPair.getPublic().getAlgorithm(), Cipher.PUBLIC_KEY);
        Key unwrappedPrivateKey = c.unwrap(wrappedPrivateKey, keyPair.getPrivate().getAlgorithm(), Cipher.PRIVATE_KEY);
        assertArraysHexEquals(keyPair.getPublic().getEncoded(), unwrappedPublicKey.getEncoded());
        assertArraysHexEquals(keyPair.getPrivate().getEncoded(), unwrappedPrivateKey.getEncoded());
        assertEquals(keyPair.getPublic(), unwrappedPublicKey);
        assertEquals(keyPair.getPrivate(), unwrappedPrivateKey);

        // By passing it through the factory we ensure that it is an understandable type
        final KeyFactory kf = KeyFactory.getInstance(keyPair.getPublic().getAlgorithm(), TestUtil.NATIVE_PROVIDER);
        assertArraysHexEquals(
            kf.getKeySpec(keyPair.getPrivate(), PKCS8EncodedKeySpec.class).getEncoded(),
            kf.getKeySpec(unwrappedPrivateKey, PKCS8EncodedKeySpec.class).getEncoded()
        );
        assertArraysHexEquals(
            kf.getKeySpec(keyPair.getPublic(), X509EncodedKeySpec.class).getEncoded(),
            kf.getKeySpec(unwrappedPublicKey, X509EncodedKeySpec.class).getEncoded()
        );
    }

    @ParameterizedTest
    @MethodSource("getParamsAsymmetric")
    public void roundtripNativeSameCipherAsymmetric(int wrappingKeySize, KeyPair keyPair, String display) throws Exception {
        roundtripAsymmetric(wrappingKeySize, keyPair, TestUtil.NATIVE_PROVIDER, null, true);
    }

    @ParameterizedTest
    @MethodSource("getParamsAsymmetric")
    public void roundtripNativeNewCipherAsymmetric(int wrappingKeySize, KeyPair keyPair, String display) throws Exception {
        roundtripAsymmetric(wrappingKeySize, keyPair, TestUtil.NATIVE_PROVIDER, TestUtil.NATIVE_PROVIDER, false);
    }

    @ParameterizedTest
    @MethodSource("getParamsAsymmetric")
    public void roundtripNative2BouncyAsymmetric(int wrappingKeySize, KeyPair keyPair, String display) throws Exception {
        // NOTE: BC is unwrapping EC private keys differently from ACCP and
        //       JCE, then remove this assumption from the parameterized test.
        //       in the meantime, we have a temporary test below showing that
        //       while the unwrapping with BC an ACCP-wrapped EC key does not
        //       produce a byte-for-byte replica of the original, it's still
        //       possible to use both keys for signing.
        org.junit.jupiter.api.Assumptions.assumeTrue(!display.startsWith("EC("));
        roundtripAsymmetric(wrappingKeySize, keyPair, TestUtil.NATIVE_PROVIDER, TestUtil.BC_PROVIDER, false);
    }

    @Test
    public void testNative2BouncyECPrivateKeySignaturesOK() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", TestUtil.NATIVE_PROVIDER);
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keyPair = kpg.generateKeyPair();
        final SecretKey wrappingKey = getAesKey(128/8);

        Cipher wrapper = Cipher.getInstance("AESWRAPPAD", TestUtil.NATIVE_PROVIDER);
        wrapper.init(Cipher.WRAP_MODE, wrappingKey);
        byte[] wrappedPrivateKey = wrapper.wrap(keyPair.getPrivate());
        wrapper = Cipher.getInstance("AESWRAPPAD", TestUtil.BC_PROVIDER);
        wrapper.init(Cipher.WRAP_MODE, wrappingKey);
        wrapper.init(Cipher.UNWRAP_MODE, wrappingKey);
        Key unwrappedPrivateKey = wrapper.unwrap(wrappedPrivateKey, "EC", Cipher.PRIVATE_KEY);

        Signature signer = Signature.getInstance("SHA256withECDSA", TestUtil.NATIVE_PROVIDER);
        final byte[] message = TestUtil.getRandomBytes(1024);
        signer.initSign(keyPair.getPrivate());
        signer.update(message);
        final byte[] goodSignature = signer.sign();
        signer.initSign((PrivateKey) unwrappedPrivateKey);
        signer.update(message);
        final byte[] unwrappedKeySignature = signer.sign();
        assertFalse(Arrays.equals(keyPair.getPrivate().getEncoded(), unwrappedPrivateKey.getEncoded()));
        assertFalse(Arrays.equals(goodSignature, unwrappedKeySignature));

        Signature verifier = Signature.getInstance("SHA256withECDSA", TestUtil.NATIVE_PROVIDER);
        verifier.initVerify(keyPair.getPublic());
        verifier.update(message);
        assertTrue(verifier.verify(goodSignature));
        verifier.initVerify(keyPair.getPublic());
        verifier.update(message);
        assertTrue(verifier.verify(unwrappedKeySignature));
    }

    @ParameterizedTest
    @MethodSource("getParamsAsymmetric")
    public void roundtripBouncy2nativeAsymmetric(int wrappingKeySize, KeyPair keyPair, String display) throws Exception {
        roundtripAsymmetric(wrappingKeySize, keyPair, TestUtil.BC_PROVIDER, TestUtil.NATIVE_PROVIDER, false);
    }

    @ParameterizedTest
    @MethodSource("getParamsAsymmetric")
    public void roundtripNative2JCEAsymmetric(int wrappingKeySize, KeyPair keyPair, String display) throws Exception {
        TestUtil.assumeMinimumJavaVersion(17);  // KWP added to JCE in 17 https://bugs.openjdk.org/browse/JDK-8248268
        roundtripAsymmetric(wrappingKeySize, keyPair, TestUtil.NATIVE_PROVIDER, null, false);
    }

    @ParameterizedTest
    @MethodSource("getParamsAsymmetric")
    public void roundtripJCE2nativeAsymmetric(int wrappingKeySize, KeyPair keyPair, String display) throws Exception {
        TestUtil.assumeMinimumJavaVersion(17);  // KWP added to JCE in 17 https://bugs.openjdk.org/browse/JDK-8248268
        roundtripAsymmetric(wrappingKeySize, keyPair, null, TestUtil.NATIVE_PROVIDER, false);
    }

    public static List<Arguments> getParamsIncremental() {
        final int[] stepSizes = new int[] { 1, 7, 9, 16, 17, 32 };
        final int[] doFinalSizes = new int[] { 0, 1, 7, 9, 16, 17, 32 };
        final List<Arguments> args = new ArrayList<>();
        for (Arguments other : getParamsGeneric()) {
            for (int stepSize : stepSizes) {
                for (int doFinalSize : doFinalSizes) {
                    args.add(Arguments.of(other.get()[0], other.get()[1], stepSize, doFinalSize));
                }
            }
        }
        return args;
    }

    private void roundtripIncremental(int wrappingKeySize, int secretSize, int stepSize,
            int doFinalSize) throws Exception {
        final SecretKey wrappingKey = getAesKey(wrappingKeySize);
        final byte[] secret = TestUtil.getRandomBytes(secretSize);

        Cipher c = getCipher(TestUtil.NATIVE_PROVIDER);
        c.init(Cipher.ENCRYPT_MODE, wrappingKey);
        int updateLimit = secret.length - doFinalSize;
        // if doFinalSize is greater than the data we're working with, then
        // don't add any more data in the doFinal call.
        if (updateLimit < 0) {
            updateLimit = secret.length;
        }
        for (int ii = 0; ii < updateLimit; ii += stepSize) {
            byte[] chunk = Arrays.copyOfRange(secret, ii, Math.min(ii+stepSize, updateLimit));
            c.update(chunk);
        }
        byte[] ciphertext = c.doFinal(Arrays.copyOfRange(secret, updateLimit, secret.length));
        assertFalse(Arrays.equals(secret, ciphertext));
        c.init(Cipher.DECRYPT_MODE, wrappingKey);
        updateLimit = ciphertext.length - doFinalSize;
        // if doFinalSize is greater than the data we're working with, then
        // don't add any more data in the doFinal call.
        if (updateLimit < 0) {
            updateLimit = ciphertext.length;
        }
        for (int ii = 0; ii < updateLimit; ii += stepSize) {
            byte[] chunk = Arrays.copyOfRange(ciphertext, ii, Math.min(ii+stepSize, updateLimit));
            c.update(chunk);
        }
        byte[] plaintext = c.doFinal(Arrays.copyOfRange(ciphertext, updateLimit, ciphertext.length));
        assertArraysHexEquals(secret, plaintext);
    }

    @ParameterizedTest
    @MethodSource("getParamsIncremental")
    public void roundtripNativeSameCipherIncremental(int wrappingKeySize, int secretSize, int stepSize,
            int doFinalSize) throws Exception {
        roundtripIncremental(wrappingKeySize, secretSize, stepSize, doFinalSize);
    }

    @Test
    public void nativeProviderAliasTest() throws Exception {
        // this test asserts that all expected aliases for the AES KWP cipher
        // are adequatly supplied by the native provider
        for (String alias : KWP_CIPHER_ALIASES) {
            Cipher.getInstance(alias, TestUtil.NATIVE_PROVIDER);
        }
    }

    @Test
    public void testEngineGetOtputSize() throws Exception {
        final int[] inputSizes = new int[] { 1, 5, 9, 16, 31, 32 };
        Cipher c = getCipher(TestUtil.NATIVE_PROVIDER);
        final SecretKey kek = getAesKey(128/8);
        c.init(Cipher.ENCRYPT_MODE, kek);
        // first pass, no buffered data
        for (int inputSize : inputSizes) {
            assertTrue(c.getOutputSize(inputSize) % 8 == 0);
            assertTrue(c.getOutputSize(inputSize) >= inputSize + 8);
        }
        // second pass, buffer data
        int bytesBuffered = 0;
        for (int inputSize : inputSizes) {
            c.update(new byte[inputSize]);
            bytesBuffered += inputSize;
            assertTrue(c.getOutputSize(0) >= bytesBuffered + 8);
        }
        int finalOutputSize = c.getOutputSize(0);
        byte[] ciphertext = c.doFinal();
        assertEquals(ciphertext.length, finalOutputSize);

        c.init(Cipher.DECRYPT_MODE, kek);
        // first pass, no buffered data
        for (int inputSize : inputSizes) {
            assertTrue(c.getOutputSize(inputSize) == Math.max(inputSize - 8, 8));
        }
        // second pass, buffer data
        for (int inputSize : inputSizes) {
            c.update(new byte[inputSize]);
        }
        // reset and update w/ ciphertext otherwise decrypt will fail.
        c.init(Cipher.DECRYPT_MODE, kek);
        c.update(ciphertext);
        finalOutputSize = c.getOutputSize(0);
        assertTrue(c.doFinal().length <= finalOutputSize);
    }

    @Test
    public void testBadInputs() {
        // TODO [childw]
        // setMode
        // setPadding
        // getKeySize
        // getOutputSize
        // init
        // update
        // doFinal
        // wrap
        // unwrap
    }

    // NOTE: this funciton is a convenience to make the test code cleaner
    //       across providers that use different aliases to provide the same
    //       Cipher. it relies on nativeProviderAliasTest to ensure that we
    //       provide ciphers across all expected aliases.
    private static Cipher getCipher(Provider provider) throws GeneralSecurityException {
        GeneralSecurityException lastEx = null;
        for (String alias : KWP_CIPHER_ALIASES) {
            try {
                if (provider != null) {
                    return Cipher.getInstance(alias, provider);
                } else {
                    return Cipher.getInstance(alias);
                }
            } catch (GeneralSecurityException e) {
                lastEx = e;
            }
        }
        throw lastEx;
    }

    private static SecretKey getAesKey(int size) {
        return new SecretKeySpec(TestUtil.getRandomBytes(size), "AES");
    }
}
