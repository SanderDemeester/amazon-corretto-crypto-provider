package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.assertArraysHexEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.SecureRandom;
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
    public void roundtripNative2BCGeneric(int wrappingKeySize, int secretSize) throws Exception {
        roundtripGeneric(wrappingKeySize, secretSize, TestUtil.NATIVE_PROVIDER, TestUtil.BC_PROVIDER, false);
    }

    @ParameterizedTest
    @MethodSource("getParamsGeneric")
    public void roundtripBC2nativeGeneric(int wrappingKeySize, int secretSize) throws Exception {
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
    public void roundtripNative2BCAsymmetric(int wrappingKeySize, KeyPair keyPair, String display) throws Exception {
        // TODO [childw] get to the bottom of why BC is unwrapping EC private keys differently from ACCP and JCE.
        org.junit.jupiter.api.Assumptions.assumeTrue(!display.startsWith("EC("));
        roundtripAsymmetric(wrappingKeySize, keyPair, TestUtil.NATIVE_PROVIDER, TestUtil.BC_PROVIDER, false);
    }

    @ParameterizedTest
    @MethodSource("getParamsAsymmetric")
    public void roundtripBC2nativeAsymmetric(int wrappingKeySize, KeyPair keyPair, String display) throws Exception {
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

    @Test
    public void nativeProviderAliasTest() throws Exception {
        // this test asserts that all expected aliases for the AES KWP cipher
        // are adequatly supplied by the native provider
        for (String alias : KWP_CIPHER_ALIASES) {
            Cipher.getInstance(alias, TestUtil.NATIVE_PROVIDER);
        }
    }
}
