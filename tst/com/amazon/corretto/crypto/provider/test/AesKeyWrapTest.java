package com.amazon.corretto.crypto.provider.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.Provider;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;
import java.util.zip.GZIPInputStream;

import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

@ExtendWith(TestResultLogger.class)
@Execution(ExecutionMode.CONCURRENT)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ)
public final class AesKeyWrapTest {
    // TODO [childw] any other aliases in BC or JCE that we need to check?
    private static final List<String> KWP_CIPHER_ALIASES = Arrays.asList(
            "AESWRAPPAD",
            "AES/KWP/NoPadding"
    );

    // TODO [childw] provide more descriptive names
    public static List<Arguments> sizes() {
        final int[] aesKeySizes = {16, 24, 32};
        final int[] secretSizes = {
            8,                          // https://datatracker.ietf.org/doc/html/rfc5649#section-4.1
            16, 24, 32,                 // AES keys
            512, 1024, 2048, 4096,      // RSA keys
            4, 123, 900, 81, 99, 37,    // weird sizes to exercise padding logic
        };
        List<Arguments> args = new ArrayList<>();
        for (int aesKeySize : aesKeySizes) {
            for (int secretSize : secretSizes) {
                args.add(Arguments.of(aesKeySize, secretSize > 0 ? secretSize-1 : secretSize));
                args.add(Arguments.of(aesKeySize, secretSize));
                args.add(Arguments.of(aesKeySize, secretSize+1));
            }
        }
        return args;
    }

    @ParameterizedTest
    @MethodSource("sizes")
    public void roundtripNativeSameCipher(int aesKeySize, int secretSize) throws Exception {
        roundtrip(aesKeySize, secretSize, TestUtil.NATIVE_PROVIDER, null, true);
    }

    @ParameterizedTest
    @MethodSource("sizes")
    public void roundtripNativeNewCipher(int aesKeySize, int secretSize) throws Exception {
        roundtrip(aesKeySize, secretSize, TestUtil.NATIVE_PROVIDER, TestUtil.NATIVE_PROVIDER, false);
    }

    @ParameterizedTest
    @MethodSource("sizes")
    public void roundtripNative2BC(int aesKeySize, int secretSize) throws Exception {
        roundtrip(aesKeySize, secretSize, TestUtil.NATIVE_PROVIDER, TestUtil.BC_PROVIDER, false);
    }

    @ParameterizedTest
    @MethodSource("sizes")
    public void roundtripBC2native(int aesKeySize, int secretSize) throws Exception {
        roundtrip(aesKeySize, secretSize, TestUtil.BC_PROVIDER, TestUtil.NATIVE_PROVIDER, false);
    }

    // TODO [childw] add new compatibility test cases for JCE providers that skip if < Java17
    // TODO [childw] add parameter for SecretKey type, parameterize that out across EC, RSA, etc.
    //               bonus points if we can auto-detect valid key sizes and filter the overarching
    //               secret key parameter sizes into these parameterized tests for particular key sizes.
    private void roundtrip(int aesKeySize, int secretSize, Provider wrappingProvider, Provider unwrappingProvider, boolean reuseCipher) throws Exception {
        final SecureRandom sr = new SecureRandom();
        byte[] keyBytes = new byte[aesKeySize];
        sr.nextBytes(keyBytes);
        final SecretKey key = new SecretKeySpec(keyBytes, "AES");

        byte[] secretBytes = new byte[secretSize];
        sr.nextBytes(secretBytes);
        final SecretKey secret = new SecretKeySpec(secretBytes, "Generic");

        Cipher c = getCipher(wrappingProvider);
        c.init(Cipher.WRAP_MODE, key, sr);
        byte[] wrapped = c.wrap(secret);
        assertFalse(Arrays.equals(secretBytes, wrapped));
        if (!reuseCipher) {
            c = getCipher(unwrappingProvider);
        } else {
            assertTrue(unwrappingProvider == null);
        }
        c.init(Cipher.UNWRAP_MODE, key, sr);
        Key unwrapped = c.unwrap(wrapped, "Generic", Cipher.SECRET_KEY);
        assertTrue(Arrays.equals(secret.getEncoded(), unwrapped.getEncoded()));
        assertEquals(secret, unwrapped);
    }

    // NOTE: this funciton is a convenience to make the test code cleaner
    //       across providers that use different aliases to provide the same
    //       Cipher. it relies on nativeProviderAliasTest to ensure that we
    //       provide ciphers across all expected aliases.
    private static Cipher getCipher(Provider provider) throws Exception {
        Exception lastEx = null;
        for (String alias : KWP_CIPHER_ALIASES) {
            try {
                if (provider != null) {
                    return Cipher.getInstance(alias, provider);
                } else {
                    return Cipher.getInstance(alias);
                }
            } catch (Exception e) { // TODO [childw] tighten this exception type up and in mthd signature
                lastEx = e;
            }
        }
        throw lastEx;
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
