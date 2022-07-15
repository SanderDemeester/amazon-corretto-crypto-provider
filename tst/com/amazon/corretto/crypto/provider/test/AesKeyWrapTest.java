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

    public static List<Arguments> sizes() {
        final int[] keySizes = {16, 24, 32};
        final int[] secretSizes = {
            8,                      // https://datatracker.ietf.org/doc/html/rfc5649#section-4.1
            16, 24, 32,             // AES keys
            512, 1024, 2048, 4096,  // RSA keys
            123, 900, 81, 99, 37,   // weird sizes to exercise padding logic
        };
        List<Arguments> args = new ArrayList<>();
        for (int keySize : keySizes) {
            for (int secretSize : secretSizes) {
                args.add(Arguments.of(keySize, secretSize));
            }
        }
        return args;
    }

    @ParameterizedTest
    @MethodSource("sizes")
    public void roundtrip(int keySize, int secretSize) throws Exception {
        final SecureRandom sr = new SecureRandom();
        byte[] keyBytes = new byte[keySize];
        sr.nextBytes(keyBytes);
        final SecretKey key = new SecretKeySpec(keyBytes, "AES");

        byte[] secretBytes = new byte[secretSize];
        sr.nextBytes(secretBytes);
        final SecretKey secret = new SecretKeySpec(secretBytes, "AES");

        Cipher c = Cipher.getInstance("AES/KWP/NoPadding", TestUtil.NATIVE_PROVIDER);
        c.init(Cipher.WRAP_MODE, key, sr);
        byte[] wrapped = c.wrap(secret);
        assertFalse(Arrays.equals(secretBytes, wrapped));
        c = Cipher.getInstance("AES/KWP/NoPadding", TestUtil.NATIVE_PROVIDER);
        c.init(Cipher.UNWRAP_MODE, key, sr);
        Key unwrapped = c.unwrap(wrapped, "AES", Cipher.SECRET_KEY);
        //System.out.println("KEY:    " + Arrays.toString(key.getEncoded()));
        //System.out.println("SECRET: " + Arrays.toString(secret.getEncoded()));
        //System.out.println("WRAPPD: " + Arrays.toString(wrapped));
        //System.out.println("UNWRAP: " + Arrays.toString(unwrapped.getEncoded()));
        assertTrue(Arrays.equals(secret.getEncoded(), unwrapped.getEncoded()));
        assertEquals(secret, unwrapped);
    }

}
