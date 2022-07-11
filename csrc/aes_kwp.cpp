// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <cstdio>
#include <cassert>
#include <algorithm> // for std::min
#include <openssl/evp.h>
#include <openssl/err.h>
#include "generated-headers.h"
#include "util.h"
#include "env.h"
#include "buffer.h"
#include "keyutils.h"

#define NATIVE_MODE_ENCRYPT 1
#define NATIVE_MODE_DECRYPT 0

#define EX_BADTAG "javax/crypto/AEADBadTagException"
#define EX_SHORTBUF "javax/crypto/ShortBufferException"

// Number of bytes to process each time we lock the input/output byte arrays
#define CHUNK_SIZE (256 * 1024)

#define MAX_KEY_SIZE 32

#define KEY_LEN_AES128 16
#define KEY_LEN_AES192 24
#define KEY_LEN_AES256 32

using namespace AmazonCorrettoCryptoProvider;

static void initContext(
  raii_env &env,
  raii_cipher_ctx &ctx,
  jint opMode,
  java_buffer key,
  java_buffer iv
) {
    const EVP_CIPHER *cipher;

    switch (key.len()) {
        case KEY_LEN_AES128: cipher = EVP_aes_128_kwp(); break;
        case KEY_LEN_AES192: cipher = EVP_aes_192_kwp(); break;
        case KEY_LEN_AES256: cipher = EVP_aes_256_kwp(); break;
        default: throw java_ex(EX_RUNTIME_CRYPTO, "Unsupported key length");
    }

    // We use a SecureBuffer on the stack rather than a borrow to minimize the number
    // of times we need to cross the JNI boundary (we only need to cross once this way)
    SecureBuffer<uint8_t, KEY_LEN_AES256> keybuf;
    key.get_bytes(env, keybuf.buf, 0, key.len());

    if (unlikely(!EVP_CipherInit_ex(ctx, cipher, NULL, NULL, NULL, opMode))) {
        throw java_ex::from_openssl(EX_RUNTIME_CRYPTO, "Initializing cipher failed");
    }

    if (unlikely(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_kwp_SET_IVLEN, iv.len(), NULL))) {
        throw java_ex::from_openssl(EX_RUNTIME_CRYPTO, "Setting IV length failed");
    }

    jni_borrow ivBorrow(env, iv, "iv");

    if (unlikely(!EVP_CipherInit_ex(ctx, NULL, NULL, keybuf, ivBorrow.data(), opMode))) {
        throw java_ex::from_openssl(EX_RUNTIME_CRYPTO, "Final cipher init failed");
    }
}

JNIEXPORT int JNICALL Java_com_amazon_corretto_crypto_provider_AesKeyWrapSpi_wrapKey(
  JNIEnv *pEnv,
  jclass,
  jlong ctxPtr,
  jlongArray ctxOut,
  jbyteArray inputArray,
  jint inoffset,
  jint inlen,
  jbyteArray resultArray,
  jint resultOffset,
  jint tagLen,
  jbyteArray keyArray,
  jbyteArray ivArray
)
{
    try {
        raii_env env(pEnv);

        java_buffer input = java_buffer::from_array(env, inputArray, inoffset, inlen);
        java_buffer result = java_buffer::from_array(env, resultArray, resultOffset);
        java_buffer iv = java_buffer::from_array(env, ivArray);

        raii_cipher_ctx ctx;
        if (ctxPtr) {
            ctx.borrow(reinterpret_cast<EVP_CIPHER_CTX*>(ctxPtr));

            jni_borrow ivBorrow(env, iv, "iv");
            if (unlikely(!EVP_CipherInit_ex(ctx, NULL, NULL, NULL, ivBorrow.data(), NATIVE_MODE_ENCRYPT))) {
                throw java_ex::from_openssl(EX_RUNTIME_CRYPTO, "Failed to set IV");
            }
        } else {
            ctx.init();
            EVP_CIPHER_CTX_init(ctx);
            java_buffer key = java_buffer::from_array(env, keyArray);
            initContext(env, ctx, NATIVE_MODE_ENCRYPT, key, iv);
        }

        int outoffset = updateLoop(env, result, input, ctx);
        if (outoffset < 0) return 0;

        result = result.subrange(outoffset);
        int finalOffset = cryptFinish(env, NATIVE_MODE_ENCRYPT, result, tagLen, ctx);

        if (!ctxPtr && ctxOut) {
            // Context is new, but caller does want it back
            jlong tmpPtr = reinterpret_cast<jlong>(ctx.take());
            env->SetLongArrayRegion(ctxOut, 0 /* start position */, 1 /* number of elements */, &tmpPtr);
        }

        return finalOffset + outoffset;
    } catch (java_ex &ex) {
        ex.throw_to_java(pEnv);
        return -1;
    }
}
