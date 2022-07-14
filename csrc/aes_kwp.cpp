// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <cstdio>
#include <cassert>
#include <algorithm> // for std::min
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "generated-headers.h"
#include "util.h"
#include "env.h"
#include "buffer.h"
#include "keyutils.h"

using namespace AmazonCorrettoCryptoProvider;

JNIEXPORT int JNICALL Java_com_amazon_corretto_crypto_provider_AesKeyWrapSpi_wrapKey(
  JNIEnv *pEnv,
  jclass,
  jbyteArray keyArray,
  jbyteArray inputArray,
  jbyteArray outputArray
)
{
    try {
        raii_env env(pEnv);

        java_buffer key = java_buffer::from_array(env, keyArray);
        java_buffer input = java_buffer::from_array(env, inputArray);
        java_buffer output = java_buffer::from_array(env, outputArray);

        AES_KEY aes_key;
        SecureBuffer<uint8_t, 32> keybuf;
        input.get_bytes(env, keybuf.buf, 0, key.len());
        if (AES_set_encrypt_key(keybuf.buf, key.len()*8, &aes_key) != 0) {
            throw java_ex::from_openssl(EX_RUNTIME_CRYPTO, "AES key init failed");
        }


        // TODO [childw] smaller more precise size
        // TODO [childw] try to eliminate extra copies.
        SecureBuffer<uint8_t, 4096> inbuf;
        input.get_bytes(env, inbuf.buf, 0, input.len());
        SecureBuffer<uint8_t, 4096> outbuf;
        size_t outlen;
        AES_wrap_key_padded(&aes_key, outbuf.buf, &outlen, sizeof(outbuf.buf),
                inbuf.buf, input.len());
        output.put_bytes(env, outbuf.buf, 0, outlen);

        return 1;
    } catch (java_ex &ex) {
        ex.throw_to_java(pEnv);
        return 0;
    }
}

JNIEXPORT int JNICALL Java_com_amazon_corretto_crypto_provider_AesKeyWrapSpi_unwrapKey(
  JNIEnv *pEnv,
  jclass,
  jbyteArray key,
  jbyteArray inputArray,
  jbyteArray outputArray
)
{
    try {
        raii_env env(pEnv);

        //java_buffer input = java_buffer::from_array(env, inputArray);
        //java_buffer output = java_buffer::from_array(env, outputArray);

        return 1;
    } catch (java_ex &ex) {
        ex.throw_to_java(pEnv);
        return 0;
    }
}
