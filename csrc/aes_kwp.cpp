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

using namespace AmazonCorrettoCryptoProvider;

JNIEXPORT int JNICALL Java_com_amazon_corretto_crypto_provider_AesKeyWrapSpi_wrapKey(
  JNIEnv *pEnv,
  jclass,
  jlong keyPtr,
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

JNIEXPORT int JNICALL Java_com_amazon_corretto_crypto_provider_AesKeyWrapSpi_unwrapKey(
  JNIEnv *pEnv,
  jclass,
  jlong keyPtr,
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
