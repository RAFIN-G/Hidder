/*
 * Copyright (C) 2025 ModSeeker
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

// ============================================================================
// OpenSSL-based Cryptographic Vault for Hidder Mod
// Replaces Windows CNG with OpenSSL for Java compatibility
// ============================================================================

#include <jni.h>
#include <string>
#include <vector>
#include <cstring>
#include <fstream>
#include <sstream>
#include <iomanip>

// OpenSSL Headers
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/bn.h>

// Windows types for compatibility
typedef unsigned char BYTE;


// --- Base64 Utilities ---
static const std::string base64_chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

std::vector<BYTE> base64_decode(std::string const& encoded_string) {
    int in_len = encoded_string.size();
    int i = 0;
    int j = 0;
    int in_ = 0;
    BYTE char_array_4[4], char_array_3[3];
    std::vector<BYTE> ret;

    while (in_len-- && (encoded_string[in_] != '=') &&
           (isalnum(encoded_string[in_]) || (encoded_string[in_] == '+') || (encoded_string[in_] == '/'))) {
        char_array_4[i++] = encoded_string[in_];
        in_++;
        if (i == 4) {
            for (i = 0; i < 4; i++)
                char_array_4[i] = base64_chars.find(char_array_4[i]);

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; i < 3; i++)
                ret.push_back(char_array_3[i]);
            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 4; j++)
            char_array_4[j] = 0;

        for (j = 0; j < 4; j++)
            char_array_4[j] = base64_chars.find(char_array_4[j]);

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

        for (j = 0; j < i - 1; j++)
            ret.push_back(char_array_3[j]);
    }

    return ret;
}

std::string base64_encode(const BYTE* bytes_to_encode, unsigned int in_len) {
    std::string ret;
    int i = 0;
    int j = 0;
    BYTE char_array_3[3];
    BYTE char_array_4[4];

    while (in_len--) {
        char_array_3[i++] = *(bytes_to_encode++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; i < 4; i++)
                ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (j = 0; j < i + 1; j++)
            ret += base64_chars[char_array_4[j]];

        while (i++ < 3)
            ret += '=';
    }

    return ret;
}

// ============================================================================
// RSA KEY COMPONENTS
// ============================================================================

// --- CLIENT RSA Key Components (For Signing) ---
const std::string B64_MODULUS = "PLACEHOLDER";
const std::string B64_PUB_EXP = "PLACEHOLDER";
const std::string B64_PRIV_EXP = "PLACEHOLDER";
const std::string B64_PRIME1 = "PLACEHOLDER";
const std::string B64_PRIME2 = "PLACEHOLDER";
const std::string B64_EXP1 = "PLACEHOLDER";
const std::string B64_EXP2 = "PLACEHOLDER";
const std::string B64_COEFF = "PLACEHOLDER";

// --- SERVER RSA Key Components (For Encryption) ---
const std::string SRV_B64_MODULUS = "PLACEHOLDER";
const std::string SRV_B64_EXP = "PLACEHOLDER";

// ============================================================================
// OpenSSL Key Handles (Global)
// ============================================================================
EVP_PKEY* pClientKey = NULL;  // Client private key for signing
EVP_PKEY* pServerKey = NULL;  // Server public key for encryption

// ============================================================================
// Initialize Keys using OpenSSL
// ============================================================================
void InitializeKeys() {
    if (pClientKey != NULL && pServerKey != NULL) return;

    // --- Import Client Private Key (For Signing) ---
    if (pClientKey == NULL) {
        auto modBytes = base64_decode(B64_MODULUS);
        auto pubExpBytes = base64_decode(B64_PUB_EXP);
        auto privExpBytes = base64_decode(B64_PRIV_EXP);
        auto p1Bytes = base64_decode(B64_PRIME1);
        auto p2Bytes = base64_decode(B64_PRIME2);
        auto e1Bytes = base64_decode(B64_EXP1);
        auto e2Bytes = base64_decode(B64_EXP2);
        auto coeffBytes = base64_decode(B64_COEFF);

        // Strip leading zero if present (Java BigInteger sign byte)
        if (modBytes.size() == 257 && modBytes[0] == 0) modBytes.erase(modBytes.begin());
        if (privExpBytes.size() == 257 && privExpBytes[0] == 0) privExpBytes.erase(privExpBytes.begin());
        if (p1Bytes.size() == 129 && p1Bytes[0] == 0) p1Bytes.erase(p1Bytes.begin());
        if (p2Bytes.size() == 129 && p2Bytes[0] == 0) p2Bytes.erase(p2Bytes.begin());
        if (e1Bytes.size() == 129 && e1Bytes[0] == 0) e1Bytes.erase(e1Bytes.begin());
        if (e2Bytes.size() == 129 && e2Bytes[0] == 0) e2Bytes.erase(e2Bytes.begin());
        if (coeffBytes.size() == 129 && coeffBytes[0] == 0) coeffBytes.erase(coeffBytes.begin());

        // Create BIGNUM objects from byte arrays
        BIGNUM* n = BN_bin2bn(modBytes.data(), modBytes.size(), NULL);
        BIGNUM* e = BN_bin2bn(pubExpBytes.data(), pubExpBytes.size(), NULL);
        BIGNUM* d = BN_bin2bn(privExpBytes.data(), privExpBytes.size(), NULL);
        BIGNUM* p = BN_bin2bn(p1Bytes.data(), p1Bytes.size(), NULL);
        BIGNUM* q = BN_bin2bn(p2Bytes.data(), p2Bytes.size(), NULL);
        BIGNUM* dmp1 = BN_bin2bn(e1Bytes.data(), e1Bytes.size(), NULL);
        BIGNUM* dmq1 = BN_bin2bn(e2Bytes.data(), e2Bytes.size(), NULL);
        BIGNUM* iqmp = BN_bin2bn(coeffBytes.data(), coeffBytes.size(), NULL);

        // Create RSA key and set components
        RSA* rsa = RSA_new();
        RSA_set0_key(rsa, n, e, d);
        RSA_set0_factors(rsa, p, q);
        RSA_set0_crt_params(rsa, dmp1, dmq1, iqmp);

        // Create EVP_PKEY from RSA
        pClientKey = EVP_PKEY_new();
        EVP_PKEY_assign_RSA(pClientKey, rsa);
    }

    // --- Import Server Public Key (For Encryption) ---
    if (pServerKey == NULL) {
        auto modBytes = base64_decode(SRV_B64_MODULUS);
        auto expBytes = base64_decode(SRV_B64_EXP);

        // Strip leading zero if present
        if (modBytes.size() == 257 && modBytes[0] == 0) modBytes.erase(modBytes.begin());

        // Create BIGNUM objects
        BIGNUM* n = BN_bin2bn(modBytes.data(), modBytes.size(), NULL);
        BIGNUM* e = BN_bin2bn(expBytes.data(), expBytes.size(), NULL);

        // Create RSA key (public only)
        RSA* rsa = RSA_new();
        RSA_set0_key(rsa, n, e, NULL);  // NULL for private exponent (public key only)

        // Create EVP_PKEY from RSA
        pServerKey = EVP_PKEY_new();
        EVP_PKEY_assign_RSA(pServerKey, rsa);
    }
}

// ============================================================================
// JNI Exported Functions
// ============================================================================
extern "C" {

    // --- Sign Function ---
    JNIEXPORT jstring JNICALL Java_com_example_hidder_NativeBridge_sign(JNIEnv* env, jclass clazz, jstring data) {
        InitializeKeys();
        if (pClientKey == NULL) {
            return env->NewStringUTF("ERROR_KEY_INIT");
        }

        const char* dataChars = env->GetStringUTFChars(data, nullptr);
        std::string dataStr(dataChars);
        env->ReleaseStringUTFChars(data, dataChars);

        // Create signing context
        EVP_MD_CTX* mdCtx = EVP_MD_CTX_new();
        EVP_DigestSignInit(mdCtx, NULL, EVP_sha256(), NULL, pClientKey);
        EVP_DigestSignUpdate(mdCtx, dataStr.c_str(), dataStr.length());

        // Get signature length
        size_t sigLen = 0;
        EVP_DigestSignFinal(mdCtx, NULL, &sigLen);

        // Get signature
        std::vector<BYTE> signature(sigLen);
        EVP_DigestSignFinal(mdCtx, signature.data(), &sigLen);
        EVP_MD_CTX_free(mdCtx);

        std::string b64Sig = base64_encode(signature.data(), sigLen);
        return env->NewStringUTF(b64Sig.c_str());
    }

    // --- Encrypt Function ---
    JNIEXPORT jstring JNICALL Java_com_example_hidder_NativeBridge_encrypt(JNIEnv* env, jclass clazz, jstring data) {

        InitializeKeys();

        if (pServerKey == NULL) {

            return env->NewStringUTF("ERROR_SRV_KEY_INIT");
        }

        // 1. Generate AES Session Key (32 bytes for AES-256)
        BYTE aesKey[32];
        if (RAND_bytes(aesKey, 32) != 1) {

            return env->NewStringUTF("ERROR_RNG");
        }


        // 2. Encrypt AES Key with Server RSA Public Key (PKCS#1 v1.5 padding)
        EVP_PKEY_CTX* rsaCtx = EVP_PKEY_CTX_new(pServerKey, NULL);
        EVP_PKEY_encrypt_init(rsaCtx);
        EVP_PKEY_CTX_set_rsa_padding(rsaCtx, RSA_PKCS1_PADDING);

        // Get encrypted key length
        size_t encryptedKeyLen = 0;
        EVP_PKEY_encrypt(rsaCtx, NULL, &encryptedKeyLen, aesKey, 32);

        // Encrypt the AES key
        std::vector<BYTE> encryptedAesKey(encryptedKeyLen);
        if (EVP_PKEY_encrypt(rsaCtx, encryptedAesKey.data(), &encryptedKeyLen, aesKey, 32) <= 0) {

            EVP_PKEY_CTX_free(rsaCtx);
            return env->NewStringUTF("ERROR_RSA_ENCRYPT");
        }
        EVP_PKEY_CTX_free(rsaCtx);



        // 3. Get plaintext data from Java
        const char* dataChars = env->GetStringUTFChars(data, nullptr);
        std::string plainText(dataChars);
        env->ReleaseStringUTFChars(data, dataChars);



        // 4. Generate random IV (16 bytes for AES-CBC)
        BYTE iv[16];
        RAND_bytes(iv, 16);
        BYTE ivCopy[16];
        memcpy(ivCopy, iv, 16);  // Keep copy for output (encryption modifies IV)

        // 5. Encrypt data with AES-256-CBC using OpenSSL EVP
        EVP_CIPHER_CTX* aesCtx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(aesCtx, EVP_aes_256_cbc(), NULL, aesKey, iv);

        // EVP handles PKCS7 padding automatically
        int outLen = 0;
        int finalLen = 0;
        std::vector<BYTE> encryptedData(plainText.length() + EVP_MAX_BLOCK_LENGTH);

        EVP_EncryptUpdate(aesCtx, encryptedData.data(), &outLen,
                          (const unsigned char*)plainText.c_str(), plainText.length());
        int totalLen = outLen;

        EVP_EncryptFinal_ex(aesCtx, encryptedData.data() + outLen, &finalLen);
        totalLen += finalLen;

        EVP_CIPHER_CTX_free(aesCtx);

        // Resize to actual encrypted length
        encryptedData.resize(totalLen);

        // 6. Combine: [Encrypted AES Key B64] | [IV B64] | [Encrypted Data B64]
        std::string finalOutput = base64_encode(encryptedAesKey.data(), encryptedKeyLen) + "|" +
                                  base64_encode(ivCopy, 16) + "|" +
                                  base64_encode(encryptedData.data(), totalLen);

        return env->NewStringUTF(finalOutput.c_str());
    }
}
