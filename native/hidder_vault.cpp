// SPDX-FileCopyrightText: 2025 ModSeeker
// SPDX-License-Identifier: AGPL-3.0-or-later

#include <jni.h>
#include <jvmti.h>
#include <string>
#include <vector>
#include <cstring>
#include <cstdint>
#include <cwctype>
#include <fstream>
#include <sstream>
#include <iomanip>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/hmac.h>
#include <openssl/x509.h>
#include <openssl/crypto.h>


#include <windows.h>
#include <tlhelp32.h>
#include <algorithm>
#include <cctype>
#include <map>
#include <set>
#include <setjmp.h>
#include <mutex>
#include <array>
#include <atomic>
#include <chrono>
#include <initializer_list>
#include <utility>
#include "metadata_json.h"
#include "loader_profile_policy.h"
#include "class_fingerprints.generated.inc"
#include "client_report_key.generated.inc"

#ifdef HIDDER_INPUT_VALIDATION
static std::atomic<const LoaderIntegrityProfile*> activeLoaderProfile{&EXPECTED_LOADER_PROFILES[0]};
#else
static std::atomic<const LoaderIntegrityProfile*> activeLoaderProfile{nullptr};
#endif

typedef unsigned char BYTE;


static const std::string base64_chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

std::vector<BYTE> base64_decode(std::string const& encoded_string) {
    size_t len = encoded_string.size();
    if (len == 0 || len % 4 != 0) return {};
    std::vector<BYTE> ret;
    ret.reserve(len / 4 * 3);
    for (size_t pos = 0; pos < len; pos += 4) {
        int quad[4];
        bool pad[4] = { false, false, false, false };
        for (int k = 0; k < 4; k++) {
            char c = encoded_string[pos + k];
            if (c == '=') {
                if (pos + 4 != len || k < 2) return {};
                pad[k] = true;
                quad[k] = 0;
            } else {
                size_t idx = base64_chars.find(c);
                if (idx == std::string::npos) return {};
                quad[k] = (int)idx;
            }
        }
        if (pad[2] && !pad[3]) return {};
        ret.push_back((BYTE)((quad[0] << 2) | (quad[1] >> 4)));
        if (!pad[2]) ret.push_back((BYTE)((quad[1] << 4) | (quad[2] >> 2)));
        if (!pad[3]) ret.push_back((BYTE)((quad[2] << 6) | quad[3]));
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


#if __has_include("client_keys.generated.inc")
#include "client_keys.generated.inc"
#else
#error Run BuildCustomPair.ps1 -InitializeKeysOnly before compiling Hidder
#endif
EVP_PKEY* pClientKey = NULL;

static const unsigned char OBF_KEY[16] = {
    0x3D, 0x91, 0x27, 0x6C, 0xB4, 0x0A, 0xF2, 0x58,
    0x1E, 0x83, 0x4F, 0xD6, 0x7A, 0x2B, 0xC9, 0x60
};

static std::string deobfB64(const unsigned char* data, size_t len) {
    std::string out;
    out.resize(len);
    for (size_t i = 0; i < len; i++) out[i] = (char)(data[i] ^ OBF_KEY[i % 16]);
    return out;
}

static bool clientKeyMatchesExpectedIdentity(EVP_PKEY* key) {
    if (key == nullptr) return false;
    int derLength = i2d_PUBKEY(key, nullptr);
    if (derLength <= 0 || derLength > 8192) return false;
    std::vector<unsigned char> der((size_t)derLength);
    unsigned char* cursor = der.data();
    if (i2d_PUBKEY(key, &cursor) != derLength) return false;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digestLength = 0;
    if (EVP_Digest(der.data(), der.size(), digest, &digestLength, EVP_sha256(), nullptr) != 1
            || digestLength != 32) return false;
    static const char hex[] = "0123456789abcdef";
    std::string identity = "MODSEEKER_REPORT_KEY_SHA256=";
    identity.reserve(identity.size() + 64);
    for (unsigned int index = 0; index < digestLength; index++) {
        identity.push_back(hex[digest[index] >> 4]);
        identity.push_back(hex[digest[index] & 0x0f]);
    }
    return identity == EXPECTED_CLIENT_REPORT_KEY_IDENTITY;
}

void InitializeKeys() {
    static std::mutex keyInitMutex;
    std::lock_guard<std::mutex> lock(keyInitMutex);
    if (pClientKey != NULL) return;

    if (pClientKey == NULL) {
        auto modBytes = base64_decode(deobfB64(B64_MODULUS_ENC, sizeof(B64_MODULUS_ENC)));
        auto pubExpBytes = base64_decode(deobfB64(B64_PUB_EXP_ENC, sizeof(B64_PUB_EXP_ENC)));
        auto privExpBytes = base64_decode(deobfB64(B64_PRIV_EXP_ENC, sizeof(B64_PRIV_EXP_ENC)));
        auto p1Bytes = base64_decode(deobfB64(B64_PRIME1_ENC, sizeof(B64_PRIME1_ENC)));
        auto p2Bytes = base64_decode(deobfB64(B64_PRIME2_ENC, sizeof(B64_PRIME2_ENC)));
        auto e1Bytes = base64_decode(deobfB64(B64_EXP1_ENC, sizeof(B64_EXP1_ENC)));
        auto e2Bytes = base64_decode(deobfB64(B64_EXP2_ENC, sizeof(B64_EXP2_ENC)));
        auto coeffBytes = base64_decode(deobfB64(B64_COEFF_ENC, sizeof(B64_COEFF_ENC)));
        auto cleanseParts = [&]() {
            for (std::vector<unsigned char>* value : std::initializer_list<std::vector<unsigned char>*>{
                    &modBytes, &pubExpBytes, &privExpBytes, &p1Bytes, &p2Bytes, &e1Bytes, &e2Bytes, &coeffBytes}) {
                if (!value->empty()) OPENSSL_cleanse(value->data(), value->size());
                value->clear();
            }
        };

        auto trimLeadingZero = [](std::vector<unsigned char>& value, size_t encodedSize) {
            if (value.size() != encodedSize || value[0] != 0) return;
            std::vector<unsigned char> trimmed(value.begin() + 1, value.end());
            OPENSSL_cleanse(value.data(), value.size());
            value.swap(trimmed);
        };
        trimLeadingZero(modBytes, 257);
        trimLeadingZero(privExpBytes, 257);
        trimLeadingZero(p1Bytes, 129);
        trimLeadingZero(p2Bytes, 129);
        trimLeadingZero(e1Bytes, 129);
        trimLeadingZero(e2Bytes, 129);
        trimLeadingZero(coeffBytes, 129);

        BIGNUM* n = BN_bin2bn(modBytes.data(), modBytes.size(), NULL);
        BIGNUM* e = BN_bin2bn(pubExpBytes.data(), pubExpBytes.size(), NULL);
        BIGNUM* d = BN_bin2bn(privExpBytes.data(), privExpBytes.size(), NULL);
        BIGNUM* p = BN_bin2bn(p1Bytes.data(), p1Bytes.size(), NULL);
        BIGNUM* q = BN_bin2bn(p2Bytes.data(), p2Bytes.size(), NULL);
        BIGNUM* dmp1 = BN_bin2bn(e1Bytes.data(), e1Bytes.size(), NULL);
        BIGNUM* dmq1 = BN_bin2bn(e2Bytes.data(), e2Bytes.size(), NULL);
        BIGNUM* iqmp = BN_bin2bn(coeffBytes.data(), coeffBytes.size(), NULL);

        RSA* rsa = RSA_new();
        auto freeParts = [&]() {
            BN_clear_free(n);
            BN_clear_free(e);
            BN_clear_free(d);
            BN_clear_free(p);
            BN_clear_free(q);
            BN_clear_free(dmp1);
            BN_clear_free(dmq1);
            BN_clear_free(iqmp);
        };
        if (rsa == nullptr || n == nullptr || e == nullptr || d == nullptr || p == nullptr || q == nullptr
                || dmp1 == nullptr || dmq1 == nullptr || iqmp == nullptr) {
            freeParts();
            RSA_free(rsa);
            cleanseParts();
            return;
        }
        if (RSA_set0_key(rsa, n, e, d) != 1) {
            freeParts();
            RSA_free(rsa);
            cleanseParts();
            return;
        }
        n = nullptr;
        e = nullptr;
        d = nullptr;
        if (RSA_set0_factors(rsa, p, q) != 1) {
            freeParts();
            RSA_free(rsa);
            cleanseParts();
            return;
        }
        p = nullptr;
        q = nullptr;
        if (RSA_set0_crt_params(rsa, dmp1, dmq1, iqmp) != 1) {
            freeParts();
            RSA_free(rsa);
            cleanseParts();
            return;
        }
        dmp1 = nullptr;
        dmq1 = nullptr;
        iqmp = nullptr;
        cleanseParts();

#ifndef HIDDER_INPUT_VALIDATION
        if (RSA_check_key_ex(rsa, nullptr) != 1) {
            RSA_free(rsa);
            return;
        }
#endif

        pClientKey = EVP_PKEY_new();
        if (pClientKey == nullptr) {
            RSA_free(rsa);
            return;
        }
        if (EVP_PKEY_assign_RSA(pClientKey, rsa) != 1) {
            EVP_PKEY_free(pClientKey);
            RSA_free(rsa);
            pClientKey = nullptr;
            return;
        }
#ifndef HIDDER_INPUT_VALIDATION
        if (!clientKeyMatchesExpectedIdentity(pClientKey)) {
            EVP_PKEY_free(pClientKey);
            pClientKey = nullptr;
        }
#endif
    }

}

int pf_inflate(unsigned char* dest, unsigned long* destlen,
               const unsigned char* source, unsigned long sourcelen);

static uint16_t zr16(const unsigned char* p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t zr32(const unsigned char* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

struct ZipEntry {
    std::string name;
    uint16_t flags;
    uint16_t method;
    uint32_t compSize;
    uint32_t uncompSize;
    uint32_t localOffset;
};

static bool zipList(const std::vector<unsigned char>& zip, std::vector<ZipEntry>& out) {
    size_t n = zip.size();
    if (n < 22) return false;
    size_t eocd = (size_t)-1;
    size_t limit = (n > (size_t)(22 + 65535)) ? (n - (22 + 65535)) : 0;
    for (size_t i = n - 22 + 1; i-- > limit; ) {
        if (zr32(&zip[i]) == 0x06054b50) { eocd = i; break; }
        if (i == 0) break;
    }
    if (eocd == (size_t)-1) return false;
    if (eocd + 22 + zr16(&zip[eocd + 20]) != n) return false;
    if (zr16(&zip[eocd + 4]) != 0 || zr16(&zip[eocd + 6]) != 0) return false;
    if (zr16(&zip[eocd + 8]) != zr16(&zip[eocd + 10])) return false;
    uint16_t count = zr16(&zip[eocd + 10]);
    if (count > 32768) return false;
    uint32_t cdSize = zr32(&zip[eocd + 12]);
    uint32_t cdOff = zr32(&zip[eocd + 16]);
    if (cdOff > eocd || cdSize > eocd - cdOff) return false;
    size_t cdEnd = (size_t)cdOff + cdSize;
    size_t p = cdOff;
    for (uint16_t i = 0; i < count; i++) {
        if (p > cdEnd || 46 > cdEnd - p) return false;
        if (zr32(&zip[p]) != 0x02014b50) return false;
        ZipEntry e;
        e.flags = zr16(&zip[p + 8]);
        e.method = zr16(&zip[p + 10]);
        e.compSize = zr32(&zip[p + 20]);
        e.uncompSize = zr32(&zip[p + 24]);
        uint16_t nameLen = zr16(&zip[p + 28]);
        uint16_t extraLen = zr16(&zip[p + 30]);
        uint16_t commentLen = zr16(&zip[p + 32]);
        e.localOffset = zr32(&zip[p + 42]);
        if ((size_t)nameLen + extraLen + commentLen > cdEnd - (p + 46)) return false;
        e.name.assign((const char*)&zip[p + 46], nameLen);
        out.push_back(e);
        p += 46 + (size_t)nameLen + extraLen + commentLen;
    }
    return p == cdEnd;
}

static bool zipExtract(const std::vector<unsigned char>& zip, const ZipEntry& e, std::vector<unsigned char>& out) {
    size_t n = zip.size();
    size_t p = e.localOffset;
    if (p > n || 30 > n - p || (e.flags & 1) != 0) return false;
    if (zr32(&zip[p]) != 0x04034b50) return false;
    if (zr16(&zip[p + 6]) != e.flags || zr16(&zip[p + 8]) != e.method) return false;
    uint16_t nameLen = zr16(&zip[p + 26]);
    uint16_t extraLen = zr16(&zip[p + 28]);
    if (nameLen != e.name.size() || (size_t)nameLen + extraLen > n - (p + 30)) return false;
    if (std::memcmp(&zip[p + 30], e.name.data(), nameLen) != 0) return false;
    size_t dataOff = p + 30 + nameLen + extraLen;
    if (dataOff > n || e.compSize > n - dataOff) return false;
    if (e.method == 0) {
        if (e.compSize != e.uncompSize) return false;
        out.assign(zip.begin() + dataOff, zip.begin() + dataOff + e.compSize);
        return true;
    } else if (e.method == 8) {
        if (e.uncompSize == 0) { out.clear(); return true; }
        out.resize(e.uncompSize);
        unsigned long destlen = e.uncompSize;
        int r = pf_inflate(out.data(), &destlen, &zip[dataOff], e.compSize);
        if (r != 0 || destlen != e.uncompSize) { out.clear(); return false; }
        out.resize(destlen);
        return true;
    }
    return false;
}

static constexpr size_t MAX_JAR_BYTES = 128u * 1024u * 1024u;
static constexpr size_t MAX_TOTAL_JAR_BYTES = 2048u * 1024u * 1024u;
static constexpr size_t MAX_TOTAL_NESTED_BYTES = 256u * 1024u * 1024u;
static constexpr size_t MAX_JARS = 512;
static constexpr size_t MAX_NESTED_DEPTH = 8;
static constexpr size_t MAX_REPORTED_MODS = 512;

static std::wstring absolutePath(const std::wstring& path) {
    if (path.empty() || path.find(L'\0') != std::wstring::npos
            || path.rfind(L"\\\\.\\", 0) == 0 || path.rfind(L"\\??\\", 0) == 0) return {};
    std::wstring input = path;
    if (path.size() >= 8
            && CompareStringOrdinal(path.c_str(), 8, L"\\\\?\\UNC\\", 8, TRUE) == CSTR_EQUAL) {
        input = L"\\\\" + path.substr(8);
    } else if (path.rfind(L"\\\\?\\", 0) == 0) {
        if (path.size() < 7 || !std::iswalpha(path[4]) || path[5] != L':'
                || (path[6] != L'\\' && path[6] != L'/')) return {};
        input = path.substr(4);
    }
    DWORD length = GetFullPathNameW(input.c_str(), 0, nullptr, nullptr);
    if (length == 0 || length > 32767) return {};
    std::vector<wchar_t> buffer(length + 1);
    DWORD written = GetFullPathNameW(input.c_str(), (DWORD)buffer.size(), buffer.data(), nullptr);
    if (written == 0 || written >= buffer.size()) return {};
    return std::wstring(buffer.data(), written);
}

static std::wstring ioPath(const std::wstring& path) {
    std::wstring full = absolutePath(path);
    if (full.empty()) return full;
    if (full.rfind(L"\\\\", 0) == 0) return L"\\\\?\\UNC\\" + full.substr(2);
    return L"\\\\?\\" + full;
}

static bool readFileBytes(const std::wstring& path, std::vector<unsigned char>& data) {
    std::wstring readable = ioPath(path);
    if (readable.empty()) return false;
    HANDLE h = CreateFileW(readable.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER sz;
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart <= 0
            || static_cast<ULONGLONG>(sz.QuadPart) > MAX_JAR_BYTES) {
        CloseHandle(h);
        return false;
    }
    data.resize((size_t)sz.QuadPart);
    size_t off = 0;
    while (off < data.size()) {
        DWORD toRead = (DWORD)std::min<size_t>(1u << 20, data.size() - off);
        DWORD got = 0;
        if (!ReadFile(h, data.data() + off, toRead, &got, NULL) || got == 0) break;
        off += got;
    }
    CloseHandle(h);
    return off == data.size();
}

static bool sha512Digest(const unsigned char* data, size_t len, std::array<unsigned char, 64>& digest) {
    unsigned int mdLen = 0;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == NULL) return false;
    bool valid = EVP_DigestInit_ex(ctx, EVP_sha512(), NULL) == 1
            && EVP_DigestUpdate(ctx, data, len) == 1
            && EVP_DigestFinal_ex(ctx, digest.data(), &mdLen) == 1
            && mdLen == digest.size();
    EVP_MD_CTX_free(ctx);
    return valid;
}

static std::string sha512B64(const unsigned char* data, size_t len) {
    std::array<unsigned char, 64> digest{};
    if (!sha512Digest(data, len, digest)) return "";
    std::string encoded = base64_encode(digest.data(), digest.size());
    OPENSSL_cleanse(digest.data(), digest.size());
    return encoded;
}

static bool parseModIds(const std::vector<unsigned char>& zip, std::vector<std::string>& ids,
                        size_t depth, size_t& nestedBytes) {
    if (depth > MAX_NESTED_DEPTH || ids.size() >= MAX_REPORTED_MODS) return false;
    std::vector<ZipEntry> entries;
    if (!zipList(zip, entries)) return false;
    const ZipEntry* metadata = nullptr;
    for (const ZipEntry& e : entries) {
        if (e.name == "fabric.mod.json") {
            if (metadata != nullptr) return false;
            metadata = &e;
        }
    }
    if (metadata == nullptr || metadata->uncompSize == 0 || metadata->uncompSize > 1024 * 1024
            || metadata->compSize == 0 || metadata->compSize > 1024 * 1024) return false;
    std::vector<unsigned char> content;
    if (!zipExtract(zip, *metadata, content) || content.empty()) return false;
    std::string json((const char*)content.data(), content.size());
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, json.data(), (int)json.size(), NULL, 0) == 0) {
        return false;
    }
    std::string id;
    std::string version;
    std::vector<std::string> nestedFiles;
    if (!MetadataJsonReader(json).parse(id, version, &nestedFiles)) return false;
    ids.push_back((depth > 0 ? "+" : "") + id + ":" + version);
    for (const std::string& path : nestedFiles) {
        const ZipEntry* nested = nullptr;
        for (const ZipEntry& entry : entries) {
            if (entry.name == path) {
                if (nested != nullptr) return false;
                nested = &entry;
            }
        }
        if (nested == nullptr || nested->uncompSize == 0 || nested->uncompSize > MAX_JAR_BYTES
                || nested->compSize == 0 || nested->compSize > MAX_JAR_BYTES
                || nested->uncompSize > MAX_TOTAL_NESTED_BYTES - nestedBytes) return false;
        std::vector<unsigned char> nestedJar;
        if (!zipExtract(zip, *nested, nestedJar) || nestedJar.size() != nested->uncompSize) return false;
        nestedBytes += nestedJar.size();
        if (!parseModIds(nestedJar, ids, depth + 1, nestedBytes)) return false;
    }
    return true;
}

static std::wstring toWide(const std::string& s) {
    if (s.empty()) return std::wstring();
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), NULL, 0);
    std::wstring w(len, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], len);
    return w;
}

static bool enumerateJars(const std::wstring& dir, std::vector<std::wstring>& jars) {
    std::wstring fullDir = absolutePath(dir);
    if (fullDir.empty()) return false;
    std::wstring separator = fullDir.back() == L'\\' || fullDir.back() == L'/' ? L"" : L"\\";
    std::wstring pattern = ioPath(fullDir + separator + L"*.jar");
    if (pattern.empty()) return false;
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
    }
    while (true) {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            std::wstring name(fd.cFileName);
            if (!name.empty() && name[0] != L'.' && name.size() > 4
                    && name.compare(name.size() - 4, 4, L".jar") == 0) {
                if (jars.size() >= MAX_JARS) {
                    FindClose(h);
                    return false;
                }
                jars.push_back(fullDir + separator + name);
            }
        }
        if (!FindNextFileW(h, &fd)) {
            DWORD error = GetLastError();
            FindClose(h);
            return error == ERROR_NO_MORE_FILES;
        }
    }
}

struct FileIdentity {
    BYTE kind;
    ULONGLONG volume;
    BYTE id[16];
    std::wstring path;

    bool operator<(const FileIdentity& other) const {
        if (kind != other.kind) return kind < other.kind;
        if (kind == 2) return path < other.path;
        if (volume != other.volume) return volume < other.volume;
        return std::memcmp(id, other.id, sizeof(id)) < 0;
    }
};

static bool extendedFileIdentity(HANDLE handle, FileIdentity& identity) {
    FILE_ID_INFO info{};
    if (!GetFileInformationByHandleEx(handle, FileIdInfo, &info, sizeof(info))) return false;
    identity.kind = 0;
    identity.volume = info.VolumeSerialNumber;
    std::memcpy(identity.id, info.FileId.Identifier, sizeof(identity.id));
    return true;
}

static bool basicFileIdentity(HANDLE handle, FileIdentity& identity) {
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(handle, &info)) return false;
    identity.kind = 1;
    identity.volume = info.dwVolumeSerialNumber;
    std::memset(identity.id, 0, sizeof(identity.id));
    std::memcpy(identity.id, &info.nFileIndexHigh, sizeof(info.nFileIndexHigh));
    std::memcpy(identity.id + sizeof(info.nFileIndexHigh),
            &info.nFileIndexLow, sizeof(info.nFileIndexLow));
    return true;
}

static bool exactPathIdentity(HANDLE handle, const std::wstring& path, FileIdentity& identity) {
    DWORD length = GetFinalPathNameByHandleW(handle, nullptr, 0,
            FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    std::wstring resolved;
    if (length > 0 && length <= 32767) {
        std::vector<wchar_t> buffer(length + 1);
        DWORD written = GetFinalPathNameByHandleW(handle, buffer.data(), (DWORD)buffer.size(),
                FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
        if (written > 0 && written < buffer.size()) resolved.assign(buffer.data(), written);
    }
    if (resolved.empty()) resolved = absolutePath(path);
    if (resolved.empty()) return false;
    identity.kind = 2;
    identity.path = resolved;
    return true;
}

static bool fileIdentity(const std::wstring& path, FileIdentity& identity) {
    std::wstring readable = ioPath(path);
    if (readable.empty()) return false;
    HANDLE handle = CreateFileW(readable.c_str(), FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) return false;
    bool result = extendedFileIdentity(handle, identity)
            || basicFileIdentity(handle, identity)
            || exactPathIdentity(handle, path, identity);
    CloseHandle(handle);
    return result;
}

static bool collectModsAndHashes(const std::string& gameDirNarrow, const std::wstring& selectedModsDir,
                                 bool hasSelectedModsDir, bool advanced,
                                 const std::map<std::string, std::wstring>& expectedSources,
                                 std::string& modsOut, std::string& hashesOut) {
    const LoaderIntegrityProfile* profile = activeLoaderProfile.load(std::memory_order_acquire);
    if (profile == nullptr) return false;
    std::vector<std::wstring> jars;
    std::wstring modsDir;
    if (hasSelectedModsDir) {
        modsDir = selectedModsDir.empty() ? L"." : selectedModsDir;
    } else if (!gameDirNarrow.empty()) {
        modsDir = toWide(gameDirNarrow) + L"\\mods";
    } else {
        modsDir = L"mods";
    }
    if (!enumerateJars(modsDir, jars)) return false;

    std::set<FileIdentity> queued;
    for (const std::wstring& jar : jars) {
        FileIdentity identity{};
        if (!fileIdentity(jar, identity)) return false;
        queued.insert(identity);
    }
    for (const auto& source : expectedSources) {
        const std::wstring& path = source.second;
        if (path.size() <= 4 || path.compare(path.size() - 4, 4, L".jar") != 0) return false;
        FileIdentity identity{};
        if (!fileIdentity(path, identity)) return false;
        if (!queued.insert(identity).second) continue;
        if (jars.size() >= MAX_JARS) return false;
        jars.push_back(path);
    }

    std::vector<std::string> mods;
    std::vector<std::string> hashes;
    std::set<FileIdentity> seenPaths;
    bool mixinExtrasSeen = false;
    size_t totalBytes = 0;
    size_t nestedBytes = 0;
    for (const std::wstring& jarPath : jars) {
        FileIdentity identity{};
        if (!fileIdentity(jarPath, identity)) return false;
        if (!seenPaths.insert(identity).second) continue;
        std::vector<unsigned char> bytes;
        if (!readFileBytes(jarPath, bytes)) return false;
        if (bytes.size() > MAX_TOTAL_JAR_BYTES - totalBytes) return false;
        totalBytes += bytes.size();
        std::vector<std::string> modIds;
        if (!parseModIds(bytes, modIds, 0, nestedBytes)) return false;
        bool declaresMixinExtras = false;
        for (const std::string& modid : modIds) {
            if (!modid.empty() && modid[0] != '+' && modid.rfind("mixinextras:", 0) == 0) {
                declaresMixinExtras = true;
            }
        }
        if (declaresMixinExtras) {
            std::array<unsigned char, 64> digest{};
            bool trusted = !mixinExtrasSeen
                    && modIds[0] == profile->mixinExtrasIdentity
                    && sha512Digest(bytes.data(), bytes.size(), digest)
                    && CRYPTO_memcmp(digest.data(), profile->mixinExtrasDigest, digest.size()) == 0;
            OPENSSL_cleanse(digest.data(), digest.size());
            if (!trusted) return false;
            mixinExtrasSeen = true;
            continue;
        }
        std::string h;
        if (advanced) {
            h = sha512B64(bytes.data(), bytes.size());
            if (h.empty()) return false;
        }
        std::set<std::string> jarSeen;
        bool jarHasTopLevel = false;
        for (const std::string& modid : modIds) {
            bool nested = !modid.empty() && modid[0] == '+';
            const std::string entry = nested ? modid.substr(1) : modid;
            if (entry.find(':') == std::string::npos) return false;
            if (!jarSeen.insert(entry).second) continue;
            if (mods.size() >= MAX_REPORTED_MODS) return false;
            mods.push_back(modid);
            if (!nested) jarHasTopLevel = true;
        }
        if (!jarHasTopLevel) return false;
        if (advanced) hashes.push_back(h);
    }

    if (mods.empty()) return false;

    for (size_t i = 0; i < mods.size(); i++) {
        if (i > 0) modsOut += ",";
        modsOut += mods[i];
    }
    for (size_t i = 0; i < hashes.size();) {
        size_t run = 1;
        while (i + run < hashes.size() && hashes[i + run] == hashes[i]) run++;
        if (i > 0) hashesOut += ",";
        hashesOut += run > 1 ? hashes[i] + "*" + std::to_string(run) : hashes[i];
        i += run;
    }
    return true;
}

static bool getSystemProperty(JNIEnv* env, const char* name, std::wstring& value, bool* present = nullptr) {
    jclass systemClass = env->FindClass("java/lang/System");
    if (systemClass == nullptr) return false;
    jmethodID getter = env->GetStaticMethodID(systemClass, "getProperty", "(Ljava/lang/String;)Ljava/lang/String;");
    if (getter == nullptr) {
        env->DeleteLocalRef(systemClass);
        return false;
    }
    jstring key = env->NewStringUTF(name);
    if (key == nullptr) {
        env->DeleteLocalRef(systemClass);
        return false;
    }
    jstring result = (jstring)env->CallStaticObjectMethod(systemClass, getter, key);
    env->DeleteLocalRef(key);
    env->DeleteLocalRef(systemClass);
    if (env->ExceptionCheck()) return false;
    if (present != nullptr) *present = result != nullptr;
    if (result != nullptr) {
        const jchar* chars = env->GetStringChars(result, nullptr);
        if (chars == nullptr) {
            env->DeleteLocalRef(result);
            return false;
        }
        value.assign(chars, chars + env->GetStringLength(result));
        env->ReleaseStringChars(result, chars);
        env->DeleteLocalRef(result);
    }
    return true;
}

static bool getResolvedSources(JNIEnv* env, jstring input,
                               std::map<std::string, std::wstring>& sources) {
    if (input == nullptr) return false;
    jsize length = env->GetStringLength(input);
    if (length < 0 || length > (jsize)(MAX_REPORTED_MODS * 1024)) return false;
    const jchar* chars = env->GetStringChars(input, nullptr);
    if (chars == nullptr) return false;
    std::wstring value(chars, chars + length);
    env->ReleaseStringChars(input, chars);
    if (value.empty()) return false;
    size_t start = 0;
    while (start < value.size()) {
        size_t end = value.find(L'\n', start);
        std::wstring line = value.substr(start, end == std::wstring::npos ? end : end - start);
        size_t separator = line.find(L'\t');
        if (separator == std::wstring::npos || separator == 0 || separator > 256
                || separator == line.size() - 1 || sources.size() >= MAX_REPORTED_MODS) return false;
        std::string id;
        id.reserve(separator);
        for (size_t i = 0; i < separator; ++i) {
            wchar_t ch = line[i];
            if (!((ch >= L'a' && ch <= L'z') || (ch >= L'0' && ch <= L'9')
                    || ch == L'_' || ch == L'-')) return false;
            id.push_back((char)ch);
        }
        std::wstring path = line.substr(separator + 1);
        if (path.find(L'\t') != std::wstring::npos || !sources.emplace(id, path).second) return false;
        if (end == std::wstring::npos) break;
        start = end + 1;
    }
    return start < value.size();
}

static std::string signWithClientKey(const std::string& data) {
    if (pClientKey == NULL) return "";
    EVP_MD_CTX* mdCtx = EVP_MD_CTX_new();
    if (mdCtx == NULL) return "";
    size_t sigLen = 0;
    bool ready = EVP_DigestSignInit(mdCtx, NULL, EVP_sha256(), NULL, pClientKey) > 0
            && EVP_DigestSignUpdate(mdCtx, data.data(), data.size()) > 0
            && EVP_DigestSignFinal(mdCtx, NULL, &sigLen) > 0
            && sigLen > 0 && sigLen <= 8192;
    if (!ready) {
        EVP_MD_CTX_free(mdCtx);
        return "";
    }
    std::vector<BYTE> signature(sigLen);
    bool signedData = EVP_DigestSignFinal(mdCtx, signature.data(), &sigLen) > 0;
    EVP_MD_CTX_free(mdCtx);
    if (!signedData || sigLen == 0 || sigLen > signature.size()) return "";
    signature.resize(sigLen);
    return base64_encode(signature.data(), (unsigned int)sigLen);
}

static bool isLowerHex(const std::string& value, size_t length) {
    if (value.size() != length) return false;
    for (char c : value) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return true;
}

static bool validSealFields(const std::string& fields) {
    const std::string checkPrefix = "checkId=chk-";
    const std::string nonceMarker = "|nonce=";
    if (fields.size() > 16384 || fields.rfind(checkPrefix, 0) != 0) return false;

    size_t noncePos = fields.find(nonceMarker, checkPrefix.size());
    if (noncePos != 20) return false;
    if (fields.find('|', noncePos + nonceMarker.size()) != std::string::npos) return false;

    std::string checkHex = fields.substr(checkPrefix.size(), 8);
    std::string nonce = fields.substr(noncePos + nonceMarker.size());
    return isLowerHex(checkHex, 8) && isLowerHex(nonce, 32);
}

static EVP_PKEY* importPubKeyB64(const std::string& b64) {
    std::vector<BYTE> der = base64_decode(b64);
    if (der.empty()) return NULL;
    const unsigned char* p = der.data();
    EVP_PKEY* key = d2i_PUBKEY(NULL, &p, (long)der.size());
    if (key != NULL && (p != der.data() + der.size() || EVP_PKEY_base_id(key) != EVP_PKEY_RSA
            || EVP_PKEY_bits(key) < 2048 || EVP_PKEY_bits(key) > 4096)) {
        EVP_PKEY_free(key);
        return NULL;
    }
    return key;
}

static std::string encryptToKey(EVP_PKEY* serverKey, const std::string& plainText) {
    if (serverKey == NULL || plainText.size() > 256u * 1024u) return "";

    BYTE aesKey[32]{};
    auto clearKey = [&]() {
        OPENSSL_cleanse(aesKey, sizeof(aesKey));
    };
    if (RAND_bytes(aesKey, 32) != 1) {
        clearKey();
        return "";
    }

    EVP_PKEY_CTX* rsaCtx = EVP_PKEY_CTX_new(serverKey, NULL);
    if (rsaCtx == NULL) {
        clearKey();
        return "";
    }
    if (EVP_PKEY_encrypt_init(rsaCtx) <= 0
            || EVP_PKEY_CTX_set_rsa_padding(rsaCtx, RSA_PKCS1_OAEP_PADDING) <= 0
            || EVP_PKEY_CTX_set_rsa_oaep_md(rsaCtx, EVP_sha256()) <= 0
            || EVP_PKEY_CTX_set_rsa_mgf1_md(rsaCtx, EVP_sha256()) <= 0) {
        EVP_PKEY_CTX_free(rsaCtx);
        clearKey();
        return "";
    }
    size_t encryptedKeyLen = 0;
    if (EVP_PKEY_encrypt(rsaCtx, NULL, &encryptedKeyLen, aesKey, 32) <= 0) {
        EVP_PKEY_CTX_free(rsaCtx);
        clearKey();
        return "";
    }
    std::vector<BYTE> encryptedAesKey(encryptedKeyLen);
    if (EVP_PKEY_encrypt(rsaCtx, encryptedAesKey.data(), &encryptedKeyLen, aesKey, 32) <= 0) {
        EVP_PKEY_CTX_free(rsaCtx);
        clearKey();
        return "";
    }
    EVP_PKEY_CTX_free(rsaCtx);

    BYTE iv[12];
    if (RAND_bytes(iv, sizeof(iv)) != 1) {
        clearKey();
        return "";
    }
    EVP_CIPHER_CTX* aesCtx = EVP_CIPHER_CTX_new();
    if (aesCtx == NULL) {
        clearKey();
        return "";
    }
    int outLen = 0, finalLen = 0;
    std::vector<BYTE> encryptedData(plainText.length() + 16);
    BYTE tag[16];
    bool encrypted = EVP_EncryptInit_ex(aesCtx, EVP_aes_256_gcm(), NULL, NULL, NULL) > 0
            && EVP_CIPHER_CTX_ctrl(aesCtx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL) > 0
            && EVP_EncryptInit_ex(aesCtx, NULL, NULL, aesKey, iv) > 0
            && EVP_EncryptUpdate(aesCtx, encryptedData.data(), &outLen,
                                 (const unsigned char*)plainText.data(), (int)plainText.length()) > 0
            && EVP_EncryptFinal_ex(aesCtx, encryptedData.data() + outLen, &finalLen) > 0
            && EVP_CIPHER_CTX_ctrl(aesCtx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag) > 0;
    EVP_CIPHER_CTX_free(aesCtx);
    if (!encrypted) {
        clearKey();
        return "";
    }
    encryptedData.resize(outLen + finalLen);
    encryptedData.insert(encryptedData.end(), tag, tag + sizeof(tag));

    std::string result = base64_encode(encryptedAesKey.data(), (unsigned int)encryptedKeyLen) + "|" +
           base64_encode(iv, sizeof(iv)) + "|" +
           base64_encode(encryptedData.data(), (unsigned int)encryptedData.size());
    clearKey();
    return result;
}

static jstring JNICALL detectLauncherCore(JNIEnv* env, jclass clazz);

    static bool hidderDebuggerPresent() {
        if (IsDebuggerPresent()) {
            return true;
        }
        BOOL remote = FALSE;
        if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote) && remote) {
            return true;
        }
        return false;
    }

    static jstring JNICALL signChallengeCore(JNIEnv* env, jclass clazz, jstring nonce, jlong timestamp) {
        if (env->ExceptionCheck()) return nullptr;
        if (hidderDebuggerPresent()) {
            return env->NewStringUTF("ERROR_ENV");
        }
        InitializeKeys();
        if (pClientKey == NULL) {
            return env->NewStringUTF("ERROR_KEY_INIT");
        }

        if (nonce == nullptr) return env->NewStringUTF("ERROR_INPUT");
        const char* nonceChars = env->GetStringUTFChars(nonce, nullptr);
        if (nonceChars == nullptr) return nullptr;
        std::string nonceValue(nonceChars);
        env->ReleaseStringUTFChars(nonce, nonceChars);
        if (!isLowerHex(nonceValue, 32) || timestamp < 1000000000000LL || timestamp > 9999999999999LL) {
            return env->NewStringUTF("ERROR_INPUT");
        }

        jstring detected = detectLauncherCore(env, clazz);
        if (detected == nullptr) {
            return env->ExceptionCheck() ? nullptr : env->NewStringUTF("ERROR_LAUNCHER");
        }
        const char* launcherChars = env->GetStringUTFChars(detected, nullptr);
        if (launcherChars == nullptr) {
            env->DeleteLocalRef(detected);
            return env->ExceptionCheck() ? nullptr : env->NewStringUTF("ERROR_LAUNCHER");
        }
        std::string launcherId(launcherChars);
        env->ReleaseStringUTFChars(detected, launcherChars);
        env->DeleteLocalRef(detected);
        if (launcherId.empty() || launcherId.size() > 32) return env->NewStringUTF("ERROR_LAUNCHER");
        for (char ch : launcherId) {
            if (!((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '-')) {
                return env->NewStringUTF("ERROR_LAUNCHER");
            }
        }
        std::string data = "MODSEEKER|3.6|L1|" + nonceValue + "|" + std::to_string(timestamp) + "|" + launcherId;
        std::string signature = signWithClientKey(data);
        if (signature.empty()) return env->NewStringUTF("ERROR_SIGN");
        return env->NewStringUTF((launcherId + "|" + signature).c_str());
    }

    static std::string wideToLowerString(const wchar_t* wstr) {
        if (!wstr) return "";
        int len = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, nullptr, 0, nullptr, nullptr);
        if (len <= 0) return "";
        std::string str(len - 1, '\0');
        WideCharToMultiByte(CP_UTF8, 0, wstr, -1, &str[0], len, nullptr, nullptr);
        std::transform(str.begin(), str.end(), str.begin(),
            [](unsigned char c) { return std::tolower(c); });
        return str;
    }


    static std::string toLower(const std::string& s) {
        std::string result = s;
        std::transform(result.begin(), result.end(), result.begin(),
            [](unsigned char c) { return std::tolower(c); });
        return result;
    }

    static std::string extractJvmProperty(const std::string& cmdLine, const std::string& propName) {
        std::string search1 = "-d" + toLower(propName) + "=";
        std::string lowerCmd = toLower(cmdLine);

        size_t pos = lowerCmd.find(search1);
        if (pos == std::string::npos) return "";

        pos += search1.length();

        size_t end = pos;
        if (end < cmdLine.length() && cmdLine[end] == '"') {
            end++;
            while (end < cmdLine.length() && cmdLine[end] != '"') end++;
            return cmdLine.substr(pos + 1, end - pos - 1);
        }

        while (end < cmdLine.length() && cmdLine[end] != ' ' && cmdLine[end] != ',' && cmdLine[end] != '\t') {
            end++;
        }
        return cmdLine.substr(pos, end - pos);
    }

    static std::string extractGameDir(const std::string& cmdLine) {
        std::string lowerCmd = toLower(cmdLine);
        size_t pos = lowerCmd.find("--gamedir");
        if (pos == std::string::npos) return "";

        pos += 9;

        while (pos < cmdLine.length() && (cmdLine[pos] == '=' || cmdLine[pos] == ' ' || cmdLine[pos] == ',')) {
            pos++;
        }

        size_t end = pos;
        if (end < cmdLine.length() && cmdLine[end] == '"') {
            end++;
            while (end < cmdLine.length() && cmdLine[end] != '"') end++;
            return cmdLine.substr(pos + 1, end - pos - 1);
        }
        while (end < cmdLine.length() && cmdLine[end] != ' ' && cmdLine[end] != ',' && cmdLine[end] != '\t') {
            end++;
        }
        return cmdLine.substr(pos, end - pos);
    }


    static DWORD getParentPID() {
        DWORD pid = GetCurrentProcessId();
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(pe);

        DWORD parentPid = 0;
        if (Process32FirstW(hSnapshot, &pe)) {
            do {
                if (pe.th32ProcessID == pid) {
                    parentPid = pe.th32ParentProcessID;
                    break;
                }
            } while (Process32NextW(hSnapshot, &pe));
        }
        CloseHandle(hSnapshot);
        return parentPid;
    }


    static std::string getProcessName(DWORD pid) {
        if (pid == 0) return "";
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return "";

        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(pe);

        std::string name = "";
        if (Process32FirstW(hSnapshot, &pe)) {
            do {
                if (pe.th32ProcessID == pid) {
                    name = wideToLowerString(pe.szExeFile);
                    break;
                }
            } while (Process32NextW(hSnapshot, &pe));
        }
        CloseHandle(hSnapshot);
        return name;
    }


    static std::string getProcessPath(DWORD pid) {
        if (pid == 0) return "";
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!hProcess) return "";

        wchar_t path[MAX_PATH] = { 0 };
        DWORD pathLen = MAX_PATH;
        std::string result = "";
        if (QueryFullProcessImageNameW(hProcess, 0, path, &pathLen)) {
            result = wideToLowerString(path);
        }
        CloseHandle(hProcess);
        return result;
    }


    static std::string matchBrandToLauncher(const std::string& brand) {
        if (brand.empty()) return "";
        std::string b = toLower(brand);


        if (b.find("atlauncher") != std::string::npos)  return "atlauncher";
        if (b.find("prism") != std::string::npos)       return "prism";
        if (b.find("curseforge") != std::string::npos)  return "curseforge";
        if (b.find("multimc") != std::string::npos)     return "multimc";
        if (b.find("modrinth") != std::string::npos)    return "modrinth";
        if (b.find("gdlauncher") != std::string::npos)  return "gdlauncher";
        if (b.find("technic") != std::string::npos)     return "technic";
        if (b.find("ftb") != std::string::npos)         return "ftb";
        if (b.find("lunar") != std::string::npos)       return "lunar";
        if (b.find("badlion") != std::string::npos)     return "badlion";
        if (b.find("feather") != std::string::npos)     return "feather";
        if (b.find("tlauncher") != std::string::npos)   return "tlauncher";
        if (b.find("sklauncher") != std::string::npos)  return "sklauncher";
        if (b.find("skl") != std::string::npos)         return "sklauncher";

        return "";
    }


    static std::string matchProcessToLauncher(const std::string& processName, const std::string& processPath) {
        if (processName.empty()) return "";
        std::string p = toLower(processName);
        std::string pp = toLower(processPath);


        if (p.find("atlauncher") != std::string::npos)       return "atlauncher";
        if (p.find("prismlauncher") != std::string::npos)    return "prism";
        if (p.find("curseforge") != std::string::npos)       return "curseforge";
        if (p.find("multimc") != std::string::npos)          return "multimc";
        if (p.find("modrinth") != std::string::npos)         return "modrinth";
        if (p.find("gdlauncher") != std::string::npos)       return "gdlauncher";
        if (p.find("technic") != std::string::npos)          return "technic";
        if (p.find("ftb") != std::string::npos)              return "ftb";
        if (p.find("lunar") != std::string::npos)            return "lunar";
        if (p.find("badlion") != std::string::npos)          return "badlion";
        if (p.find("feather") != std::string::npos)          return "feather";
        if (p.find("tlauncher") != std::string::npos)        return "tlauncher";
        if (p.find("sklauncher") != std::string::npos)       return "sklauncher";


        if (!pp.empty()) {
            if (pp.find("atlauncher") != std::string::npos)       return "atlauncher";
            if (pp.find("prismlauncher") != std::string::npos)    return "prism";
            if (pp.find("curseforge") != std::string::npos)       return "curseforge";
            if (pp.find("multimc") != std::string::npos)          return "multimc";
            if (pp.find("modrinth") != std::string::npos)         return "modrinth";
            if (pp.find("gdlauncher") != std::string::npos)       return "gdlauncher";
            if (pp.find("technic") != std::string::npos)          return "technic";
            if (pp.find("ftba") != std::string::npos)             return "ftb";
            if (pp.find("feed the beast") != std::string::npos)   return "ftb";
            if (pp.find("lunar") != std::string::npos)            return "lunar";
            if (pp.find("badlion") != std::string::npos)          return "badlion";
            if (pp.find("feather") != std::string::npos)          return "feather";
            if (pp.find("tlauncher") != std::string::npos)        return "tlauncher";
            if (pp.find("sklauncher") != std::string::npos)       return "sklauncher";
        }

        return "";
    }


    static std::string matchPathToLauncher(const std::string& gameDir) {
        if (gameDir.empty()) return "";
        std::string gd = toLower(gameDir);

        if (gd.find("atlauncher") != std::string::npos)         return "atlauncher";
        if (gd.find("prismlauncher") != std::string::npos)      return "prism";
        if (gd.find(".prismlauncher") != std::string::npos)     return "prism";
        if (gd.find("curseforge") != std::string::npos)         return "curseforge";
        if (gd.find("multimc") != std::string::npos)            return "multimc";
        if (gd.find(".multimc") != std::string::npos)           return "multimc";
        if (gd.find("com.modrinth") != std::string::npos)       return "modrinth";
        if (gd.find("modrinth") != std::string::npos)           return "modrinth";
        if (gd.find("gdlauncher") != std::string::npos)         return "gdlauncher";
        if (gd.find(".technic") != std::string::npos)           return "technic";
        if (gd.find("technic") != std::string::npos)            return "technic";
        if (gd.find(".ftba") != std::string::npos)              return "ftb";
        if (gd.find("ftb app") != std::string::npos)            return "ftb";
        if (gd.find("feed the beast") != std::string::npos)     return "ftb";
        if (gd.find(".lunarclient") != std::string::npos)       return "lunar";
        if (gd.find("lunarclient") != std::string::npos)        return "lunar";
        if (gd.find("badlion") != std::string::npos)            return "badlion";
        if (gd.find("feather") != std::string::npos)            return "feather";
        if (gd.find(".tlauncher") != std::string::npos)         return "tlauncher";
        if (gd.find("tlauncher") != std::string::npos)          return "tlauncher";
        if (gd.find("sklauncher") != std::string::npos)         return "sklauncher";

        return "";
    }

static jstring JNICALL detectLauncherCore(JNIEnv* env, jclass) {
        std::string result = "";

        {
            wchar_t* cmdLineW = GetCommandLineW();
            std::string cmdLine = wideToLowerString(cmdLineW);


            std::string brand = extractJvmProperty(cmdLine, "minecraft.launcher.brand");
            if (!brand.empty()) {
                result = matchBrandToLauncher(brand);
                if (!result.empty()) {
                    return env->NewStringUTF(result.c_str());
                }
            }


            std::string fabricBrand = extractJvmProperty(cmdLine, "fabric.launcher.brand");
            if (!fabricBrand.empty()) {
                result = matchBrandToLauncher(fabricBrand);
                if (!result.empty()) {
                    return env->NewStringUTF(result.c_str());
                }
            }
        }


        {

            const char* prismId = getenv("PRISM_INST_ID");
            if (prismId != nullptr) {
                return env->NewStringUTF("prism");
            }


            const char* instId = getenv("INST_ID");
            if (instId != nullptr) {

                const char* prismDir = getenv("PRISM_INST_DIR");
                if (prismDir != nullptr) {
                    return env->NewStringUTF("prism");
                }
                return env->NewStringUTF("multimc");
            }


            const char* curseDir = getenv("CURSEFORGE_INSTALL_DIR");
            if (curseDir != nullptr) {
                return env->NewStringUTF("curseforge");
            }


            const char* ftbDir = getenv("FTB_PACK_ID");
            if (ftbDir != nullptr) {
                return env->NewStringUTF("ftb");
            }
        }


        {
            DWORD parentPid = getParentPID();
            if (parentPid != 0) {
                std::string parentName = getProcessName(parentPid);
                std::string parentPath = getProcessPath(parentPid);


                if (parentName.find("java") != std::string::npos) {
                    DWORD grandparentPid = 0;
                    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                    if (hSnap != INVALID_HANDLE_VALUE) {
                        PROCESSENTRY32W pe;
                        pe.dwSize = sizeof(pe);
                        if (Process32FirstW(hSnap, &pe)) {
                            do {
                                if (pe.th32ProcessID == parentPid) {
                                    grandparentPid = pe.th32ParentProcessID;
                                    break;
                                }
                            } while (Process32NextW(hSnap, &pe));
                        }
                        CloseHandle(hSnap);
                    }
                    if (grandparentPid != 0) {
                        parentName = getProcessName(grandparentPid);
                        parentPath = getProcessPath(grandparentPid);
                    }
                }

                result = matchProcessToLauncher(parentName, parentPath);
                if (!result.empty()) {
                    return env->NewStringUTF(result.c_str());
                }
            }
        }


        {
            wchar_t* cmdLineW = GetCommandLineW();
            std::string cmdLine = wideToLowerString(cmdLineW);


            std::string gameDir = extractGameDir(cmdLine);
            if (!gameDir.empty()) {
                result = matchPathToLauncher(gameDir);
                if (!result.empty()) {
                    return env->NewStringUTF(result.c_str());
                }
            }


            result = matchPathToLauncher(cmdLine);
            if (!result.empty()) {
                return env->NewStringUTF(result.c_str());
            }
        }

        return env->NewStringUTF("unknown");
    }

static jstring JNICALL sealPayloadCore(JNIEnv* env, jclass,
            jstring jFields, jstring jServerPub, jstring jResolvedSources, jboolean jAdvanced) {
        if (env->ExceptionCheck()) return nullptr;
        if (hidderDebuggerPresent()) {
            return env->NewStringUTF("ERROR_ENV");
        }
        InitializeKeys();
        if (pClientKey == NULL) {
            return env->NewStringUTF("ERROR_KEY_INIT");
        }

        if (jFields == nullptr) return env->NewStringUTF("ERROR_INPUT");
        const char* fc = env->GetStringUTFChars(jFields, nullptr);
        if (fc == nullptr) return nullptr;
        std::string javaFields(fc);
        env->ReleaseStringUTFChars(jFields, fc);
        if (!validSealFields(javaFields)) {
            return env->NewStringUTF("ERROR_INPUT");
        }

        std::map<std::string, std::wstring> expectedSources;
        if (!getResolvedSources(env, jResolvedSources, expectedSources)) {
            return env->ExceptionCheck() ? nullptr : env->NewStringUTF("ERROR_MOD_SCAN");
        }

        if (jServerPub == nullptr) return env->NewStringUTF("ERROR_SRV_KEY");
        const char* pc = env->GetStringUTFChars(jServerPub, nullptr);
        if (pc == nullptr) return nullptr;
        std::string pubB64(pc);
        env->ReleaseStringUTFChars(jServerPub, pc);

        EVP_PKEY* serverKey = importPubKeyB64(pubB64);
        if (serverKey == NULL) {
            return env->NewStringUTF("ERROR_SRV_KEY");
        }

        std::string cmdLine = wideToLowerString(GetCommandLineW());
        std::string gameDir = extractGameDir(cmdLine);
        std::wstring selectedModsDir;
        bool hasSelectedModsDir = false;
        if (!getSystemProperty(env, "fabric.modsFolder", selectedModsDir, &hasSelectedModsDir)) {
            EVP_PKEY_free(serverKey);
            return env->ExceptionCheck() ? nullptr : env->NewStringUTF("ERROR_MOD_SCAN");
        }
        std::string mods;
        std::string hashes;
        if (!collectModsAndHashes(gameDir, selectedModsDir, hasSelectedModsDir, jAdvanced == JNI_TRUE,
                expectedSources, mods, hashes)) {
            EVP_PKEY_free(serverKey);
            return env->NewStringUTF("ERROR_MOD_SCAN");
        }

        std::string full = javaFields + "|mods=" + mods + "|hashes=" + hashes;
        std::string sig = signWithClientKey("MODSEEKER|3.6|L3|" + full);
        if (sig.empty()) {
            EVP_PKEY_free(serverKey);
            return env->NewStringUTF("ERROR_SIGN");
        }
        std::string payload = full + "|sig=" + sig;

        std::string ciphertext = encryptToKey(serverKey, payload);
        EVP_PKEY_free(serverKey);

        if (ciphertext.empty()) {
            return env->NewStringUTF("ERROR_ENCRYPT");
        }
        return env->NewStringUTF(ciphertext.c_str());
    }

enum class LifecycleStage {
    UNINITIALIZED,
    FABRIC_READY,
    CHALLENGE_ACTIVE,
    CHALLENGE_SIGNED,
    REPORT_ACTIVE,
    CONSUMED,
    INVALIDATED
};

struct LifecycleState {
    std::mutex mutex;
    LifecycleStage stage = LifecycleStage::UNINITIALIZED;
    jweak owner = nullptr;
    jweak classLoader = nullptr;
    jclass ownerClass = nullptr;
    jclass bridgeClass = nullptr;
    jlong generation = 0;
    DWORD fabricThread = 0;
    DWORD sealThread = 0;
    std::string connectionContext;
    std::array<unsigned char, 32> processSecret{};
    std::array<unsigned char, 32> sessionSecret{};
    std::array<unsigned char, 32> sessionTag{};
    std::array<unsigned char, 32> cachedRequest{};
    bool processSecretReady = false;
    bool sessionTagReady = false;
    bool cachedRequestReady = false;
    std::string cachedCiphertext;
    std::chrono::steady_clock::time_point expiresAt{};
};

static LifecycleState lifecycle;
static constexpr auto LIFECYCLE_TTL = std::chrono::seconds(120);
#ifndef HIDDER_INPUT_VALIDATION
static jvmtiEnv* lifecycleJvmti = nullptr;
#endif

static void cleanse(std::array<unsigned char, 32>& value) {
    OPENSSL_cleanse(value.data(), value.size());
}

static void cleanse(std::string& value) {
    if (!value.empty()) OPENSSL_cleanse(&value[0], value.size());
    value.clear();
}

static void clearConnectionLocked(LifecycleStage stage) {
    lifecycle.stage = stage;
    lifecycle.sealThread = 0;
    lifecycle.connectionContext.clear();
    cleanse(lifecycle.sessionSecret);
    cleanse(lifecycle.sessionTag);
    cleanse(lifecycle.cachedRequest);
    lifecycle.sessionTagReady = false;
    lifecycle.cachedRequestReady = false;
    cleanse(lifecycle.cachedCiphertext);
}

static void releaseLifecycleRefsLocked(JNIEnv* env) {
    if (lifecycle.owner != nullptr) env->DeleteWeakGlobalRef(lifecycle.owner);
    if (lifecycle.classLoader != nullptr) env->DeleteWeakGlobalRef(lifecycle.classLoader);
    if (lifecycle.ownerClass != nullptr) env->DeleteGlobalRef(lifecycle.ownerClass);
    if (lifecycle.bridgeClass != nullptr) env->DeleteGlobalRef(lifecycle.bridgeClass);
    lifecycle.owner = nullptr;
    lifecycle.classLoader = nullptr;
    lifecycle.ownerClass = nullptr;
    lifecycle.bridgeClass = nullptr;
}

static bool readUtf8(JNIEnv* env, jstring value, size_t maxBytes, std::string& result) {
    if (value == nullptr) return false;
    jsize length = env->GetStringUTFLength(value);
    if (env->ExceptionCheck() || length < 0 || static_cast<size_t>(length) > maxBytes) return false;
    const char* chars = env->GetStringUTFChars(value, nullptr);
    if (chars == nullptr) return false;
    result.assign(chars, static_cast<size_t>(length));
    env->ReleaseStringUTFChars(value, chars);
    return !env->ExceptionCheck();
}

static jobject classLoaderOf(JNIEnv* env, jobject owner) {
    jclass ownerClass = env->GetObjectClass(owner);
    if (ownerClass == nullptr) return nullptr;
    jclass classClass = env->FindClass("java/lang/Class");
    if (classClass == nullptr) {
        env->DeleteLocalRef(ownerClass);
        return nullptr;
    }
    jmethodID getClassLoader = env->GetMethodID(classClass, "getClassLoader", "()Ljava/lang/ClassLoader;");
    if (getClassLoader == nullptr) {
        env->DeleteLocalRef(classClass);
        env->DeleteLocalRef(ownerClass);
        return nullptr;
    }
    jobject loader = env->CallObjectMethod(ownerClass, getClassLoader);
    env->DeleteLocalRef(classClass);
    env->DeleteLocalRef(ownerClass);
    return env->ExceptionCheck() ? nullptr : loader;
}

static jobject classLoaderOfClass(JNIEnv* env, jclass type) {
    jclass classClass = env->FindClass("java/lang/Class");
    if (classClass == nullptr) return nullptr;
    jmethodID getClassLoader = env->GetMethodID(classClass, "getClassLoader", "()Ljava/lang/ClassLoader;");
    if (getClassLoader == nullptr) {
        env->DeleteLocalRef(classClass);
        return nullptr;
    }
    jobject loader = env->CallObjectMethod(type, getClassLoader);
    env->DeleteLocalRef(classClass);
    return env->ExceptionCheck() ? nullptr : loader;
}

static bool classNameEquals(JNIEnv* env, jclass type, const char* expected) {
    jclass classClass = env->FindClass("java/lang/Class");
    if (classClass == nullptr) return false;
    jmethodID getName = env->GetMethodID(classClass, "getName", "()Ljava/lang/String;");
    if (getName == nullptr) {
        env->DeleteLocalRef(classClass);
        return false;
    }
    jstring name = static_cast<jstring>(env->CallObjectMethod(type, getName));
    env->DeleteLocalRef(classClass);
    if (name == nullptr || env->ExceptionCheck()) return false;
    std::string value;
    bool read = readUtf8(env, name, 256, value);
    env->DeleteLocalRef(name);
    return read && value == expected;
}

#ifndef HIDDER_INPUT_VALIDATION
struct ClassMethodBytes {
    std::string name;
    std::string descriptor;
    jint modifiers;
    std::vector<unsigned char> code;
};

static bool fingerprintUpdateInt(EVP_MD_CTX* digest, unsigned int value) {
    unsigned char bytes[4] = {
        static_cast<unsigned char>(value >> 24),
        static_cast<unsigned char>(value >> 16),
        static_cast<unsigned char>(value >> 8),
        static_cast<unsigned char>(value)
    };
    return EVP_DigestUpdate(digest, bytes, sizeof(bytes)) == 1;
}

static bool fingerprintUpdateBytes(EVP_MD_CTX* digest, const unsigned char* bytes, size_t size) {
    return fingerprintUpdateInt(digest, static_cast<unsigned int>(size))
            && (size == 0 || EVP_DigestUpdate(digest, bytes, size) == 1);
}

static bool classFingerprint(jclass type, std::array<unsigned char, 32>& output) {
    if (lifecycleJvmti == nullptr || type == nullptr) return false;
    jint constantPoolCount = 0;
    jint constantPoolByteCount = 0;
    unsigned char* constantPoolBytes = nullptr;
    if (lifecycleJvmti->GetConstantPool(type, &constantPoolCount, &constantPoolByteCount,
                &constantPoolBytes) != JVMTI_ERROR_NONE) return false;
    jint methodCount = 0;
    jmethodID* methodIds = nullptr;
    if (lifecycleJvmti->GetClassMethods(type, &methodCount, &methodIds) != JVMTI_ERROR_NONE) {
        lifecycleJvmti->Deallocate(constantPoolBytes);
        return false;
    }
    std::vector<ClassMethodBytes> methods;
    bool valid = true;
    for (jint index = 0; index < methodCount && valid; index++) {
        char* name = nullptr;
        char* descriptor = nullptr;
        char* generic = nullptr;
        jint modifiers = 0;
        if (lifecycleJvmti->GetMethodName(methodIds[index], &name, &descriptor, &generic) != JVMTI_ERROR_NONE
                || name == nullptr || descriptor == nullptr
                || lifecycleJvmti->GetMethodModifiers(methodIds[index], &modifiers) != JVMTI_ERROR_NONE) {
            valid = false;
        } else {
            std::vector<unsigned char> code;
            if ((modifiers & (0x0100 | 0x0400)) == 0) {
                jint bytecodeCount = 0;
                unsigned char* bytecodes = nullptr;
                if (lifecycleJvmti->GetBytecodes(methodIds[index], &bytecodeCount, &bytecodes) != JVMTI_ERROR_NONE
                        || bytecodeCount < 0) {
                    valid = false;
                } else {
                    code.assign(bytecodes, bytecodes + bytecodeCount);
                }
                if (bytecodes != nullptr) lifecycleJvmti->Deallocate(bytecodes);
            }
            if (valid) methods.push_back({name, descriptor, modifiers, std::move(code)});
        }
        if (name != nullptr) lifecycleJvmti->Deallocate(reinterpret_cast<unsigned char*>(name));
        if (descriptor != nullptr) lifecycleJvmti->Deallocate(reinterpret_cast<unsigned char*>(descriptor));
        if (generic != nullptr) lifecycleJvmti->Deallocate(reinterpret_cast<unsigned char*>(generic));
    }
    if (methodIds != nullptr) lifecycleJvmti->Deallocate(reinterpret_cast<unsigned char*>(methodIds));
    if (!valid) {
        lifecycleJvmti->Deallocate(constantPoolBytes);
        return false;
    }
    std::sort(methods.begin(), methods.end(), [](const ClassMethodBytes& left, const ClassMethodBytes& right) {
        return left.name < right.name || (left.name == right.name && left.descriptor < right.descriptor);
    });
    EVP_MD_CTX* digest = EVP_MD_CTX_new();
    valid = digest != nullptr && EVP_DigestInit_ex(digest, EVP_sha256(), nullptr) == 1
            && fingerprintUpdateInt(digest, static_cast<unsigned int>(constantPoolCount))
            && fingerprintUpdateBytes(digest, constantPoolBytes, static_cast<size_t>(constantPoolByteCount))
            && fingerprintUpdateInt(digest, static_cast<unsigned int>(methods.size()));
    lifecycleJvmti->Deallocate(constantPoolBytes);
    for (const ClassMethodBytes& method : methods) {
        valid = valid
                && fingerprintUpdateBytes(digest,
                        reinterpret_cast<const unsigned char*>(method.name.data()), method.name.size())
                && fingerprintUpdateBytes(digest,
                        reinterpret_cast<const unsigned char*>(method.descriptor.data()), method.descriptor.size())
                && fingerprintUpdateInt(digest, static_cast<unsigned int>(method.modifiers))
                && fingerprintUpdateBytes(digest, method.code.data(), method.code.size());
    }
    unsigned int digestSize = 0;
    valid = valid && EVP_DigestFinal_ex(digest, output.data(), &digestSize) == 1
            && digestSize == output.size();
    if (digest != nullptr) EVP_MD_CTX_free(digest);
    return valid;
}

static bool classFingerprintMatches(jclass type, const unsigned char expected[32]) {
    std::array<unsigned char, 32> actual{};
    bool matches = classFingerprint(type, actual)
            && CRYPTO_memcmp(actual.data(), expected, actual.size()) == 0;
    cleanse(actual);
    return matches;
}

static bool productionBridgeFingerprintsMatch(jclass bridge, jclass loader) {
    return classFingerprintMatches(bridge, EXPECTED_NATIVE_BRIDGE_FINGERPRINT)
            && classFingerprintMatches(loader, EXPECTED_NATIVE_LIBRARY_LOADER_FINGERPRINT);
}

static bool productionFingerprintIdentityValid() {
    unsigned char combined = 0;
    for (size_t index = 0; index < 64; index++) {
        combined |= static_cast<unsigned char>(CLASS_FINGERPRINT_IDENTITY[index]);
    }
    return combined != 0 && CLASS_FINGERPRINT_IDENTITY[64] == '\0';
}

static const LoaderIntegrityProfile* productionFabricProfile(JNIEnv* env) {
    const char* names[] = {
        "net/fabricmc/loader/api/FabricLoader",
        "net/fabricmc/loader/impl/FabricLoaderImpl",
        "net/fabricmc/loader/impl/launch/FabricLauncherBase",
        "net/fabricmc/loader/impl/launch/knot/KnotClassLoader",
        "net/fabricmc/loader/impl/launch/knot/KnotClassDelegate",
        "net/fabricmc/loader/impl/entrypoint/EntrypointStorage"
    };
    unsigned char measured[6][32]{};
    for (size_t index = 0; index < 6; index++) {
        jclass type = env->FindClass(names[index]);
        if (type == nullptr || env->ExceptionCheck()) return nullptr;
        std::array<unsigned char, 32> digest{};
        bool valid = classFingerprint(type, digest);
        env->DeleteLocalRef(type);
        if (!valid) return nullptr;
        std::memcpy(measured[index], digest.data(), digest.size());
        cleanse(digest);
    }
    const LoaderIntegrityProfile* selected = selectLoaderIntegrityProfile(measured,
            EXPECTED_LOADER_PROFILES, sizeof(EXPECTED_LOADER_PROFILES) / sizeof(EXPECTED_LOADER_PROFILES[0]));
    OPENSSL_cleanse(measured, sizeof(measured));
    return selected;
}
#endif

static bool ownerMatchesLocked(JNIEnv* env, jclass bridgeClass, jobject owner) {
    if (owner == nullptr || lifecycle.owner == nullptr || lifecycle.classLoader == nullptr
            || lifecycle.ownerClass == nullptr || lifecycle.bridgeClass == nullptr) return false;
    if (!env->IsSameObject(bridgeClass, lifecycle.bridgeClass)
            || !env->IsSameObject(owner, lifecycle.owner)) return false;
    jclass currentOwnerClass = env->GetObjectClass(owner);
    if (currentOwnerClass == nullptr) return false;
    bool classMatches = env->IsSameObject(currentOwnerClass, lifecycle.ownerClass) == JNI_TRUE;
#ifndef HIDDER_INPUT_VALIDATION
    classMatches = classMatches
            && classFingerprintMatches(bridgeClass, EXPECTED_NATIVE_BRIDGE_FINGERPRINT)
            && classFingerprintMatches(currentOwnerClass, EXPECTED_HIDDER_FABRIC_FINGERPRINT);
#endif
    env->DeleteLocalRef(currentOwnerClass);
    if (!classMatches) return false;
    jobject loader = classLoaderOf(env, owner);
    if (loader == nullptr) return false;
    bool loaderMatches = env->IsSameObject(loader, lifecycle.classLoader) == JNI_TRUE;
    env->DeleteLocalRef(loader);
    return loaderMatches && !env->ExceptionCheck();
}

static bool constantTimeEqual(const std::string& left, const std::string& right) {
    return left.size() == right.size()
            && (left.empty() || CRYPTO_memcmp(left.data(), right.data(), left.size()) == 0);
}

static bool makeSessionTagLocked() {
    if (!lifecycle.processSecretReady
            || RAND_bytes(lifecycle.sessionSecret.data(), static_cast<int>(lifecycle.sessionSecret.size())) != 1) {
        return false;
    }
    std::string material = std::to_string(lifecycle.generation) + "|" + lifecycle.connectionContext;
    material.append(reinterpret_cast<const char*>(lifecycle.sessionSecret.data()), lifecycle.sessionSecret.size());
    unsigned int length = 0;
    unsigned char* result = HMAC(EVP_sha256(), lifecycle.processSecret.data(),
            static_cast<int>(lifecycle.processSecret.size()),
            reinterpret_cast<const unsigned char*>(material.data()), material.size(),
            lifecycle.sessionTag.data(), &length);
    lifecycle.sessionTagReady = result != nullptr && length == lifecycle.sessionTag.size();
    OPENSSL_cleanse(&material[0], material.size());
    return lifecycle.sessionTagReady;
}

static bool validSessionTagLocked() {
    if (!lifecycle.sessionTagReady || !lifecycle.processSecretReady) return false;
    std::array<unsigned char, 32> expected{};
    std::string material = std::to_string(lifecycle.generation) + "|" + lifecycle.connectionContext;
    material.append(reinterpret_cast<const char*>(lifecycle.sessionSecret.data()), lifecycle.sessionSecret.size());
    unsigned int length = 0;
    unsigned char* result = HMAC(EVP_sha256(), lifecycle.processSecret.data(),
            static_cast<int>(lifecycle.processSecret.size()),
            reinterpret_cast<const unsigned char*>(material.data()), material.size(), expected.data(), &length);
    bool valid = result != nullptr && length == expected.size()
            && CRYPTO_memcmp(expected.data(), lifecycle.sessionTag.data(), expected.size()) == 0;
    cleanse(expected);
    OPENSSL_cleanse(&material[0], material.size());
    return valid;
}

static bool digestPart(EVP_MD_CTX* context, const std::string& value) {
    uint64_t length = static_cast<uint64_t>(value.size());
    return EVP_DigestUpdate(context, &length, sizeof(length)) == 1
            && (value.empty() || EVP_DigestUpdate(context, value.data(), value.size()) == 1);
}

static bool digestRequest(const std::string& fields, const std::string& serverPublic,
        const std::string& sources, bool advanced, std::array<unsigned char, 32>& output) {
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    if (context == nullptr) return false;
    unsigned int length = 0;
    unsigned char mode = advanced ? 1 : 0;
    bool valid = EVP_DigestInit_ex(context, EVP_sha256(), nullptr) == 1
            && digestPart(context, fields)
            && digestPart(context, serverPublic)
            && digestPart(context, sources)
            && EVP_DigestUpdate(context, &mode, sizeof(mode)) == 1
            && EVP_DigestFinal_ex(context, output.data(), &length) == 1
            && length == output.size();
    EVP_MD_CTX_free(context);
    return valid;
}

static bool expireConnectionLocked() {
    if (std::chrono::steady_clock::now() <= lifecycle.expiresAt) return false;
    clearConnectionLocked(LifecycleStage::INVALIDATED);
    return true;
}

static bool jstringIsError(JNIEnv* env, jstring value, std::string* text = nullptr) {
    if (value == nullptr) return true;
    const char* chars = env->GetStringUTFChars(value, nullptr);
    if (chars == nullptr) return true;
    std::string result(chars);
    env->ReleaseStringUTFChars(value, chars);
    if (text != nullptr) *text = result;
    return result.rfind("ERROR_", 0) == 0;
}

static bool fabricOwnerRegistered(JNIEnv* env, jobject owner) {
    jclass fabricLoaderClass = nullptr;
    jobject loader = nullptr;
    jclass loaderImplClass = nullptr;
    jobject ownerLoader = nullptr;
    jclass classLoaderClass = nullptr;
    jclass expectedImplClass = nullptr;
    jclass expectedKnotClass = nullptr;
    jclass launcherBaseClass = nullptr;
    jclass launcherClass = nullptr;
    jobject expectedInstance = nullptr;
    jobject launcher = nullptr;
    jobject targetLoader = nullptr;
    jobject loaderImplLoader = nullptr;
    jstring hidder = nullptr;
    jstring client = nullptr;
    jclass initializerClass = nullptr;
    jobject entrypoints = nullptr;
    jclass listClass = nullptr;
    auto release = [&]() {
        for (jobject reference : std::initializer_list<jobject>{listClass, entrypoints, initializerClass, client,
                hidder, loaderImplLoader, targetLoader, launcher, expectedInstance, launcherClass,
                launcherBaseClass, expectedKnotClass, expectedImplClass, classLoaderClass, ownerLoader,
                loaderImplClass, loader, fabricLoaderClass}) {
            if (reference != nullptr) env->DeleteLocalRef(reference);
        }
    };
    auto failed = [&]() {
        return env->ExceptionCheck() == JNI_TRUE;
    };

    fabricLoaderClass = env->FindClass("net/fabricmc/loader/api/FabricLoader");
    if (fabricLoaderClass == nullptr || failed()) {
        release();
        return false;
    }
    jmethodID getInstance = env->GetStaticMethodID(fabricLoaderClass, "getInstance",
            "()Lnet/fabricmc/loader/api/FabricLoader;");
    if (getInstance == nullptr || failed()) {
        release();
        return false;
    }
    jmethodID isModLoaded = env->GetMethodID(fabricLoaderClass, "isModLoaded", "(Ljava/lang/String;)Z");
    if (isModLoaded == nullptr || failed()) {
        release();
        return false;
    }
    jmethodID getEntrypoints = env->GetMethodID(fabricLoaderClass, "getEntrypoints",
            "(Ljava/lang/String;Ljava/lang/Class;)Ljava/util/List;");
    if (getEntrypoints == nullptr || failed()) {
        release();
        return false;
    }
    loader = env->CallStaticObjectMethod(fabricLoaderClass, getInstance);
    if (loader == nullptr || failed()) {
        release();
        return false;
    }
    loaderImplClass = env->GetObjectClass(loader);
    if (loaderImplClass == nullptr || failed()) {
        release();
        return false;
    }
    ownerLoader = classLoaderOf(env, owner);
    if (ownerLoader == nullptr || failed()) {
        release();
        return false;
    }
    classLoaderClass = env->GetObjectClass(ownerLoader);
    if (classLoaderClass == nullptr || failed()) {
        release();
        return false;
    }
    expectedImplClass = env->FindClass("net/fabricmc/loader/impl/FabricLoaderImpl");
    if (expectedImplClass == nullptr || failed()) {
        release();
        return false;
    }
    expectedKnotClass = env->FindClass("net/fabricmc/loader/impl/launch/knot/KnotClassLoader");
    if (expectedKnotClass == nullptr || failed()) {
        release();
        return false;
    }
    launcherBaseClass = env->FindClass("net/fabricmc/loader/impl/launch/FabricLauncherBase");
    if (launcherBaseClass == nullptr || failed()) {
        release();
        return false;
    }
    launcherClass = env->FindClass("net/fabricmc/loader/impl/launch/FabricLauncher");
    if (launcherClass == nullptr || failed()) {
        release();
        return false;
    }
    jfieldID instanceField = env->GetStaticFieldID(expectedImplClass, "INSTANCE",
            "Lnet/fabricmc/loader/impl/FabricLoaderImpl;");
    if (instanceField == nullptr || failed()) {
        release();
        return false;
    }
    expectedInstance = env->GetStaticObjectField(expectedImplClass, instanceField);
    if (expectedInstance == nullptr || failed()) {
        release();
        return false;
    }
    jmethodID getLauncher = env->GetStaticMethodID(launcherBaseClass, "getLauncher",
            "()Lnet/fabricmc/loader/impl/launch/FabricLauncher;");
    if (getLauncher == nullptr || failed()) {
        release();
        return false;
    }
    launcher = env->CallStaticObjectMethod(launcherBaseClass, getLauncher);
    if (launcher == nullptr || failed()) {
        release();
        return false;
    }
    jmethodID getTargetClassLoader = env->GetMethodID(launcherClass, "getTargetClassLoader",
            "()Ljava/lang/ClassLoader;");
    if (getTargetClassLoader == nullptr || failed()) {
        release();
        return false;
    }
    targetLoader = env->CallObjectMethod(launcher, getTargetClassLoader);
    if (targetLoader == nullptr || failed()) {
        release();
        return false;
    }
    loaderImplLoader = classLoaderOfClass(env, loaderImplClass);
    if (loaderImplLoader == nullptr || failed()) {
        release();
        return false;
    }
    bool implementationNameMatches = classNameEquals(env, loaderImplClass,
            "net.fabricmc.loader.impl.FabricLoaderImpl");
    if (!implementationNameMatches || failed()) {
        release();
        return false;
    }
    bool classLoaderNameMatches = classNameEquals(env, classLoaderClass,
            "net.fabricmc.loader.impl.launch.knot.KnotClassLoader");
    if (!classLoaderNameMatches || failed()) {
        release();
        return false;
    }
    bool runtimeMatches = implementationNameMatches
            && classLoaderNameMatches
            && env->IsSameObject(loaderImplClass, expectedImplClass) == JNI_TRUE
            && env->IsSameObject(loader, expectedInstance) == JNI_TRUE
            && env->IsSameObject(classLoaderClass, expectedKnotClass) == JNI_TRUE
            && env->IsSameObject(ownerLoader, targetLoader) == JNI_TRUE
            && env->IsSameObject(loaderImplLoader, ownerLoader) == JNI_FALSE;
    if (!runtimeMatches || failed()) {
        release();
        return false;
    }

    hidder = env->NewStringUTF("hidder");
    if (hidder == nullptr || failed()) {
        release();
        return false;
    }
    client = env->NewStringUTF("client");
    if (client == nullptr || failed()) {
        release();
        return false;
    }
    initializerClass = env->FindClass("net/fabricmc/api/ClientModInitializer");
    if (initializerClass == nullptr || failed()) {
        release();
        return false;
    }
    bool loaded = env->CallBooleanMethod(loader, isModLoaded, hidder) == JNI_TRUE;
    if (!loaded || failed()) {
        release();
        return false;
    }
    entrypoints = env->CallObjectMethod(loader, getEntrypoints, client, initializerClass);
    if (entrypoints == nullptr || failed()) {
        release();
        return false;
    }
    listClass = env->FindClass("java/util/List");
    if (listClass == nullptr || failed()) {
        release();
        return false;
    }
    jmethodID sizeMethod = env->GetMethodID(listClass, "size", "()I");
    if (sizeMethod == nullptr || failed()) {
        release();
        return false;
    }
    jmethodID getMethod = env->GetMethodID(listClass, "get", "(I)Ljava/lang/Object;");
    if (getMethod == nullptr || failed()) {
        release();
        return false;
    }
    jint size = env->CallIntMethod(entrypoints, sizeMethod);
    if (failed()) {
        release();
        return false;
    }
    bool registered = false;
    for (jint index = 0; index < size; index++) {
        jobject candidate = env->CallObjectMethod(entrypoints, getMethod, index);
        if (failed()) {
            if (candidate != nullptr) env->DeleteLocalRef(candidate);
            release();
            return false;
        }
        registered = candidate != nullptr && env->IsSameObject(candidate, owner) == JNI_TRUE;
        if (candidate != nullptr) env->DeleteLocalRef(candidate);
        if (registered) break;
    }
    release();
    return registered && !failed();
}

static std::wstring normalizedCleanupPath(const std::wstring& value) {
    std::wstring path = absolutePath(value);
    if (path.empty() || path.rfind(L"\\\\", 0) == 0) return {};
    for (wchar_t& ch : path) {
        if (ch == L'/') ch = L'\\';
        ch = (wchar_t)std::towlower(ch);
    }
    while (path.size() > 3 && path.back() == L'\\') path.pop_back();
    return path;
}

static std::wstring cleanupHandlePath(HANDLE handle) {
    DWORD length = GetFinalPathNameByHandleW(handle, nullptr, 0,
            FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (length == 0 || length > 32767) return {};
    std::vector<wchar_t> buffer(length + 1);
    DWORD written = GetFinalPathNameByHandleW(handle, buffer.data(), (DWORD)buffer.size(),
            FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (written == 0 || written >= buffer.size()) return {};
    return normalizedCleanupPath(std::wstring(buffer.data(), written));
}

static bool cleanupJString(JNIEnv* env, jstring input, std::wstring& output) {
    if (input == nullptr) return false;
    jsize length = env->GetStringLength(input);
    if (length <= 0 || length > 32767) return false;
    const jchar* chars = env->GetStringChars(input, nullptr);
    if (chars == nullptr || env->ExceptionCheck()) return false;
    output.assign(reinterpret_cast<const wchar_t*>(chars), (size_t)length);
    env->ReleaseStringChars(input, chars);
    return !env->ExceptionCheck() && output.find(L'\0') == std::wstring::npos;
}

static bool cleanupDigest(JNIEnv* env, jbyteArray input, std::array<unsigned char, 32>& output) {
    if (input == nullptr || env->GetArrayLength(input) != (jsize)output.size()) return false;
    env->GetByteArrayRegion(input, 0, (jsize)output.size(), reinterpret_cast<jbyte*>(output.data()));
    return !env->ExceptionCheck();
}

static bool cleanupDirectoryName(const std::wstring& path) {
    size_t separator = path.find_last_of(L'\\');
    if (separator == std::wstring::npos || separator + 1 >= path.size()) return false;
    std::wstring name = path.substr(separator + 1);
    const std::wstring prefix = L"hidder-native-";
    if (name.rfind(prefix, 0) != 0 || name.size() == prefix.size()
            || name.size() > prefix.size() + 20) return false;
    for (size_t index = prefix.size(); index < name.size(); index++) {
        if (name[index] < L'0' || name[index] > L'9') return false;
    }
    return true;
}

static bool cleanupPathAllowed(const std::wstring& root, const std::wstring& path) {
    if (!cleanupDirectoryName(path)) return false;
    size_t separator = path.find_last_of(L'\\');
    if (separator == std::wstring::npos) return false;
    return path.substr(0, separator) == root;
}

static bool cleanupFileShape(HANDLE handle, const std::wstring& expectedPath, LONGLONG expectedSize) {
    FILE_ATTRIBUTE_TAG_INFO attributes{};
    BY_HANDLE_FILE_INFORMATION identity{};
    LARGE_INTEGER size{};
    return GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &attributes, sizeof(attributes))
            && (attributes.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) == 0
            && GetFileInformationByHandle(handle, &identity)
            && identity.nNumberOfLinks == 1
            && GetFileSizeEx(handle, &size)
            && size.QuadPart == expectedSize
            && cleanupHandlePath(handle) == expectedPath;
}

static bool cleanupRead(HANDLE handle, size_t size, std::vector<unsigned char>& output) {
    LARGE_INTEGER start{};
    if (!SetFilePointerEx(handle, start, nullptr, FILE_BEGIN)) return false;
    output.assign(size, 0);
    size_t offset = 0;
    while (offset < size) {
        DWORD requested = (DWORD)std::min<size_t>(1u << 20, size - offset);
        DWORD received = 0;
        if (!ReadFile(handle, output.data() + offset, requested, &received, nullptr) || received == 0) {
            return false;
        }
        offset += received;
    }
    unsigned char extra = 0;
    DWORD received = 0;
    return ReadFile(handle, &extra, 1, &received, nullptr) && received == 0;
}

static bool cleanupVaultMatches(HANDLE handle, size_t size, const std::array<unsigned char, 32>& expected) {
    std::vector<unsigned char> bytes;
    if (!cleanupRead(handle, size, bytes)) return false;
    std::array<unsigned char, EVP_MAX_MD_SIZE> actual{};
    unsigned int actualSize = 0;
    if (EVP_Digest(bytes.data(), bytes.size(), actual.data(), &actualSize, EVP_sha256(), nullptr) != 1
            || actualSize != expected.size()) return false;
    return CRYPTO_memcmp(actual.data(), expected.data(), expected.size()) == 0;
}

static std::string cleanupMarkerText(jlong size, const std::array<unsigned char, 32>& digest) {
    static const char hex[] = "0123456789abcdef";
    std::string text = "hidder_vault.dll.sha256=";
    text.reserve(128);
    for (unsigned char value : digest) {
        text.push_back(hex[value >> 4]);
        text.push_back(hex[value & 15]);
    }
    text += "\nhidder_vault.dll.size=" + std::to_string(size) + "\n";
    return text;
}

static bool cleanupMarkerMatches(HANDLE handle, const std::string& expected) {
    std::vector<unsigned char> bytes;
    return cleanupRead(handle, expected.size(), bytes)
            && bytes.size() == expected.size()
            && CRYPTO_memcmp(bytes.data(), expected.data(), expected.size()) == 0;
}

static bool cleanupMarkDelete(HANDLE handle) {
    FILE_DISPOSITION_INFO disposition{};
    disposition.DeleteFile = TRUE;
    return SetFileInformationByHandle(handle, FileDispositionInfo, &disposition, sizeof(disposition)) != FALSE;
}

static jboolean JNICALL nativePruneStaleExtraction(JNIEnv* env, jclass, jstring rootText,
        jstring directoryText, jlong expectedSize, jbyteArray digestArray) {
    if (expectedSize <= 0 || expectedSize > 16LL * 1024LL * 1024LL) return JNI_FALSE;
    std::wstring suppliedRoot;
    std::wstring suppliedDirectory;
    std::array<unsigned char, 32> expectedDigest{};
    if (!cleanupJString(env, rootText, suppliedRoot)
            || !cleanupJString(env, directoryText, suppliedDirectory)
            || !cleanupDigest(env, digestArray, expectedDigest)) return JNI_FALSE;
    std::wstring root = normalizedCleanupPath(suppliedRoot);
    std::wstring directory = normalizedCleanupPath(suppliedDirectory);
    if (root.empty() || directory.empty() || !cleanupPathAllowed(root, directory)) return JNI_FALSE;
    HANDLE rootHandle = CreateFileW(ioPath(root).c_str(), FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (rootHandle == INVALID_HANDLE_VALUE) return JNI_FALSE;
    FILE_ATTRIBUTE_TAG_INFO rootAttributes{};
    bool rootValid = GetFileInformationByHandleEx(rootHandle, FileAttributeTagInfo,
                &rootAttributes, sizeof(rootAttributes))
            && (rootAttributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0
            && (rootAttributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0
            && cleanupHandlePath(rootHandle) == root;
    CloseHandle(rootHandle);
    if (!rootValid) return JNI_FALSE;
    std::wstring directoryIo = ioPath(directory);
    HANDLE directoryHandle = CreateFileW(directoryIo.c_str(),
            DELETE | FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (directoryHandle == INVALID_HANDLE_VALUE) return JNI_FALSE;
    HANDLE vaultHandle = INVALID_HANDLE_VALUE;
    HANDLE markerHandle = INVALID_HANDLE_VALUE;
    bool deleted = false;
    do {
        FILE_ATTRIBUTE_TAG_INFO directoryAttributes{};
        if (!GetFileInformationByHandleEx(directoryHandle, FileAttributeTagInfo,
                    &directoryAttributes, sizeof(directoryAttributes))
                || (directoryAttributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0
                || (directoryAttributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0
                || cleanupHandlePath(directoryHandle) != directory) break;
        std::wstring vault = directory + L"\\hidder_vault.dll";
        std::wstring marker = directory + L"\\cleanup.marker";
        vaultHandle = CreateFileW(ioPath(vault).c_str(), GENERIC_READ | DELETE | FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
        if (vaultHandle == INVALID_HANDLE_VALUE
                || !cleanupFileShape(vaultHandle, vault, expectedSize)
                || !cleanupVaultMatches(vaultHandle, (size_t)expectedSize, expectedDigest)) break;
        std::string expectedMarker = cleanupMarkerText(expectedSize, expectedDigest);
        markerHandle = CreateFileW(ioPath(marker).c_str(), GENERIC_READ | DELETE | FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
        if (markerHandle == INVALID_HANDLE_VALUE
                || !cleanupFileShape(markerHandle, marker, (LONGLONG)expectedMarker.size())
                || !cleanupMarkerMatches(markerHandle, expectedMarker)
                || cleanupHandlePath(directoryHandle) != directory) break;
        bool vaultDelete = cleanupMarkDelete(vaultHandle);
        bool markerDelete = cleanupMarkDelete(markerHandle);
        deleted = vaultDelete && markerDelete;
    } while (false);
    if (markerHandle != INVALID_HANDLE_VALUE) CloseHandle(markerHandle);
    if (vaultHandle != INVALID_HANDLE_VALUE) CloseHandle(vaultHandle);
    if (deleted) cleanupMarkDelete(directoryHandle);
    CloseHandle(directoryHandle);
    return deleted ? JNI_TRUE : JNI_FALSE;
}

static jboolean JNICALL nativeInitialize(JNIEnv* env, jclass bridgeClass, jobject owner) {
    std::lock_guard<std::mutex> lock(lifecycle.mutex);
    if (lifecycle.stage != LifecycleStage::UNINITIALIZED) {
        return ownerMatchesLocked(env, bridgeClass, owner) ? JNI_TRUE : JNI_FALSE;
    }
    if (owner == nullptr) return JNI_FALSE;
    jclass ownerClass = env->GetObjectClass(owner);
#ifndef HIDDER_INPUT_VALIDATION
    const LoaderIntegrityProfile* approvedLoader = nullptr;
    if (ownerClass == nullptr
            || !classFingerprintMatches(bridgeClass, EXPECTED_NATIVE_BRIDGE_FINGERPRINT)
            || !classFingerprintMatches(ownerClass, EXPECTED_HIDDER_FABRIC_FINGERPRINT)
            || (approvedLoader = productionFabricProfile(env)) == nullptr) {
        if (ownerClass != nullptr) env->DeleteLocalRef(ownerClass);
        return JNI_FALSE;
    }
#endif
    if (!fabricOwnerRegistered(env, owner)) {
        if (ownerClass != nullptr) env->DeleteLocalRef(ownerClass);
        return JNI_FALSE;
    }
    jobject loader = classLoaderOf(env, owner);
    if (ownerClass == nullptr || loader == nullptr || env->ExceptionCheck()) {
        if (ownerClass != nullptr) env->DeleteLocalRef(ownerClass);
        if (loader != nullptr) env->DeleteLocalRef(loader);
        return JNI_FALSE;
    }
    lifecycle.owner = env->NewWeakGlobalRef(owner);
    lifecycle.classLoader = env->NewWeakGlobalRef(loader);
    lifecycle.ownerClass = static_cast<jclass>(env->NewGlobalRef(ownerClass));
    lifecycle.bridgeClass = static_cast<jclass>(env->NewGlobalRef(bridgeClass));
    env->DeleteLocalRef(loader);
    env->DeleteLocalRef(ownerClass);
    if (lifecycle.owner == nullptr || lifecycle.classLoader == nullptr
            || lifecycle.ownerClass == nullptr || lifecycle.bridgeClass == nullptr
            || RAND_bytes(lifecycle.processSecret.data(), static_cast<int>(lifecycle.processSecret.size())) != 1) {
        clearConnectionLocked(LifecycleStage::UNINITIALIZED);
        releaseLifecycleRefsLocked(env);
        cleanse(lifecycle.processSecret);
        lifecycle.processSecretReady = false;
        return JNI_FALSE;
    }
    lifecycle.processSecretReady = true;
#ifndef HIDDER_INPUT_VALIDATION
    activeLoaderProfile.store(approvedLoader, std::memory_order_release);
#endif
    lifecycle.fabricThread = 0;
    lifecycle.stage = LifecycleStage::FABRIC_READY;
    return JNI_TRUE;
}

static jboolean JNICALL nativeBeginConnection(JNIEnv* env, jclass bridgeClass, jobject owner,
        jlong generation, jstring connectionContext) {
    std::string context;
    if (!readUtf8(env, connectionContext, 1024, context) || context.empty()) return JNI_FALSE;
    std::lock_guard<std::mutex> lock(lifecycle.mutex);
    if (!ownerMatchesLocked(env, bridgeClass, owner)
            || generation <= lifecycle.generation) return JNI_FALSE;
    clearConnectionLocked(LifecycleStage::FABRIC_READY);
    lifecycle.fabricThread = GetCurrentThreadId();
    lifecycle.generation = generation;
    lifecycle.connectionContext = context;
    lifecycle.expiresAt = std::chrono::steady_clock::now() + LIFECYCLE_TTL;
    if (!makeSessionTagLocked()) {
        clearConnectionLocked(LifecycleStage::INVALIDATED);
        return JNI_FALSE;
    }
    return JNI_TRUE;
}

static void JNICALL nativeInvalidate(JNIEnv* env, jclass bridgeClass, jobject owner, jlong generation) {
    std::lock_guard<std::mutex> lock(lifecycle.mutex);
    if (!ownerMatchesLocked(env, bridgeClass, owner) || generation < lifecycle.generation) return;
    lifecycle.generation = generation;
    clearConnectionLocked(LifecycleStage::INVALIDATED);
}

static jboolean JNICALL nativeIsReady(JNIEnv* env, jclass bridgeClass, jobject owner) {
    std::lock_guard<std::mutex> lock(lifecycle.mutex);
    bool active = lifecycle.stage != LifecycleStage::UNINITIALIZED
            && lifecycle.stage != LifecycleStage::INVALIDATED
            && ownerMatchesLocked(env, bridgeClass, owner);
    if (active && expireConnectionLocked()) active = false;
    return active ? JNI_TRUE : JNI_FALSE;
}

static jstring JNICALL nativeSignConnectionChallenge(JNIEnv* env, jclass bridgeClass, jobject owner,
        jlong generation, jstring connectionContext, jstring nonce, jlong timestamp) {
    std::string context;
    if (!readUtf8(env, connectionContext, 1024, context)) return env->NewStringUTF("ERROR_STATE");
    {
        std::lock_guard<std::mutex> lock(lifecycle.mutex);
        if (!ownerMatchesLocked(env, bridgeClass, owner)
                || GetCurrentThreadId() != lifecycle.fabricThread
                || lifecycle.stage != LifecycleStage::FABRIC_READY
                || lifecycle.generation != generation
                || !constantTimeEqual(context, lifecycle.connectionContext)) {
            return env->NewStringUTF("ERROR_STATE");
        }
        if (expireConnectionLocked() || !validSessionTagLocked()) {
            return env->NewStringUTF("ERROR_STATE");
        }
        lifecycle.stage = LifecycleStage::CHALLENGE_ACTIVE;
    }
    jstring result = signChallengeCore(env, bridgeClass, nonce, timestamp);
    bool failed = result == nullptr || env->ExceptionCheck() || jstringIsError(env, result);
    {
        std::lock_guard<std::mutex> lock(lifecycle.mutex);
        bool sameOperation = ownerMatchesLocked(env, bridgeClass, owner)
                && lifecycle.stage == LifecycleStage::CHALLENGE_ACTIVE
                && lifecycle.generation == generation
                && constantTimeEqual(context, lifecycle.connectionContext)
                && validSessionTagLocked();
        if (!sameOperation) {
            if (env->ExceptionCheck()) return nullptr;
            if (result != nullptr) env->DeleteLocalRef(result);
            return env->NewStringUTF("ERROR_STATE");
        }
        if (failed) {
            clearConnectionLocked(LifecycleStage::INVALIDATED);
            return result == nullptr || env->ExceptionCheck() ? nullptr : result;
        }
        if (expireConnectionLocked()) {
            if (result != nullptr) env->DeleteLocalRef(result);
            return env->NewStringUTF("ERROR_STATE");
        }
        lifecycle.stage = LifecycleStage::CHALLENGE_SIGNED;
    }
    return result;
}

static jstring JNICALL nativeSealConnectionReport(JNIEnv* env, jclass bridgeClass, jobject owner,
        jlong generation, jstring connectionContext, jstring fields, jstring serverPublic,
        jstring resolvedSources, jboolean advanced) {
    std::string context;
    std::string fieldsText;
    std::string serverText;
    std::string sourcesText;
    bool requestReadable = readUtf8(env, connectionContext, 1024, context)
            && readUtf8(env, fields, 16384, fieldsText)
            && readUtf8(env, serverPublic, 32768, serverText)
            && readUtf8(env, resolvedSources, 2 * 1024 * 1024, sourcesText);
    std::array<unsigned char, 32> requestDigest{};
    bool digestReady = requestReadable
            && digestRequest(fieldsText, serverText, sourcesText, advanced == JNI_TRUE, requestDigest);
    {
        std::lock_guard<std::mutex> lock(lifecycle.mutex);
        if (!ownerMatchesLocked(env, bridgeClass, owner)
                || lifecycle.generation != generation
                || !requestReadable
                || !digestReady
                || !constantTimeEqual(context, lifecycle.connectionContext)
                || expireConnectionLocked()
                || !validSessionTagLocked()) {
            cleanse(requestDigest);
            return env->NewStringUTF("ERROR_STATE");
        }
        if (lifecycle.stage == LifecycleStage::CONSUMED) {
            bool exactRetry = digestReady && lifecycle.cachedRequestReady
                    && GetCurrentThreadId() == lifecycle.sealThread
                    && CRYPTO_memcmp(requestDigest.data(), lifecycle.cachedRequest.data(), requestDigest.size()) == 0
                    && !lifecycle.cachedCiphertext.empty();
            cleanse(requestDigest);
            return exactRetry ? env->NewStringUTF(lifecycle.cachedCiphertext.c_str())
                    : env->NewStringUTF("ERROR_STATE");
        }
        if (lifecycle.stage != LifecycleStage::FABRIC_READY
                && lifecycle.stage != LifecycleStage::CHALLENGE_SIGNED) {
            cleanse(requestDigest);
            return env->NewStringUTF("ERROR_STATE");
        }
        DWORD currentThread = GetCurrentThreadId();
        if (lifecycle.sealThread == 0) lifecycle.sealThread = currentThread;
        if (currentThread != lifecycle.sealThread) {
            cleanse(requestDigest);
            return env->NewStringUTF("ERROR_STATE");
        }
        lifecycle.stage = LifecycleStage::REPORT_ACTIVE;
    }
    jstring result = sealPayloadCore(env, bridgeClass, fields, serverPublic, resolvedSources, advanced);
    std::string ciphertext;
    bool failed = result == nullptr || env->ExceptionCheck() || jstringIsError(env, result, &ciphertext);
    {
        std::lock_guard<std::mutex> lock(lifecycle.mutex);
        bool sameOperation = ownerMatchesLocked(env, bridgeClass, owner)
                && lifecycle.stage == LifecycleStage::REPORT_ACTIVE
                && lifecycle.generation == generation
                && constantTimeEqual(context, lifecycle.connectionContext)
                && validSessionTagLocked();
        if (!sameOperation) {
            cleanse(requestDigest);
            cleanse(ciphertext);
            if (env->ExceptionCheck()) return nullptr;
            if (result != nullptr) env->DeleteLocalRef(result);
            return env->NewStringUTF("ERROR_STATE");
        }
        if (failed) {
            cleanse(requestDigest);
            cleanse(ciphertext);
            clearConnectionLocked(LifecycleStage::INVALIDATED);
            return result == nullptr || env->ExceptionCheck() ? nullptr : result;
        }
        if (expireConnectionLocked()) {
            cleanse(requestDigest);
            cleanse(ciphertext);
            if (result != nullptr) env->DeleteLocalRef(result);
            return env->NewStringUTF("ERROR_STATE");
        }
        lifecycle.cachedRequest = requestDigest;
        lifecycle.cachedRequestReady = true;
        lifecycle.cachedCiphertext = ciphertext;
        lifecycle.stage = LifecycleStage::CONSUMED;
    }
    cleanse(requestDigest);
    cleanse(ciphertext);
    return result;
}

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    if (OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, nullptr) != 1) return JNI_ERR;
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_8) != JNI_OK || env == nullptr) {
        return JNI_ERR;
    }
#ifndef HIDDER_INPUT_VALIDATION
    if (!productionFingerprintIdentityValid()) return JNI_ERR;
    InitializeKeys();
    if (pClientKey == nullptr) return JNI_ERR;
    if (vm->GetEnv(reinterpret_cast<void**>(&lifecycleJvmti), JVMTI_VERSION_1_2) != JNI_OK
            || lifecycleJvmti == nullptr) return JNI_ERR;
    jvmtiCapabilities requested{};
    requested.can_get_bytecodes = 1;
    requested.can_get_constant_pool = 1;
    if (lifecycleJvmti->AddCapabilities(&requested) != JVMTI_ERROR_NONE) return JNI_ERR;
    jvmtiCapabilities actual{};
    if (lifecycleJvmti->GetCapabilities(&actual) != JVMTI_ERROR_NONE
            || !actual.can_get_bytecodes || !actual.can_get_constant_pool) return JNI_ERR;
#endif
    jclass bridge = env->FindClass("com/example/hidder/NativeBridge");
    if (bridge == nullptr) return JNI_ERR;
#ifndef HIDDER_INPUT_VALIDATION
    jclass loader = env->FindClass("com/example/hidder/NativeLibraryLoader");
    if (loader == nullptr || !productionBridgeFingerprintsMatch(bridge, loader)) {
        if (loader != nullptr) env->DeleteLocalRef(loader);
        env->DeleteLocalRef(bridge);
        return JNI_ERR;
    }
#endif
#ifdef HIDDER_INPUT_VALIDATION
    JNINativeMethod methods[] = {
        { const_cast<char*>("signChallenge"), const_cast<char*>("(Ljava/lang/String;J)Ljava/lang/String;"), reinterpret_cast<void*>(signChallengeCore) },
        { const_cast<char*>("sealPayload"), const_cast<char*>("(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)Ljava/lang/String;"), reinterpret_cast<void*>(sealPayloadCore) }
    };
#else
    JNINativeMethod methods[] = {
        { const_cast<char*>("nativeInitialize"), const_cast<char*>("(Lcom/example/hidder/HidderFabric;)Z"), reinterpret_cast<void*>(nativeInitialize) },
        { const_cast<char*>("nativeBeginConnection"), const_cast<char*>("(Lcom/example/hidder/HidderFabric;JLjava/lang/String;)Z"), reinterpret_cast<void*>(nativeBeginConnection) },
        { const_cast<char*>("nativeInvalidate"), const_cast<char*>("(Lcom/example/hidder/HidderFabric;J)V"), reinterpret_cast<void*>(nativeInvalidate) },
        { const_cast<char*>("nativeIsReady"), const_cast<char*>("(Lcom/example/hidder/HidderFabric;)Z"), reinterpret_cast<void*>(nativeIsReady) },
        { const_cast<char*>("nativeSignConnectionChallenge"), const_cast<char*>("(Lcom/example/hidder/HidderFabric;JLjava/lang/String;Ljava/lang/String;J)Ljava/lang/String;"), reinterpret_cast<void*>(nativeSignConnectionChallenge) },
        { const_cast<char*>("nativeSealConnectionReport"), const_cast<char*>("(Lcom/example/hidder/HidderFabric;JLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)Ljava/lang/String;"), reinterpret_cast<void*>(nativeSealConnectionReport) }
    };
#endif
    jint result = env->RegisterNatives(bridge, methods, sizeof(methods) / sizeof(methods[0]));
    env->DeleteLocalRef(bridge);
    if (result != 0) return JNI_ERR;
#ifndef HIDDER_INPUT_VALIDATION
    JNINativeMethod loaderMethods[] = {
        { const_cast<char*>("nativePruneStaleExtraction"), const_cast<char*>("(Ljava/lang/String;Ljava/lang/String;J[B)Z"), reinterpret_cast<void*>(nativePruneStaleExtraction) }
    };
    result = env->RegisterNatives(loader, loaderMethods, sizeof(loaderMethods) / sizeof(loaderMethods[0]));
    env->DeleteLocalRef(loader);
    if (result != 0) return JNI_ERR;
#endif
    return JNI_VERSION_1_8;
}

extern "C" JNIEXPORT void JNICALL JNI_OnUnload(JavaVM* vm, void*) {
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_8) != JNI_OK || env == nullptr) return;
    std::lock_guard<std::mutex> lock(lifecycle.mutex);
    releaseLifecycleRefsLocked(env);
    clearConnectionLocked(LifecycleStage::UNINITIALIZED);
    cleanse(lifecycle.processSecret);
    lifecycle.processSecretReady = false;
    lifecycle.fabricThread = 0;
    lifecycle.generation = 0;
    activeLoaderProfile.store(nullptr, std::memory_order_release);
#ifndef HIDDER_INPUT_VALIDATION
    if (lifecycleJvmti != nullptr) {
        lifecycleJvmti->DisposeEnvironment();
        lifecycleJvmti = nullptr;
    }
#endif
    if (pClientKey != nullptr) {
        EVP_PKEY_free(pClientKey);
        pClientKey = nullptr;
    }
}
