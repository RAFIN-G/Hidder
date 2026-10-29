#pragma once

#include <cstddef>

struct LoaderIntegrityProfile {
    const char* version;
    const char* mixinExtrasIdentity;
    unsigned char mixinExtrasDigest[64];
    unsigned char classes[6][32];
};

static inline const LoaderIntegrityProfile* selectLoaderIntegrityProfile(
        const unsigned char (&actual)[6][32], const LoaderIntegrityProfile* profiles, size_t count) {
    if (profiles == nullptr || count == 0 || count > 16) return nullptr;
    const LoaderIntegrityProfile* selected = nullptr;
    for (size_t profile = 0; profile < count; profile++) {
        unsigned int difference = 0;
        for (size_t type = 0; type < 6; type++) {
            for (size_t byte = 0; byte < 32; byte++) {
                difference |= actual[type][byte] ^ profiles[profile].classes[type][byte];
            }
        }
        if (difference == 0) {
            if (selected != nullptr) return nullptr;
            selected = &profiles[profile];
        }
    }
    return selected;
}
