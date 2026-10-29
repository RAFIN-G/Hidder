// SPDX-FileCopyrightText: 2026 ModSeeker
// SPDX-License-Identifier: AGPL-3.0-or-later

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

class MetadataJsonReader {
public:
    explicit MetadataJsonReader(const std::string& source) : source(source), position(0) {}

    bool parse(std::string& id, std::string& version, std::vector<std::string>* nestedFiles = nullptr) {
        id.clear();
        version.clear();
        std::vector<std::string> ignoredNested;
        std::vector<std::string>& nested = nestedFiles == nullptr ? ignoredNested : *nestedFiles;
        nested.clear();
        space();
        if (!take('{')) return false;
        space();
        bool foundId = false;
        bool foundVersion = false;
        bool foundJars = false;
        if (take('}')) return false;
        for (;;) {
            std::string key;
            if (!parseString(&key)) return false;
            space();
            if (!take(':')) return false;
            space();
            if (key == "id") {
                if (foundId || !parseString(&id)) return false;
                foundId = true;
            } else if (key == "version") {
                if (foundVersion || !parseString(&version)) return false;
                foundVersion = true;
            } else if (key == "jars") {
                if (foundJars || !parseJars(nested)) return false;
                foundJars = true;
            } else if (!parseValue(1)) {
                return false;
            }
            space();
            if (take('}')) break;
            if (!take(',')) return false;
            space();
        }
        space();
        return position == source.size() && foundId && foundVersion
            && validId(id) && validVersion(version);
    }

private:
    const std::string& source;
    std::size_t position;

    void space() {
        while (position < source.size()) {
            char c = source[position];
            if (c != ' ' && c != '\t' && c != '\r' && c != '\n') break;
            ++position;
        }
    }

    bool take(char expected) {
        if (position >= source.size() || source[position] != expected) return false;
        ++position;
        return true;
    }

    static int hexDigit(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    bool hex4(std::uint32_t& value) {
        value = 0;
        for (int i = 0; i < 4; ++i) {
            if (position >= source.size()) return false;
            int digit = hexDigit(source[position++]);
            if (digit < 0) return false;
            value = (value << 4) | static_cast<std::uint32_t>(digit);
        }
        return true;
    }

    static void appendUtf8(std::string& output, std::uint32_t codepoint) {
        if (codepoint <= 0x7F) {
            output.push_back(static_cast<char>(codepoint));
        } else if (codepoint <= 0x7FF) {
            output.push_back(static_cast<char>(0xC0 | (codepoint >> 6)));
            output.push_back(static_cast<char>(0x80 | (codepoint & 0x3F)));
        } else if (codepoint <= 0xFFFF) {
            output.push_back(static_cast<char>(0xE0 | (codepoint >> 12)));
            output.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3F)));
            output.push_back(static_cast<char>(0x80 | (codepoint & 0x3F)));
        } else {
            output.push_back(static_cast<char>(0xF0 | (codepoint >> 18)));
            output.push_back(static_cast<char>(0x80 | ((codepoint >> 12) & 0x3F)));
            output.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3F)));
            output.push_back(static_cast<char>(0x80 | (codepoint & 0x3F)));
        }
    }

    bool parseString(std::string* output) {
        if (!take('"')) return false;
        while (position < source.size()) {
            unsigned char c = static_cast<unsigned char>(source[position++]);
            if (c == '"') return true;
            if (c < 0x20) return false;
            if (c != '\\') {
                if (output) output->push_back(static_cast<char>(c));
            } else {
                if (position >= source.size()) return false;
                char escaped = source[position++];
                char decoded = 0;
                switch (escaped) {
                    case '"': decoded = '"'; break;
                    case '\\': decoded = '\\'; break;
                    case '/': decoded = '/'; break;
                    case 'b': decoded = '\b'; break;
                    case 'f': decoded = '\f'; break;
                    case 'n': decoded = '\n'; break;
                    case 'r': decoded = '\r'; break;
                    case 't': decoded = '\t'; break;
                    case 'u': {
                        std::uint32_t codepoint;
                        if (!hex4(codepoint)) return false;
                        if (codepoint >= 0xD800 && codepoint <= 0xDBFF) {
                            if (!take('\\') || !take('u')) return false;
                            std::uint32_t low;
                            if (!hex4(low) || low < 0xDC00 || low > 0xDFFF) return false;
                            codepoint = 0x10000 + ((codepoint - 0xD800) << 10) + (low - 0xDC00);
                        } else if (codepoint >= 0xDC00 && codepoint <= 0xDFFF) {
                            return false;
                        }
                        if (output) appendUtf8(*output, codepoint);
                        break;
                    }
                    default: return false;
                }
                if (escaped != 'u' && output) output->push_back(decoded);
            }
            if (output && output->size() > 4096) return false;
        }
        return false;
    }

    bool parseValue(int depth) {
        if (depth > 32 || position >= source.size()) return false;
        char c = source[position];
        if (c == '"') return parseString(nullptr);
        if (c == '{') return parseObject(depth + 1);
        if (c == '[') return parseArray(depth + 1);
        if (c == 't') return literal("true");
        if (c == 'f') return literal("false");
        if (c == 'n') return literal("null");
        return parseNumber();
    }

    bool parseObject(int depth) {
        if (!take('{')) return false;
        space();
        if (take('}')) return true;
        for (;;) {
            if (!parseString(nullptr)) return false;
            space();
            if (!take(':')) return false;
            space();
            if (!parseValue(depth)) return false;
            space();
            if (take('}')) return true;
            if (!take(',')) return false;
            space();
        }
    }

    bool parseArray(int depth) {
        if (!take('[')) return false;
        space();
        if (take(']')) return true;
        for (;;) {
            if (!parseValue(depth)) return false;
            space();
            if (take(']')) return true;
            if (!take(',')) return false;
            space();
        }
    }

    bool parseJars(std::vector<std::string>& nested) {
        if (!take('[')) return false;
        space();
        if (take(']')) return true;
        for (;;) {
            if (nested.size() >= 256 || !take('{')) return false;
            space();
            bool foundFile = false;
            std::string path;
            if (take('}')) return false;
            for (;;) {
                std::string key;
                if (!parseString(&key)) return false;
                space();
                if (!take(':')) return false;
                space();
                if (key == "file") {
                    if (foundFile || !parseString(&path)) return false;
                    foundFile = true;
                } else if (!parseValue(2)) {
                    return false;
                }
                space();
                if (take('}')) break;
                if (!take(',')) return false;
                space();
            }
            if (!foundFile || !validJarPath(path)) return false;
            for (const std::string& previous : nested) {
                if (previous == path) return false;
            }
            nested.push_back(path);
            space();
            if (take(']')) return true;
            if (!take(',')) return false;
            space();
        }
    }

    bool literal(const char* expected) {
        std::size_t length = std::char_traits<char>::length(expected);
        if (source.compare(position, length, expected) != 0) return false;
        position += length;
        return true;
    }

    static bool digit(char c) {
        return c >= '0' && c <= '9';
    }

    bool parseNumber() {
        if (take('-') && position >= source.size()) return false;
        if (take('0')) {
            if (position < source.size() && digit(source[position])) return false;
        } else {
            if (position >= source.size() || source[position] < '1' || source[position] > '9') return false;
            do { ++position; } while (position < source.size() && digit(source[position]));
        }
        if (take('.')) {
            if (position >= source.size() || !digit(source[position])) return false;
            do { ++position; } while (position < source.size() && digit(source[position]));
        }
        if (take('e') || take('E')) {
            if (!take('+')) take('-');
            if (position >= source.size() || !digit(source[position])) return false;
            do { ++position; } while (position < source.size() && digit(source[position]));
        }
        return true;
    }

    static bool validId(const std::string& id) {
        if (id.empty() || id.size() > 64 || id[0] < 'a' || id[0] > 'z') return false;
        for (char c : id) {
            if (!((c >= 'a' && c <= 'z') || digit(c) || c == '_' || c == '-')) return false;
        }
        return true;
    }

    static bool validVersion(const std::string& version) {
        if (version.empty() || version.size() > 128) return false;
        for (unsigned char c : version) {
            if (c < 0x20 || c == '|' || c == ',') return false;
        }
        return true;
    }

    static bool validJarPath(const std::string& path) {
        if (path.empty() || path.size() > 512 || path[0] == '/') return false;
        std::size_t start = 0;
        for (std::size_t i = 0; i <= path.size(); ++i) {
            if (i < path.size()) {
                unsigned char c = static_cast<unsigned char>(path[i]);
                if (c < 0x20 || c == '\\' || c == ':') return false;
            }
            if (i == path.size() || path[i] == '/') {
                std::string segment = path.substr(start, i - start);
                if (segment.empty() || segment == "." || segment == "..") return false;
                start = i + 1;
            }
        }
        return true;
    }
};
