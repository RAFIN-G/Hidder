// SPDX-FileCopyrightText: 2002-2013 Mark Adler
// SPDX-FileCopyrightText: 2026 ModSeeker
// SPDX-License-Identifier: Zlib AND AGPL-3.0-or-later

/*
  Copyright (C) 2002-2013 Mark Adler, all rights reserved
  version 2.3, 21 Jan 2013

  This software is provided 'as-is', without any express or implied
  warranty.  In no event will the author be held liable for any damages
  arising from the use of this software.

  Permission is granted to anyone to use this software for any purpose,
  including commercial applications, and to alter it and redistribute it
  freely, subject to the following restrictions:

  1. The origin of this software must not be misrepresented; you must not
     claim that you wrote the original software. If you use this software
     in a product, an acknowledgment in the product documentation would be
     appreciated but is not required.
  2. Altered source versions must be plainly marked as such, and must not be
     misrepresented as being the original software.
  3. This notice may not be removed or altered from any source distribution.

  Mark Adler    madler@alumni.caltech.edu

  Altered source: C++ adaptation for Hidder; not the original puff distribution.
*/

#include <setjmp.h>
#include <cstring>

#define PF_MAXBITS 15
#define PF_MAXLCODES 286
#define PF_MAXDCODES 30
#define PF_MAXCODES (PF_MAXLCODES + PF_MAXDCODES)
#define PF_FIXLCODES 288

struct pf_state {
    unsigned char* out;
    unsigned long outlen;
    unsigned long outcnt;
    const unsigned char* in;
    unsigned long inlen;
    unsigned long incnt;
    int bitbuf;
    int bitcnt;
    jmp_buf env;
};

struct pf_huffman {
    short* count;
    short* symbol;
};

static int pf_bits(struct pf_state* s, int need) {
    long val = s->bitbuf;
    while (s->bitcnt < need) {
        if (s->incnt == s->inlen) longjmp(s->env, 1);
        val |= (long)(s->in[s->incnt++]) << s->bitcnt;
        s->bitcnt += 8;
    }
    s->bitbuf = (int)(val >> need);
    s->bitcnt -= need;
    return (int)(val & ((1L << need) - 1));
}
static int pf_stored(struct pf_state* s) {
    unsigned len;
    s->bitbuf = 0;
    s->bitcnt = 0;
    if (s->incnt + 4 > s->inlen) return 2;
    len = s->in[s->incnt++];
    len |= s->in[s->incnt++] << 8;
    if (s->in[s->incnt++] != (~len & 0xff) ||
        s->in[s->incnt++] != ((~len >> 8) & 0xff))
        return -2;
    if (s->incnt + len > s->inlen) return 2;
    if (s->out != NULL) {
        if (s->outcnt + len > s->outlen) return 1;
        while (len--) s->out[s->outcnt++] = s->in[s->incnt++];
    } else {
        s->outcnt += len;
        s->incnt += len;
    }
    return 0;
}

static int pf_decode(struct pf_state* s, const struct pf_huffman* h) {
    int len, code, first, count, index;
    code = first = index = 0;
    for (len = 1; len <= PF_MAXBITS; len++) {
        code |= pf_bits(s, 1);
        count = h->count[len];
        if (code - count < first) return h->symbol[index + (code - first)];
        index += count;
        first += count;
        first <<= 1;
        code <<= 1;
    }
    return -10;
}

static int pf_construct(struct pf_huffman* h, const short* length, int n) {
    int symbol, len, left;
    short offs[PF_MAXBITS + 1];
    for (len = 0; len <= PF_MAXBITS; len++) h->count[len] = 0;
    for (symbol = 0; symbol < n; symbol++) (h->count[length[symbol]])++;
    if (h->count[0] == n) return 0;
    left = 1;
    for (len = 1; len <= PF_MAXBITS; len++) {
        left <<= 1;
        left -= h->count[len];
        if (left < 0) return left;
    }
    offs[1] = 0;
    for (len = 1; len < PF_MAXBITS; len++) offs[len + 1] = offs[len] + h->count[len];
    for (symbol = 0; symbol < n; symbol++)
        if (length[symbol] != 0) h->symbol[offs[length[symbol]]++] = symbol;
    return left;
}

static int pf_codes(struct pf_state* s, const struct pf_huffman* lencode, const struct pf_huffman* distcode) {
    static const short lens[29] = { 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
        35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258 };
    static const short lext[29] = { 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
        3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0 };
    static const short dists[30] = { 1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
        257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577 };
    static const short dext[30] = { 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
        7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13 };
    int symbol, len;
    unsigned dist;
    for (;;) {
        symbol = pf_decode(s, lencode);
        if (symbol < 0) return symbol;
        if (symbol < 256) {
            if (s->out != NULL) {
                if (s->outcnt == s->outlen) return 1;
                s->out[s->outcnt] = (unsigned char)symbol;
            }
            s->outcnt++;
        } else if (symbol > 256) {
            symbol -= 257;
            if (symbol >= 29) return -10;
            len = lens[symbol] + pf_bits(s, lext[symbol]);
            symbol = pf_decode(s, distcode);
            if (symbol < 0) return symbol;
            dist = dists[symbol] + pf_bits(s, dext[symbol]);
            if (dist > s->outcnt) return -11;
            if (s->out != NULL) {
                if (s->outcnt + len > s->outlen) return 1;
                while (len--) {
                    s->out[s->outcnt] = s->out[s->outcnt - dist];
                    s->outcnt++;
                }
            } else {
                s->outcnt += len;
            }
        } else {
            break;
        }
    }
    return 0;
}

static int pf_fixed(struct pf_state* s) {
    static int virgin = 1;
    static short lencnt[PF_MAXBITS + 1], lensym[PF_FIXLCODES];
    static short distcnt[PF_MAXBITS + 1], distsym[PF_MAXDCODES];
    static struct pf_huffman lencode, distcode;
    if (virgin) {
        int symbol;
        short lengths[PF_FIXLCODES];
        lencode.count = lencnt; lencode.symbol = lensym;
        distcode.count = distcnt; distcode.symbol = distsym;
        for (symbol = 0; symbol < 144; symbol++) lengths[symbol] = 8;
        for (; symbol < 256; symbol++) lengths[symbol] = 9;
        for (; symbol < 280; symbol++) lengths[symbol] = 7;
        for (; symbol < PF_FIXLCODES; symbol++) lengths[symbol] = 8;
        pf_construct(&lencode, lengths, PF_FIXLCODES);
        for (symbol = 0; symbol < PF_MAXDCODES; symbol++) lengths[symbol] = 5;
        pf_construct(&distcode, lengths, PF_MAXDCODES);
        virgin = 0;
    }
    return pf_codes(s, &lencode, &distcode);
}

static int pf_dynamic(struct pf_state* s) {
    static const short order[19] = { 16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15 };
    int nlen, ndist, ncode, index, err;
    short lengths[PF_MAXCODES];
    short lencnt[PF_MAXBITS + 1], lensym[PF_MAXLCODES];
    short distcnt[PF_MAXBITS + 1], distsym[PF_MAXDCODES];
    struct pf_huffman lencode, distcode;
    lencode.count = lencnt; lencode.symbol = lensym;
    distcode.count = distcnt; distcode.symbol = distsym;
    nlen = pf_bits(s, 5) + 257;
    ndist = pf_bits(s, 5) + 1;
    ncode = pf_bits(s, 4) + 4;
    if (nlen > PF_MAXLCODES || ndist > PF_MAXDCODES) return -3;
    for (index = 0; index < ncode; index++) lengths[order[index]] = (short)pf_bits(s, 3);
    for (; index < 19; index++) lengths[order[index]] = 0;
    err = pf_construct(&lencode, lengths, 19);
    if (err != 0) return -4;
    index = 0;
    while (index < nlen + ndist) {
        int symbol, len;
        symbol = pf_decode(s, &lencode);
        if (symbol < 0) return symbol;
        if (symbol < 16) {
            lengths[index++] = (short)symbol;
        } else {
            len = 0;
            if (symbol == 16) {
                if (index == 0) return -5;
                len = lengths[index - 1];
                symbol = 3 + pf_bits(s, 2);
            } else if (symbol == 17) {
                symbol = 3 + pf_bits(s, 3);
            } else {
                symbol = 11 + pf_bits(s, 7);
            }
            if (index + symbol > nlen + ndist) return -6;
            while (symbol--) lengths[index++] = (short)len;
        }
    }
    if (lengths[256] == 0) return -9;
    err = pf_construct(&lencode, lengths, nlen);
    if (err && (err < 0 || nlen != lencode.count[0] + lencode.count[1])) return -7;
    err = pf_construct(&distcode, lengths + nlen, ndist);
    if (err && (err < 0 || ndist != distcode.count[0] + distcode.count[1])) return -8;
    return pf_codes(s, &lencode, &distcode);
}

int pf_inflate(unsigned char* dest, unsigned long* destlen,
                      const unsigned char* source, unsigned long sourcelen) {
    struct pf_state s;
    int last, type, err;
    s.out = dest;
    s.outlen = *destlen;
    s.outcnt = 0;
    s.in = source;
    s.inlen = sourcelen;
    s.incnt = 0;
    s.bitbuf = 0;
    s.bitcnt = 0;
    if (setjmp(s.env) != 0) {
        err = 2;
    } else {
        do {
            last = pf_bits(&s, 1);
            type = pf_bits(&s, 2);
            err = type == 0 ? pf_stored(&s) :
                  (type == 1 ? pf_fixed(&s) :
                  (type == 2 ? pf_dynamic(&s) : -1));
            if (err != 0) break;
        } while (!last);
    }
    if (err <= 0) *destlen = s.outcnt;
    return err;
}
