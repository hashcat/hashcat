/*-
 * Copyright 2013-2018 Alexander Peslyak
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdint.h>
#include <string.h>

#include "insecure_memzero.h"
#include "sha256.h"

#define YESCRYPT_INTERNAL
#include "yescrypt.h"

#define BYTES2CHARS(bytes) ((((bytes) * 8) + 5) / 6)

#define HASH_SIZE sizeof(yescrypt_binary_t) /* bytes */
#define HASH_LEN BYTES2CHARS(HASH_SIZE) /* base-64 chars */

/*
 * "$y$", up to 8 params of up to 6 chars each, '$', salt
 * Alternatively, but that's smaller:
 * "$7$", 3 params encoded as 1+5+5 chars, salt
 */
#define PREFIX_LEN (3 + 8 * 6 + 1 + BYTES2CHARS(32))

static const char * const itoa64 =
	"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

static const uint8_t atoi64_partial[77] = {
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
	64, 64, 64, 64, 64, 64, 64,
	12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
	25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37,
	64, 64, 64, 64, 64, 64,
	38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
	51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63
};

static uint8_t *encode64_uint32(uint8_t *dst, size_t dstlen,
    uint32_t src, uint32_t min)
{
	uint32_t start = 0, end = 47, chars = 1, bits = 0;

	if (src < min)
		return NULL;
	src -= min;

	do {
		uint32_t count = (end + 1 - start) << bits;
		if (src < count)
			break;
		if (start >= 63)
			return NULL;
		start = end + 1;
		end = start + (62 - end) / 2;
		src -= count;
		chars++;
		bits += 6;
	} while (1);

	if (dstlen <= chars) /* require room for a NUL terminator */
		return NULL;

	*dst++ = itoa64[start + (src >> bits)];

	while (--chars) {
		bits -= 6;
		*dst++ = itoa64[(src >> bits) & 0x3f];
	}

	*dst = 0; /* NUL terminate just in case */

	return dst;
}

static inline uint32_t atoi64(uint8_t src)
{
	if (src >= '.' && src <= 'z')
		return atoi64_partial[src - '.'];

	return 64;
}

static const uint8_t *decode64_uint32(uint32_t *dst,
    const uint8_t *src, uint32_t min)
{
	uint32_t start = 0, end = 47, chars = 1, bits = 0;
	uint32_t c;

	c = atoi64(*src++);
	if (c > 63)
		goto fail;

	*dst = min;
	while (c > end) {
		*dst += (end + 1 - start) << bits;
		start = end + 1;
		end = start + (62 - end) / 2;
		chars++;
		bits += 6;
	}

	*dst += (c - start) << bits;

	while (--chars) {
		c = atoi64(*src++);
		if (c > 63)
			goto fail;
		bits -= 6;
		*dst += c << bits;
	}

	return src;

fail:
	*dst = 0;
	return NULL;
}

static uint8_t *encode64_uint32_fixed(uint8_t *dst, size_t dstlen,
    uint32_t src, uint32_t srcbits)
{
	uint32_t bits;

	for (bits = 0; bits < srcbits; bits += 6) {
		if (dstlen < 2)
			return NULL;
		*dst++ = itoa64[src & 0x3f];
		dstlen--;
		src >>= 6;
	}

	if (src || dstlen < 1)
		return NULL;

	*dst = 0; /* NUL terminate just in case */

	return dst;
}

static uint8_t *encode64(uint8_t *dst, size_t dstlen,
    const uint8_t *src, size_t srclen)
{
	size_t i;

	for (i = 0; i < srclen; ) {
		uint8_t *dnext;
		uint32_t value = 0, bits = 0;
		do {
			value |= (uint32_t)src[i++] << bits;
			bits += 8;
		} while (bits < 24 && i < srclen);
		dnext = encode64_uint32_fixed(dst, dstlen, value, bits);
		if (!dnext)
			return NULL;
		dstlen -= dnext - dst;
		dst = dnext;
	}

	if (dstlen < 1)
		return NULL;

	*dst = 0; /* NUL terminate just in case */

	return dst;
}

static const uint8_t *decode64_uint32_fixed(uint32_t *dst, uint32_t dstbits,
    const uint8_t *src)
{
	uint32_t bits;

	*dst = 0;
	for (bits = 0; bits < dstbits; bits += 6) {
		uint32_t c = atoi64(*src++);
		if (c > 63) {
			*dst = 0;
			return NULL;
		}
		*dst |= c << bits;
	}

	return src;
}

static const uint8_t *decode64(uint8_t *dst, size_t *dstlen,
    const uint8_t *src, size_t srclen)
{
	size_t dstpos = 0;

	while (dstpos <= *dstlen && srclen) {
		uint32_t value = 0, bits = 0;
		while (srclen--) {
			uint32_t c = atoi64(*src);
			if (c > 63) {
				srclen = 0;
				break;
			}
			src++;
			value |= c << bits;
			bits += 6;
			if (bits >= 24)
				break;
		}
		if (!bits)
			break;
		if (bits < 12) /* must have at least one full byte */
			goto fail;
		while (dstpos++ < *dstlen) {
			*dst++ = value;
			value >>= 8;
			bits -= 8;
			if (bits < 8) { /* 2 or 4 */
				if (value) /* must be 0 */
					goto fail;
				bits = 0;
				break;
			}
		}
		if (bits)
			goto fail;
	}

	if (!srclen && dstpos <= *dstlen) {
		*dstlen = dstpos;
		return src;
	}

fail:
	*dstlen = 0;
	return NULL;
}

typedef enum { ENC = 1, DEC = -1 } encrypt_dir_t;

static void memxor(unsigned char *dst, unsigned char *src, size_t size)
{
	while (size--)
		*dst++ ^= *src++;
}

static void encrypt(unsigned char *data, size_t datalen,
    const yescrypt_binary_t *key, encrypt_dir_t dir)
{
	SHA256_CTX ctx;
	unsigned char f[32 + 4];
	size_t halflen, which;
	unsigned char mask, round, target;

	if (!datalen)
		return;
	if (datalen > 64)
		datalen = 64;

	halflen = datalen >> 1;

	which = 0; /* offset to half we are working on (0 or halflen) */
	mask = 0x0f; /* current half's extra nibble mask if datalen is odd */

	round = 0;
	target = 5; /* 6 rounds due to Jacques Patarin's CRYPTO 2004 paper */

	if (dir == DEC) {
		which = halflen; /* even round count, so swap the halves */
		mask ^= 0xff;

		round = target;
		target = 0;
	}

	f[32] = 0;
	f[33] = sizeof(*key);
	f[34] = datalen;

	do {
		SHA256_Init(&ctx);
		f[35] = round;
		SHA256_Update(&ctx, &f[32], 4);
		SHA256_Update(&ctx, key, sizeof(*key));
		SHA256_Update(&ctx, &data[which], halflen);
		if (datalen & 1) {
			f[0] = data[datalen - 1] & mask;
			SHA256_Update(&ctx, f, 1);
		}
		SHA256_Final(f, &ctx);
		which ^= halflen;
		memxor(&data[which], f, halflen);
		if (datalen & 1) {
			mask ^= 0xff;
			data[datalen - 1] ^= f[halflen] & mask;
		}
		if (round == target)
			break;
		round += dir;
	} while (1);

	/* ctx is presumably zeroized by SHA256_Final() */
	insecure_memzero(f, sizeof(f));
}

uint8_t *yescrypt_r(const yescrypt_shared_t *shared, yescrypt_local_t *local,
    const uint8_t *passwd, size_t passwdlen,
    const uint8_t *setting,
    const yescrypt_binary_t *key,
    uint8_t *buf, size_t buflen)
{
	unsigned char saltbin[64], hashbin[32];
	const uint8_t *src, *saltstr, *salt;
	uint8_t *dst;
	size_t need, prefixlen, saltstrlen, saltlen;
	yescrypt_params_t params = { .p = 1 };

	if (setting[0] != '$' ||
	    (setting[1] != '7' && setting[1] != 'y') ||
	    setting[2] != '$')
		return NULL;
	src = setting + 3;

	if (setting[1] == '7') {
		uint32_t N_log2 = atoi64(*src++);
		if (N_log2 < 1 || N_log2 > 63)
			return NULL;
		params.N = (uint64_t)1 << N_log2;

		src = decode64_uint32_fixed(&params.r, 30, src);
		if (!src)
			return NULL;

		src = decode64_uint32_fixed(&params.p, 30, src);
		if (!src)
			return NULL;

		if (key)
			return NULL;
	} else {
		uint32_t flavor, N_log2;

		src = decode64_uint32(&flavor, src, 0);
		if (!src)
			return NULL;

		if (flavor < YESCRYPT_RW) {
			params.flags = flavor;
		} else if (flavor <= YESCRYPT_RW + (YESCRYPT_RW_FLAVOR_MASK >> 2)) {
			params.flags = YESCRYPT_RW + ((flavor - YESCRYPT_RW) << 2);
		} else {
			return NULL;
		}

		src = decode64_uint32(&N_log2, src, 1);
		if (!src || N_log2 > 63)
			return NULL;
		params.N = (uint64_t)1 << N_log2;

		src = decode64_uint32(&params.r, src, 1);
		if (!src)
			return NULL;

		if (*src != '$') {
			uint32_t have;

			src = decode64_uint32(&have, src, 1);
			if (!src)
				return NULL;

			if (have & 1) {
				src = decode64_uint32(&params.p, src, 2);
				if (!src)
					return NULL;
			}

			if (have & 2) {
				src = decode64_uint32(&params.t, src, 1);
				if (!src)
					return NULL;
			}

			if (have & 4) {
				src = decode64_uint32(&params.g, src, 1);
				if (!src)
					return NULL;
			}

			if (have & 8) {
				uint32_t NROM_log2;
				src = decode64_uint32(&NROM_log2, src, 1);
				if (!src || NROM_log2 > 63)
					return NULL;
				params.NROM = (uint64_t)1 << NROM_log2;
			}
		}

		if (*src++ != '$')
			return NULL;
	}

	prefixlen = src - setting;

	saltstr = src;
	src = (uint8_t *)strrchr((char *)saltstr, '$');
	if (src)
		saltstrlen = src - saltstr;
	else
		saltstrlen = strlen((char *)saltstr);

	if (setting[1] == '7') {
		salt = saltstr;
		saltlen = saltstrlen;
	} else {
		const uint8_t *saltend;

		saltlen = sizeof(saltbin);
		saltend = decode64(saltbin, &saltlen, saltstr, saltstrlen);

		if (!saltend || (size_t)(saltend - saltstr) != saltstrlen)
			goto fail;

		salt = saltbin;

		if (key)
			encrypt(saltbin, saltlen, key, ENC);
	}

	need = prefixlen + saltstrlen + 1 + HASH_LEN + 1;
	if (need > buflen || need < saltstrlen)
		goto fail;

	if (yescrypt_kdf(shared, local, passwd, passwdlen, salt, saltlen,
	    &params, hashbin, sizeof(hashbin)))
		goto fail;

	if (key) {
		insecure_memzero(saltbin, sizeof(saltbin));
		encrypt(hashbin, sizeof(hashbin), key, ENC);
	}

	dst = buf;
	memcpy(dst, setting, prefixlen + saltstrlen);
	dst += prefixlen + saltstrlen;
	*dst++ = '$';

	dst = encode64(dst, buflen - (dst - buf), hashbin, sizeof(hashbin));
	insecure_memzero(hashbin, sizeof(hashbin));
	if (!dst || dst >= buf + buflen)
		return NULL;

	*dst = 0; /* NUL termination */

	return buf;

fail:
	insecure_memzero(saltbin, sizeof(saltbin));
	insecure_memzero(hashbin, sizeof(hashbin));
	return NULL;
}

uint8_t *yescrypt(const uint8_t *passwd, const uint8_t *setting)
{
	/* prefix, '$', hash, NUL */
	static uint8_t buf[PREFIX_LEN + 1 + HASH_LEN + 1];
	yescrypt_local_t local;
	uint8_t *retval;

	if (yescrypt_init_local(&local))
		return NULL;
	retval = yescrypt_r(NULL, &local,
	    passwd, strlen((char *)passwd), setting, NULL, buf, sizeof(buf));
	if (yescrypt_free_local(&local))
		return NULL;
	return retval;
}

uint8_t *yescrypt_reencrypt(uint8_t *hash,
    const yescrypt_binary_t *from_key,
    const yescrypt_binary_t *to_key)
{
	uint8_t *retval = NULL, *saltstart, *hashstart;
	const uint8_t *hashend;
	unsigned char saltbin[64], hashbin[32];
	size_t saltstrlen, saltlen = 0, hashlen;

	if (strncmp((char *)hash, "$y$", 3))
		return NULL;

	saltstart = NULL;
	hashstart = (uint8_t *)strrchr((char *)hash, '$');
	if (hashstart) {
		if (hashstart > (uint8_t *)hash) {
			saltstart = hashstart - 1;
			while (*saltstart != '$' && saltstart > hash)
				saltstart--;
			if (*saltstart == '$')
				saltstart++;
		}
		hashstart++;
	} else {
		hashstart = hash;
	}
	saltstrlen = saltstart ? (hashstart - 1 - saltstart) : 0;
	if (saltstrlen > BYTES2CHARS(64) ||
	    strlen((char *)hashstart) != HASH_LEN)
		return NULL;

	if (saltstrlen) {
		const uint8_t *saltend;
		saltlen = sizeof(saltbin);
		saltend = decode64(saltbin, &saltlen, saltstart, saltstrlen);
		if (!saltend || *saltend != '$' || saltlen < 1 || saltlen > 64)
			goto out;

		if (from_key)
			encrypt(saltbin, saltlen, from_key, ENC);
		if (to_key)
			encrypt(saltbin, saltlen, to_key, DEC);
	}

	hashlen = sizeof(hashbin);
	hashend = decode64(hashbin, &hashlen, hashstart, HASH_LEN);
	if (!hashend || *hashend || hashlen != sizeof(hashbin))
		goto out;

	if (from_key)
		encrypt(hashbin, hashlen, from_key, DEC);
	if (to_key)
		encrypt(hashbin, hashlen, to_key, ENC);

	if (saltstrlen) {
		if (!encode64(saltstart, saltstrlen + 1, saltbin, saltlen))
			goto out; /* can't happen */
		*(saltstart + saltstrlen) = '$';
	}

	if (!encode64(hashstart, HASH_LEN + 1, hashbin, hashlen))
		goto out; /* can't happen */

	retval = hash;

out:
	insecure_memzero(saltbin, sizeof(saltbin));
	insecure_memzero(hashbin, sizeof(hashbin));

	return retval;
}

static uint32_t N2log2(uint64_t N)
{
	uint32_t N_log2;

	if (N < 2)
		return 0;

	N_log2 = 2;
	while (N >> N_log2 != 0)
		N_log2++;
	N_log2--;

	if (N >> N_log2 != 1)
		return 0;

	return N_log2;
}

uint8_t *yescrypt_encode_params_r(const yescrypt_params_t *params,
    const uint8_t *src, size_t srclen,
    uint8_t *buf, size_t buflen)
{
	uint32_t flavor, N_log2, NROM_log2, have;
	uint8_t *dst;

	if (srclen > SIZE_MAX / 16)
		return NULL;

	if (params->flags < YESCRYPT_RW) {
		flavor = params->flags;
	} else if ((params->flags & YESCRYPT_MODE_MASK) == YESCRYPT_RW &&
	    params->flags <= (YESCRYPT_RW | YESCRYPT_RW_FLAVOR_MASK)) {
		flavor = YESCRYPT_RW + (params->flags >> 2);
	} else {
		return NULL;
	}

	N_log2 = N2log2(params->N);
	if (!N_log2)
		return NULL;

	NROM_log2 = N2log2(params->NROM);
	if (params->NROM && !NROM_log2)
		return NULL;

	if ((uint64_t)params->r * (uint64_t)params->p >= (1U << 30))
		return NULL;

	dst = buf;
	*dst++ = '$';
	*dst++ = 'y';
	*dst++ = '$';

	dst = encode64_uint32(dst, buflen - (dst - buf), flavor, 0);
	if (!dst)
		return NULL;

	dst = encode64_uint32(dst, buflen - (dst - buf), N_log2, 1);
	if (!dst)
		return NULL;

	dst = encode64_uint32(dst, buflen - (dst - buf), params->r, 1);
	if (!dst)
		return NULL;

	have = 0;
	if (params->p != 1)
		have |= 1;
	if (params->t)
		have |= 2;
	if (params->g)
		have |= 4;
	if (NROM_log2)
		have |= 8;

	if (have) {
		dst = encode64_uint32(dst, buflen - (dst - buf), have, 1);
		if (!dst)
			return NULL;
	}

	if (params->p != 1) {
		dst = encode64_uint32(dst, buflen - (dst - buf), params->p, 2);
		if (!dst)
			return NULL;
	}

	if (params->t) {
		dst = encode64_uint32(dst, buflen - (dst - buf), params->t, 1);
		if (!dst)
			return NULL;
	}

	if (params->g) {
		dst = encode64_uint32(dst, buflen - (dst - buf), params->g, 1);
		if (!dst)
			return NULL;
	}

	if (NROM_log2) {
		dst = encode64_uint32(dst, buflen - (dst - buf), NROM_log2, 1);
		if (!dst)
			return NULL;
	}

	if (dst >= buf + buflen)
		return NULL;

	*dst++ = '$';

	dst = encode64(dst, buflen - (dst - buf), src, srclen);
	if (!dst || dst >= buf + buflen)
		return NULL;

	*dst = 0; /* NUL termination */

	return buf;
}

uint8_t *yescrypt_encode_params(const yescrypt_params_t *params,
    const uint8_t *src, size_t srclen)
{
	/* prefix, NUL */
	static uint8_t buf[PREFIX_LEN + 1];
	return yescrypt_encode_params_r(params, src, srclen, buf, sizeof(buf));
}

int crypto_scrypt(const uint8_t *passwd, size_t passwdlen,
    const uint8_t *salt, size_t saltlen, uint64_t N, uint32_t r, uint32_t p,
    uint8_t *buf, size_t buflen)
{
	yescrypt_local_t local;
	yescrypt_params_t params = { .flags = 0, .N = N, .r = r, .p = p };
	int retval;

	if (yescrypt_init_local(&local))
		return -1;
	retval = yescrypt_kdf(NULL, &local,
	    passwd, passwdlen, salt, saltlen, &params, buf, buflen);
	if (yescrypt_free_local(&local))
		return -1;
	return retval;
}
