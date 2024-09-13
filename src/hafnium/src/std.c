/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/std.h"

#include "hf/check.h"

/* Declare unsafe functions locally so they are not available globally. */
void *memset(void *s, int c, size_t n);
void *memcpy(void *dst, const void *src, size_t n);
void *memmove(void *dst, const void *src, size_t n);

/*
 * As per the C11 specification, mem*_s() operations fill the destination buffer
 * if runtime constraint validation fails, assuming that `dest` and `destsz`
 * are both valid.
 */
#define CHECK_OR_FILL(cond, dest, destsz, ch)                               \
	do {                                                                \
		if (!(cond)) {                                              \
			if ((dest) != NULL && (destsz) <= RSIZE_MAX) {      \
				memset_s((dest), (destsz), (ch), (destsz)); \
			}                                                   \
			panic("%s failed: " #cond, __func__);               \
		}                                                           \
	} while (0)

#define CHECK_OR_ZERO_FILL(cond, dest, destsz) \
	CHECK_OR_FILL(cond, dest, destsz, '\0')

void memset_s(void *dest, rsize_t destsz, int ch, rsize_t count)
{
	if (dest == NULL || destsz > RSIZE_MAX) {
		panic("memset_s failed as either dest == NULL "
		      "or destsz > RSIZE_MAX.\n");
	}

	/*
	 * Clang analyzer doesn't like us calling unsafe memory functions, so
	 * make it ignore this call.
	 */
	// NOLINTNEXTLINE
	memset(dest, ch, (count <= destsz ? count : destsz));
}

void memcpy_s(void *dest, rsize_t destsz, const void *src, rsize_t count)
{
	uintptr_t d = (uintptr_t)dest;
	uintptr_t s = (uintptr_t)src;

	CHECK_OR_ZERO_FILL(dest != NULL, dest, destsz);
	CHECK_OR_ZERO_FILL(src != NULL, dest, destsz);

	/* Check count <= destsz <= RSIZE_MAX. */
	CHECK_OR_ZERO_FILL(destsz <= RSIZE_MAX, dest, destsz);
	CHECK_OR_ZERO_FILL(count <= destsz, dest, destsz);

	/*
	 * Buffer overlap test.
	 * case a) `d < s` implies `s >= d+count`
	 * case b) `d > s` implies `d >= s+count`
	 */
	CHECK_OR_ZERO_FILL(d != s, dest, destsz);
	CHECK_OR_ZERO_FILL(d < s || d >= (s + count), dest, destsz);
	CHECK_OR_ZERO_FILL(d > s || s >= (d + count), dest, destsz);

	/*
	 * Clang analyzer doesn't like us calling unsafe memory functions, so
	 * make it ignore this call.
	 */
	// NOLINTNEXTLINE
	memcpy(dest, src, count);
}

void memmove_s(void *dest, rsize_t destsz, const void *src, rsize_t count)
{
	CHECK_OR_ZERO_FILL(dest != NULL, dest, destsz);
	CHECK_OR_ZERO_FILL(src != NULL, dest, destsz);

	/* Check count <= destsz <= RSIZE_MAX. */
	CHECK_OR_ZERO_FILL(destsz <= RSIZE_MAX, dest, destsz);
	CHECK_OR_ZERO_FILL(count <= destsz, dest, destsz);

	/*
	 * Clang analyzer doesn't like us calling unsafe memory functions, so
	 * make it ignore this call.
	 */
	// NOLINTNEXTLINE
	memmove(dest, src, count);
}

/**
 * Finds the first occurrence of character `ch` in the first `count` bytes of
 * memory pointed to by `ptr`.
 *
 * Returns NULL if `ch` is not found.
 * Panics if `ptr` is NULL (undefined behaviour).
 */
void *memchr(const void *ptr, int ch, size_t count)
{
	size_t i;
	const unsigned char *p = (const unsigned char *)ptr;

	CHECK(ptr != NULL);

	/* Iterate over at most `strsz` characters of `str`. */
	for (i = 0; i < count; ++i) {
		if (p[i] == (unsigned char)ch) {
			return (void *)(&p[i]);
		}
	}

	return NULL;
}

/**
 * Returns the length of the null-terminated byte string `str`, examining at
 * most `strsz` bytes.
 *
 * If `str` is a NULL pointer, it returns zero.
 * If a NULL character is not found, it returns `strsz`.
 */
size_t strnlen_s(const char *str, size_t strsz)
{
	if (str == NULL) {
		return 0;
	}

	for (size_t i = 0; i < strsz; ++i) {
		if (str[i] == '\0') {
			return i;
		}
	}

	/* NULL character not found. */
	return strsz;
}
