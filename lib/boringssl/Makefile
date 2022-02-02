# SPDX-License-Identifier: GPL-2.0+
#
# (C) Copyright 2021 Google LLC

obj-$(CONFIG_LIB_BORINGSSL) += \
	err.o\
	mem.o\
	rand.o\
	src/crypto/fipsmodule/aes/aes_nohw.o\
	src/crypto/curve25519/curve25519.o\
	src/crypto/fipsmodule/cipher/aead.o\
	src/crypto/fipsmodule/cipher/e_aes.o\
	src/crypto/fipsmodule/digest/digest.o\
	src/crypto/fipsmodule/digest/digests.o\
	src/crypto/fipsmodule/hmac/hmac.o\
	src/crypto/fipsmodule/modes/gcm.o\
	src/crypto/fipsmodule/modes/gcm_nohw.o\
	src/crypto/fipsmodule/rand/ctrdrbg.o\
	src/crypto/fipsmodule/rand/rand.o\
	src/crypto/fipsmodule/sha/sha256.o\
	src/crypto/fipsmodule/sha/sha512.o\
	src/crypto/hkdf/hkdf.o\
	src/crypto/mem.o\
	src/crypto/rand_extra/forkunsafe.o\
	src/crypto/thread_none.o\

BORINGSSL_EXTRA_FLAGS := \
	-I$(srctree)/lib/boringssl/include\
	-I$(srctree)/lib/boringssl/src/include\
	-I$(srctree)/lib/boringssl/src/crypto\
	-DOPENSSL_NO_THREADS_CORRUPT_MEMORY_AND_LEAK_SECRETS_IF_THREADED\
	-DOPENSSL_SMALL\
	-DOPENSSL_NO_ASM\

CFLAGS_err.o = -include pre-stdio.h
CFLAGS_digest.o = -include pre-stdio.h
CFLAGS_hkdf.o = -include pre-stdio.h
CFLAGS_mem.o = -include pre-stdio.h
CFLAGS_aead.o = -include pre-stdio.h
CFLAGS_e_aes.o = -include pre-stdio.h -include pre-stdlib.h
CFLAGS_rand.o = -include pre-stdlib.h
CFLAGS_forkunsafe.o = -include pre-stdlib.h

ccflags-y += $(BORINGSSL_EXTRA_FLAGS)
asflags-y += $(BORINGSSL_EXTRA_FLAGS)
