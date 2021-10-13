obj-$(CONFIG_LIB_OPENDICE) += \
	clear_memory.o \
	src/android/bcc.o \
	src/cbor_cert_op.o \
	src/cbor_reader.o \
	src/cbor_writer.o \
	src/dice.o \
	src/utils.o \

ccflags-$(CONFIG_LIB_OPENDICE) += \
	-I$(srctree)/lib/open-dice/include/\
	-I$(srctree)/lib/open-dice/include-patch/\

ifeq ($(CONFIG_LIB_BORINGSSL),y)
obj-$(CONFIG_LIB_OPENDICE) += \
	src/boringssl_hash_kdf_sign_ops.o \

ccflags-$(CONFIG_LIB_OPENDICE) += \
	-I$(srctree)/lib/open-dice/include/dice/config/$(CONFIG_LIB_OPENDICE_CONFIG)/\
	-I$(srctree)/lib/boringssl/src/include/\
	-I$(srctree)/lib/boringssl/include/\

endif
