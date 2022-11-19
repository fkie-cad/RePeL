CONTIKI_PROJECT = test_memoverhead
all: $(CONTIKI_PROJECT)

CONTIKI = ../../..
TINYDTLS_PATH := os/net/security/tinydtls

# Platform native does not support checking stack usage
PLATFORMS_ONLY = z1 zoul

MODULES +=	os/lib/repel
#MODULES += os/lib/repel/tinydtls-support $(TINYDTLS_PATH) ${addprefix $(TINYDTLS_PATH)/,aes sha2 ecc}

# Include RPL BR module
include $(CONTIKI)/Makefile.dir-variables
MODULES += $(CONTIKI_NG_SERVICES_DIR)/rpl-border-router

include $(CONTIKI)/Makefile.include
