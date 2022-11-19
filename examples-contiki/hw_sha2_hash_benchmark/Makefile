CONTIKI_PROJECT = hw_sha2_hash_benchmark
all: $(CONTIKI_PROJECT)

CONTIKI = ../../..

PLATFORMS_ONLY = zoul

MODULES +=	os/lib/repel

# Include RPL BR module to run logs over
include $(CONTIKI)/Makefile.dir-variables
MODULES += $(CONTIKI_NG_SERVICES_DIR)/rpl-border-router

include $(CONTIKI)/Makefile.include
