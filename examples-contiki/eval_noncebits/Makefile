CONTIKI_PROJECT = eval_noncebits
all: $(CONTIKI_PROJECT)

CONTIKI = ../../..

MODULES +=	os/lib/repel

# Include RPL BR module to run logs over
include $(CONTIKI)/Makefile.dir-variables
MODULES += $(CONTIKI_NG_SERVICES_DIR)/rpl-border-router

include $(CONTIKI)/Makefile.include
