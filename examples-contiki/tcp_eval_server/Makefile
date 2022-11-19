CONTIKI_PROJECT = tcp_eval_server
all: $(CONTIKI_PROJECT)

CONTIKI = ../../..

MODULES +=	os/lib/repel

# Include RPL BR module
include $(CONTIKI)/Makefile.dir-variables
MODULES += $(CONTIKI_NG_SERVICES_DIR)/rpl-border-router

include $(CONTIKI)/Makefile.include
