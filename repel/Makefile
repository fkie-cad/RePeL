# Build RePeL as a standalone

SUPPORTED_PLATFORMS := linux

ifeq ($(OUT),)
OUT ?= ./out
$(warning "Variable 'OUT' is unset. Building RePeL in default directory '$(OUT)'.")
endif

ifneq ($(MAKECMDGOALS),clean)

ifeq ($(PLATFORM),)
PLATFORM ?= linux
$(warning "Variable 'PLATFORM' is unset. Building RePeL for default platform '$(PLATFORM)'.")
endif
ifeq ($(filter $(PLATFORM), $(SUPPORTED_PLATFORMS)),)
$(error "RePeL does not support platform '$(PLATFORM)' as standalone, choose one of '$(SUPPORTED_PLATFORMS)' instead.")
endif

ifeq ($(LIBTINYDTLS),)
$(error "RePeL requires the TinyDTLS library. Set LIBTINYDTLS accordingly.")
endif

endif

# clock_gettime() in linux/platform.c requires _POSIX_C_SOURCE
CFLAGS := -Wall -Wextra -Wshadow -Werror -pedantic -std=c99 -D_POSIX_C_SOURCE=200809L -O2 -I$(LIBTINYDTLS) -I$(LIBTINYDTLS)/posix -Iplatform/$(PLATFORM) ${addprefix -D, $(DEFINES)}
ARFLAGS := cru

LIB := $(OUT)/librepel.a
SRCS := $(wildcard *.c) $(wildcard parser/*.c) $(wildcard mac/*.c) $(wildcard platform/$(PLATFORM)/*.c)
OBJS := $(patsubst %.c, $(OUT)/%.o, $(SRCS))
DEPS := $(OBJS:.o=.d)

.SUFFIXES:
.PHONY: all clean

all: $(LIB)

clean:
	rm -rf $(OUT)

$(LIB): $(OBJS)
	$(AR) $(ARFLAGS) $@ $^

$(OUT)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

-include $(DEPS)