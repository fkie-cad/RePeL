TARGET := udp_gateway
CMD := ./$(TARGET)
LIBREPEL := $(abspath ../../repel)
LIBTINYDTLS := $(abspath ../tinydtls)
SANE_IO := $(abspath ../sane_io)

BUILD := $(abspath ./build)

# clock_gettime() in linux/platform.c requires _POSIX_C_SOURCE
CFLAGS := -Wall -Wextra -Wshadow -Werror -pedantic -std=c99 -D_POSIX_C_SOURCE=200809L -O2 -I$(LIBREPEL) -I$(LIBREPEL)/platform/linux -I$(SANE_IO)

SRCS := $(wildcard *.c)
OBJS := $(patsubst %.c, $(BUILD)/%.o, $(SRCS))
DEPS := $(OBJS:.o=.d)

.SUFFIXES:
.PHONY: all clean libs run valgrind

all: $(TARGET)

$(TARGET): $(OBJS) $(LIBREPEL)/out/librepel.a $(LIBTINYDTLS)/libtinydtls.a $(SANE_IO)/out/sane_io.a
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

$(LIBTINYDTLS)/libtinydtls.a:
	$(MAKE) -C $(LIBTINYDTLS)

$(SANE_IO)/out/sane_io.a:
	$(MAKE) -C $(SANE_IO)

$(LIBREPEL)/out/librepel.a:
	$(MAKE) -C $(LIBREPEL) PLATFORM=linux LIBTINYDTLS=$(LIBTINYDTLS) DEFINES=ENABLE_EVAL_TIMERS=false

libs:
	$(MAKE) -C $(LIBTINYDTLS)
	$(MAKE) -C $(LIBREPEL) PLATFORM=linux LIBTINYDTLS=$(LIBTINYDTLS) DEFINES=ENABLE_EVAL_TIMERS=false
	$(MAKE) -C $(SANE_IO)

clean:
	$(MAKE) clean -C $(LIBTINYDTLS)
	$(MAKE) clean -C $(LIBREPEL)
	$(MAKE) clean -C $(SANE_IO)
	rm -rf $(BUILD)
	rm -f $(TARGET)

run:
	$(CMD)

valgrind:
	valgrind $(CMD)
