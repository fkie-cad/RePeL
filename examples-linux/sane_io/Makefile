OUT ?= ./out

CFLAGS := -Wall -Wextra -Wshadow -Werror -pedantic -std=c99 -D_POSIX_C_SOURCE=200809L -O2
ARFLAGS := cru

LIB := $(OUT)/sane_io.a
SRCS := $(wildcard *.c)
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