CC := $(CROSS_COMPILE)gcc
AS := $(CROSS_COMPILE)gcc
CFLAGS = -g

BINS = get_char do_mmap buddy_algorithm

all: $(BINS)

%: %.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -rf $(BINS)
