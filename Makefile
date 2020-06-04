CFLAGS = -O2 -g

vc-log: vc-log.c
	$(CC) -std=gnu11 -Wall -Wextra $(CFLAGS) $< -o $@
