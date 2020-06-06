// SPDX-License-Identifier: (GPL-2.0-or-later OR BSD-3-Clause)

#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <string.h>

static int vc_fd;
static uint32_t vc_mem_size, vc_mem_base, vc_mem_load, vc_mem_phys;
static void *vc_mem;
static uint32_t vc_syms_off;

#define VC_MEM_IOC_MAGIC  'v'

#define VC_MEM_IOC_MEM_PHYS_ADDR    _IOR( VC_MEM_IOC_MAGIC, 0, unsigned long )
#define VC_MEM_IOC_MEM_SIZE         _IOR( VC_MEM_IOC_MAGIC, 1, unsigned int )
#define VC_MEM_IOC_MEM_BASE         _IOR( VC_MEM_IOC_MAGIC, 2, unsigned int )
#define VC_MEM_IOC_MEM_LOAD         _IOR( VC_MEM_IOC_MAGIC, 3, unsigned int )
#define VC_MEM_IOC_MEM_COPY         _IOWR( VC_MEM_IOC_MAGIC, 4, char *)

#define VC_DEBUG_HEADER_OFFSET 0x2800
#define VC_SYMBOL_BASE_OFFSET VC_DEBUG_HEADER_OFFSET

static void vc_read(void *buf, size_t off, size_t size) {
	// if(off < vc_mem_base) {
	// 	fprintf(stderr, "small address\n");
	// 	abort();
	// }
	if(off > vc_mem_size || size > vc_mem_size - off) {
		fprintf(stderr, "out of bounds read: %zx+%zx/%x\n", off, size, vc_mem_size);
		abort();
	}

	if(size == 0) return;

	size_t skip = off % 4;
	volatile uint32_t *inp = (volatile uint32_t*)((char*)vc_mem + (off - skip));
	char *out = buf;
	if(skip) {
		uint32_t v = *inp;
		inp++;
		size_t have = 4 - skip;
		if(have >= size) {
			memcpy(out, (char*)&v + skip, size);
			return;
		}
		memcpy(out, (char*)&v + skip, have);
		out += have;
		size -= have;
	}

	while(1) {
		uint32_t v = *inp;
		inp++;
		if(size < 4) {
			memcpy(out, &v, size);
			return;
		}
		memcpy(out, &v, 4);
		out += 4;
		size -= 4;
	}
}

static uint32_t vc_read_u32(size_t off) {
	uint32_t r = 42;
	vc_read(&r, off, 4);
	return r;
}

static uint16_t vc_read_u16(size_t off) {
	uint16_t r = 42;
	vc_read(&r, off, 2);
	return r;
}

static uint8_t vc_read_u8(size_t off) {
	uint8_t r = 42;
	vc_read(&r, off, 1);
	return r;
}

static size_t vc_read_ptr(size_t off) {
	uint32_t r = vc_read_u32(off);
	if(r == 0) return 0;
	if(r <= 0xc0000000) {
		fprintf(stderr, "invalid pointer: %x\n", r);
		abort();
	}
	return r - 0xc0000000;
}

static char *vc_read_str(size_t off) {
	size_t len = 0, alloc = 16;
	char *r = malloc(alloc);
	if(!r) abort();
	while(1) {
		size_t roff = off + len;
		size_t try_read = alloc - len;
		if(try_read > vc_mem_size - roff) {
			try_read = vc_mem_size - roff;
		}
		if(try_read == 0) abort();
		vc_read(r + len, roff, try_read);
		size_t add = strnlen(r + len, try_read);
		len += add;
		if(add < try_read) {
			break;
		}

		size_t alloc2 = alloc + (alloc << 2);
		alloc2 += (-alloc2) % 16;
		char *r2 = realloc(r, alloc2);
		if(!r2) abort();
		r = r2;
		alloc = alloc2;
	}

	return r;
}

static void vc_open(void) {
	int r = open("/dev/vc-mem", O_RDWR | O_SYNC | O_CLOEXEC);
	if(r < 0) {
		perror("open");
		abort();
	}
	vc_fd = r;

	r = ioctl(vc_fd, VC_MEM_IOC_MEM_SIZE, &vc_mem_size);
	if(r < 0) {
		perror("VC_MEM_IOC_MEM_SIZE");
		abort();
	}
	r = ioctl(vc_fd, VC_MEM_IOC_MEM_BASE, &vc_mem_base);
	if(r < 0) {
		perror("VC_MEM_IOC_MEM_BASE");
		abort();
	}
	r = ioctl(vc_fd, VC_MEM_IOC_MEM_LOAD, &vc_mem_load);
	if(r < 0) {
		perror("VC_MEM_IOC_MEM_LOAD");
		abort();
	}
	r = ioctl(vc_fd, VC_MEM_IOC_MEM_PHYS_ADDR, &vc_mem_phys);
	if(r < 0) {
		perror("VC_MEM_IOC_MEM_PHYS_ADDR");
		abort();
	}

	vc_mem = mmap(NULL, vc_mem_size, PROT_READ, MAP_SHARED, vc_fd, 0);
	if(vc_mem == MAP_FAILED) {
		perror("mmap");
		abort();
	}

	uint32_t dbg_off = vc_mem_load + VC_DEBUG_HEADER_OFFSET;
	uint32_t dbg_magic = vc_read_u32(dbg_off + 4);
	if(dbg_magic != 0x48444356) {
		fprintf(stderr, "bad debug magic: %08x, wanted 48444356\n", dbg_magic);
		abort();
	}
	vc_syms_off = vc_read_u32(dbg_off);
}

static size_t vc_sym_find(const char *want) {
	uint32_t at = vc_syms_off;
	while(1) {
		uint32_t label = vc_read_u32(at + 0);
		uint32_t addr = vc_read_u32(at + 4);
		if(label == 0) return 0;

		char *name = vc_read_str(label);
		int r = strcmp(name, want);
		free(name);
		if(!r) return addr;

		at += 12;
	}
}

static void vc_log_read(size_t descriptor_ptr) {
	uint8_t fmt = vc_read_u8(descriptor_ptr);
	size_t ptr = vc_read_ptr(descriptor_ptr + 4);
	if(!ptr) {
		printf("no data\n");
	}
	if(fmt != 1) {
		printf("unsupported log format %u\n", fmt);
		return;
	}

	uint32_t magic = vc_read_u32(ptr);
	if(magic != 0x5353454d) {
		printf("bad fifo log magic: %08x, wanted 5353454d", magic);
		return;
	}

	size_t l_start = vc_read_ptr(ptr + 4);
	size_t l_end = vc_read_ptr(ptr + 8);
	size_t l_ptr = vc_read_ptr(ptr + 12);
	size_t l_next_msg = vc_read_ptr(ptr + 16);

	size_t at = l_next_msg;
	do {
		uint32_t time = vc_read_u32(at + 0);
		uint32_t seq = vc_read_u16(at + 4);
		size_t size = vc_read_u16(at + 6);
		if(size < 12) {
			printf("short message: %zu\n", size);
			return;
		}
		size_t len = size - 12;
		char *s = malloc(len + 1);
		if(!s) abort();
		vc_read(s, at + 12, len);
		s[len] = 0;
		printf("[%u : %u] %s\n", time, seq, s);
		free(s);

		at += size;
		if(at == l_end) at = l_start;
	} while(at != l_ptr);
}

static void vc_log_read_all(void) {
	size_t log_start = vc_sym_find("__LOG_START");
	if(!log_start) {
		fprintf(stderr, "no __LOG_START\n");
		abort();
	}
	log_start = vc_read_ptr(log_start);

	uint32_t log_magic = vc_read_u32(log_start);
	if(log_magic != 0x564c4f47) {
		fprintf(stderr, "bad log header magic: %08x, wanted 564c4f47\n", log_magic);
		abort();
	}

	vc_log_read(log_start + 40);
}

int main() {
	vc_open();
	vc_log_read_all();

	close(vc_fd);
	return 0;
}
