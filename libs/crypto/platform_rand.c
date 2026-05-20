#define RAND_PLATFORM_INDEPENDENT 1

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "rand.h"

static void read_urandom_or_die(uint8_t* buf, size_t len) {
  int fd = open("/dev/urandom", O_RDONLY);
  if (fd < 0) {
    fprintf(stderr, "fatal: cannot open /dev/urandom: %s\n", strerror(errno));
    abort();
  }

  size_t off = 0;
  while (off < len) {
    const ssize_t n = read(fd, buf + off, len - off);
    if (n <= 0) {
      fprintf(stderr, "fatal: cannot read /dev/urandom: %s\n",
              n == 0 ? "unexpected EOF" : strerror(errno));
      close(fd);
      abort();
    }
    off += (size_t)n;
  }
  close(fd);
}

uint32_t random32(void) {
  uint32_t value = 0;
  read_urandom_or_die((uint8_t*)&value, sizeof(value));
  return value;
}

void random_buffer(uint8_t* buf, size_t len) {
  if (len == 0) {
    return;
  }
  read_urandom_or_die(buf, len);
}
