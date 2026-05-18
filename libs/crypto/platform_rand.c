#define RAND_PLATFORM_INDEPENDENT 1

#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>

#include "rand.h"

uint32_t random32(void) {
  uint32_t value = 0;
  int fd = open("/dev/urandom", O_RDONLY);
  if (fd >= 0) {
    ssize_t n = read(fd, &value, sizeof(value));
    (void)n;
    close(fd);
  }
  return value;
}
