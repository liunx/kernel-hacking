#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <signal.h>
#include <unistd.h>

#define MEM_SIZE (1 << 26)
static const char *dev_path = "/dev/mmap_dev";

int main(int argc, const char **argv)
{
    int fd;
    void *addr;

    fd = open(dev_path, O_RDWR);
    if (fd < 0) {
        perror("open");
        return fd;
    }

    addr = mmap(NULL, MEM_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (addr == MAP_FAILED) {
        perror("mmap");
        goto mmap_fail;
    }

    for (int i = 0; i < 16; i++) {
        // printf("memset: %d\n", i);
        memset(addr, i, MEM_SIZE);
    }

    munmap(addr, MEM_SIZE);
mmap_fail:
    close(fd);
    return 0;
}
