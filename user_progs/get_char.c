#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

static unsigned long a = 0x1122334455667788;

void sighandler(int sig)
{
    printf("a=0x%lx\n", a);
    exit(0);
}

int main(int argc, char **argv)
{
    signal(SIGINT, sighandler);
    printf("%lx %p\n", a, &a);
    while (1) {
        sleep(1);
    }

    return 0;
}