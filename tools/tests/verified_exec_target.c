#include <stdio.h>
#include <sys/prctl.h>

int main(void) {
    char comm[16] = {0};
    if (prctl(PR_GET_NAME, comm) != 0) return 2;
    puts(comm);
    return 0;
}
