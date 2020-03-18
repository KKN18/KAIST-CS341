#include <stdio.h>
#include <stdlib.h>

#define U2L 32

int encrypt(char *, int);

int main(int argc, char **argv) {
    return 0;
}

int encrypt(char *buf, int key) {
    int i=0;
    while(buf[i] != 0) {
        if('A' <= buf[i] && buf[i] <= 'Z')
            buf[i] += U2L;
        if('a' <= buf[i] && buf[i] <= 'z')
            buf[i] = 'a' + (buf[i] - 'a' + key) % 26;
        i++;
    }
    return i;
}
