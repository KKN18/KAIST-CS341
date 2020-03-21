/* 
 * CS341 Introduction to Computer Networks
 * Project #0: Socket Programming
 *
 * Author: Jihwan Kim, KAIST
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

/* Some settings */
typedef unsigned char byte;

#define OP_ENC 0
#define OP_DEC 1

#define MSG_MAX 10000000
#define BUF_MAX MSG_MAX-16
#define U2L 32

#define DEBUG 1
/* Function declarations */
int main(int, char **);
int str_crypt(char *, int);
uint32_t build_packet(char **, char, char, uint32_t, const char *);
uint16_t checksum(char, char, uint32_t, uint32_t, const char *);
uint16_t unpack(const char *);

int main(int argc, char **argv) {
    return 0;
}

int str_crypt(char *buf, int key) {
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

uint32_t build_packet(char **out, char op, char shift, uint32_t payload_length, const char *payload) { 
    if(op != OP_ENC && op != OP_DEC)
        return -1; //Invalid op
    if(payload_length > MSG_MAX - 8)
        return -2; //Too large body

    uint32_t msg_length = 8 + payload_length;
    char *buf = (char *)malloc(msg_length);

    if(out == NULL)
        return -11; //malloc failed

    uint16_t c = checksum(op, shift, msg_length, payload_length, payload);

    buf[0] = op;
    buf[1] = shift;
    buf[2] = (c >> 8) & 0xff;
    buf[3] = (c) & 0xff;
    buf[4] = (msg_length >> 24) & 0xff;
    buf[5] = (msg_length >> 16) & 0xff;
    buf[6] = (msg_length >> 8) & 0xff;
    buf[7] = (msg_length) & 0xff;
    
    memcpy(&buf[8], payload, payload_length);

    *out = buf;
    return msg_length; //return generated message's size
}

uint16_t checksum(char op, char shift, uint32_t length, uint32_t buf_size, const char *buf) {
    uint32_t i=0;
    unsigned int sum=0;

    unsigned int t;
    //Handle header
    sum+= t= ((unsigned int)op << 8) + (unsigned int)shift;
    sum += t= (((length >> 24) & 0xff) << 8) + ((length >> 16) & 0xff);
    sum +=t= (((length >> 8) & 0xff ) << 8) + (length & 0xff);
    

    if(buf_size % 2 == 1) {
        sum += (unsigned int) buf[buf_size - 1] << 8;
    }
    while(i+1 < buf_size) {
        sum += unpack(&buf[i]);
        i += 2;
    }
    while(sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    
    return ~sum;
}

uint16_t unpack(const char *ptr) {
    //unpack char[2] -> short.
    return ((unsigned)ptr[0] << 8) + ((unsigned)ptr[1]);
}
