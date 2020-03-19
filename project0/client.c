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
#define OP_ENC 0
#define OP_DEC 1

#define MSG_MAX 10000000
#define BUF_MAX MSG_MAX-16

#define DEBUG 1
/* Function declarations */
int main(int, char **);
uint32_t build_packet(char **, char, char, uint32_t, const char *);
uint16_t checksum(char, char, uint32_t, uint32_t, const char *);
uint16_t unpack(const char *);
/* Function implementations */
int main(int argc, char **argv) {
    char *buf = (char *)malloc(MSG_MAX);
    char c, host[16] = "\0", *t_msg;
    int p=-1, mode=-1, s=-1, t;
    
    int cnt=0, total_wrote=0;
    int sockfd;
    struct sockaddr_in sa;
    /*if(DEBUG) { 
        char c;
        int i =0, j=0;
        while((c = getchar()) != EOF) {
            buf[i++] = c;
        }
        char *x;
        int t=build_packet(&x, OP_ENC, 1, i, buf);
        for(j=0; j<t; j++)
            printf ("%c", x[j] & 0xff);
    }*/
    while((c = getopt(argc, argv, "h:p:o:s:")) != -1) {
        switch(c) {
            case 'h':
                strncpy(host, optarg, 15);
                break;
            case 'p':
                p = atoi(optarg);
                if(p < 1 || p > 65535) {
                    printf("Invalid port: %d\n", p);
                    return -1;
                }
                break;
            case 'o':
                t = atoi(optarg);
                if(t == 0)
                    mode = OP_ENC;
                else if(t == 1)
                    mode = OP_DEC;
                else {
                    printf("Invalid argument: -o [0, 1]\n");
                    return -1;
                }
                break;
            case 's':
                t = atoi(optarg);
                s = t & 0xFFFF;
                break;
            default:
                printf("Unknown argument: -%c\n", optopt);
                return -1;
        }
    }
    
    if(host[0] == '\0' || p == -1 || mode == -1 || s == -1) {
        printf("There is(are) missing argument(s)\n");
        return -1;
    }  
    //Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0) {
        printf("Error to create socket");
        return -1;
    }
    sa.sin_family = AF_INET;
    sa.sin_port = htons(p);
    if(inet_pton(AF_INET, host, &sa.sin_addr) <= 0) {
        printf("Invalid address: %s\n", host);
        return -1;
    }

    if(connect(sockfd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        printf("Error to connect %s:%d\n", host, p);
        return -1;
    }
    while((c = getchar()) != EOF) {
        buf[cnt++] = c;

        if(cnt == BUF_MAX - 16) {
            t = build_packet(&t_msg, mode, s, cnt, buf);
            write(sockfd, t_msg, t);    //send to server
            total_wrote += cnt;
            cnt = 0;
        }
    }
    t = build_packet(&t_msg, mode, s, cnt, buf);
    write(sockfd, t_msg, t);
    total_wrote += cnt;
    cnt = 0;

    free(t_msg);

    t_msg = (char *)malloc(MSG_MAX);
    //Now receive the packet
    while(total_wrote > 0) {
        t = read(sockfd, t_msg, 8);
        if(t < 8) {
            printf("Error in response (malformed header)\n");
            return -1;
        }
        char op = t_msg[0];
        char shift =  t_msg[1];
        uint16_t chk = unpack(t_msg + 2);
        uint32_t payload_len = (unpack(t_msg + 4) << 16) + unpack(t_msg+6);

        t = read(sockfd, t_msg, payload_len);
        if(t < (int)payload_len - 8) {
            printf("Error in response (message length)\nExpected %d bytes, but %d bytes recieved.", payload_len - 8, t);
            return -1;
        }

        uint16_t _checksum = checksum(op, shift, payload_len, payload_len - 8, t_msg);
        if(_checksum != chk) {
            printf("Error in response (checksum)\n");
            return -1;
        }

        write(1, t_msg, payload_len);
        total_wrote -= payload_len;
    }
    close(sockfd);
    return 0;
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
    //Assume ptr's size is two.
    return ((unsigned)ptr[0] << 8) + ((unsigned)ptr[1]);
}
