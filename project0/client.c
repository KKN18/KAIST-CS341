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

#define MSG_MAX 9*1000*1000
#define BUF_MAX MSG_MAX-30

int VERBOSE = 0;
/* Function declarations */
int main(int, char **);
uint32_t build_packet(char **, char, char, uint32_t, const char *);
uint16_t checksum(char, char, uint32_t, uint32_t, const char *);
uint16_t unpack(const char *);
uint32_t read_n(int, char *, uint32_t);


/* Function implementations */
int main(int argc, char **argv) {
    char *buf = (char *)malloc(BUF_MAX);
    char c, host[16] = "\0", *t_msg, op, shift;
    int p=-1, mode=-1, s=-1, t;
    
    uint16_t chk;
    int cnt=0, msg_len, payload_len;
    int sockfd;
    struct sockaddr_in sa;
    /*if(VERBOSE) { 
        char c;
        int i =0, j=0;
        while((c = getchar()) != EOF) {
            buf[i++] = c;
        }
        char *x;
        int t=build_packet(&x, OP_ENC, 1, i, buf);
        for(j=0; j<t; j++)
            printf ("%c", x[j] & 0xff);
        return 0;
    }*/
    while((c = getopt(argc, argv, "h:p:o:s:v")) != -1) {
        switch(c) {
            case 'h':
                strncpy(host, optarg, 15);
                break;
            case 'p':
                p = atoi(optarg);
                if(p < 1 || p > 65535) {
                    fprintf(stderr,"Invalid port: %d\n", p);
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
                    fprintf(stderr,"Invalid argument: -o [0, 1]\n");
                    return -1;
                }
                break;
            case 's':
                t = atoi(optarg);
                t %= 26;
                if(t < 0)
                    t += 26;
                s = t & 0xFFFF;
                break;
            case 'v':
                VERBOSE = 1;
                break;
            default:
                fprintf(stderr,"Unknown argument: -%c\n", optopt);
                return -1;
        }
    }
    
    if(host[0] == '\0' || p == -1 || mode == -1 || s == -1) {
        fprintf(stderr,"There is(are) missing argument(s)\n");
        return -1;
    }  
    //Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0) {
        fprintf(stderr,"Error to create socket");
        return -1;
    }
    sa.sin_family = AF_INET;
    sa.sin_port = htons(p);
    if(inet_pton(AF_INET, host, &sa.sin_addr) <= 0) {
        fprintf(stderr,"Invalid address: %s\n", host);
        return -1;
    }

    if(connect(sockfd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        fprintf(stderr,"Error to connect %s:%d\n", host, p);
        return -1;
    }

    if(VERBOSE) fprintf(stderr,"> connected\n");
    while((c = getchar()) != EOF) {
        buf[cnt++] = c;

        if(cnt == BUF_MAX) {
            t = build_packet(&t_msg, mode, s, cnt, buf);
            write(sockfd, t_msg, t);
            
            if(VERBOSE) fprintf(stderr,"> %d bytes packet written, chksum : %x\n",t, unpack(&t_msg[2]));
            if(VERBOSE) fprintf(stderr,"> Waiting to receive header\n");
            
            t = read_n(sockfd, t_msg, 8);
            if(VERBOSE) fprintf(stderr,"> Received header\n");
            if(t < 8) {
                fprintf(stderr,"Error in response (malformed header)\n");
                return -1;
            }
            
            op = t_msg[0];
            shift =  t_msg[1];
            chk = unpack(t_msg + 2);
            msg_len = (unpack(t_msg + 4) << 16) + unpack(t_msg+6);
            payload_len = msg_len - 8;
            
            if(VERBOSE) fprintf(stderr,"> Waiting to receive string\n");
            t = read_n(sockfd, buf, payload_len);
            
            if(VERBOSE) fprintf(stderr,"> Received string\n");
            
            if(t < (int)payload_len) {
                fprintf(stderr,"Error in response (message length)\nExpected %d bytes, but %d bytes received.", payload_len - 8, t);
                return -1;
            }

            uint16_t _checksum = checksum(op, shift, msg_len, payload_len, buf);
            if(_checksum != chk) {
                fprintf(stderr,"Error in response (checksum)\nExcpected %x as checksum, but %x was received as checksum", _checksum, chk);
                return -1;
            }
            write(1, buf, payload_len);
            
            free(t_msg);
            cnt = 0;
        }
    }
    t = build_packet(&t_msg, mode, s, cnt, buf);
    write(sockfd, t_msg, t);
    
    if(VERBOSE) fprintf(stderr,"> %d bytes packet written, chksum : %x\n",t, unpack(&t_msg[2]));
    if(VERBOSE) fprintf(stderr,"> Waiting to receive header\n");
    
    t = read_n(sockfd, t_msg, 8);
    if(VERBOSE) fprintf(stderr,"> Received header\n");
    if(t < 8) {
        fprintf(stderr,"Error in response (malformed header)\n");
        return -1;
    }
    
    op = t_msg[0];
    shift =  t_msg[1];
    chk = unpack(t_msg + 2);
    msg_len = (unpack(t_msg + 4) << 16) + unpack(t_msg+6);
    payload_len = msg_len - 8;
    
    if(VERBOSE) fprintf(stderr,"> Waiting to receive string\n");
    t = read_n(sockfd, buf, payload_len);
    
    if(VERBOSE) fprintf(stderr,"> Received string\n");
    
    if(t < (int)payload_len) {
        fprintf(stderr,"Error in response (message length)\nExpected %d bytes, but %d bytes received.", payload_len - 8, t);
        return -1;
    }

    uint16_t _checksum = checksum(op, shift, msg_len, payload_len, buf);
    if(_checksum != chk) {
        fprintf(stderr,"Error in response (checksum)\nExcpected %x as checksum, but %x was received as checksum", _checksum, chk);
        return -1;
    }
    write(1, buf, payload_len);
    
    free(t_msg);
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
    buf[0] = (unsigned) op & 0xff;
    buf[1] = (unsigned) shift & 0xff;
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
 
    //Handle header
    sum += ((op & 0xff) << 8) + (shift & 0xff);
    sum += (((length >> 24) & 0xff) << 8) + ((length >> 16) & 0xff);
    sum += (((length >> 8) & 0xff ) << 8) + (length & 0xff);
    
    if(buf_size % 2 == 1) {
        sum += (unsigned int) (buf[buf_size - 1] & 0xff) << 8;
         
    }
    while(sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    while(i+1 < buf_size) {
        sum += unpack(&buf[i]);
        while(sum >> 16)
            sum = (sum & 0xFFFF) + (sum >> 16);   
        i += 2;
    } 

    return ~sum;
}

uint16_t unpack(const char *ptr) {
    //unpack char[2] -> short
    //
    uint16_t t =  (((unsigned)ptr[0] & 0xff) << 8) + ((unsigned)ptr[1] & 0xff);
    return t;
}

uint32_t read_n(int sockfd, char *out, uint32_t length) {
    uint32_t r_amt=0;
    int t=0;
    if(length == 0)
        return 0;
    while(r_amt != length) {
        if((t = read(sockfd, out + r_amt, length - r_amt)) < 0)
            return 0;
        r_amt += t;
    }
    return r_amt;
}
