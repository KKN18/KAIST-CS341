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

#define LISTENQ 100

#define MSG_MAX 10000000
#define BUF_MAX MSG_MAX-30
#define U2L 32

#define DEBUG 1
int VERBOSE = 0;
/* Function declarations */
int main(int, char **);
int str_crypt(char *, int, int);
uint32_t build_packet(char **, char, char, uint32_t, const char *);

uint16_t checksum(char, char, uint32_t, uint32_t, const char *);
uint16_t unpack(const char *);
uint32_t read_n(int, char *, uint32_t);

int process(int);

int main(int argc, char **argv) {
    int port, sockfd, connfd;
    int t;
    socklen_t c_len;
    struct sockaddr_in sa, ca;

    char c;
    
    while((c = getopt(argc, argv, "p:v")) != -1) {
        switch(c) {
            case 'p':
                port = atoi(optarg);
                break;
            case 'v':
                VERBOSE = 1;
                break;
            default:
                fprintf(stderr,"Unknown argument: -%c\n", optopt);
                return -1;
        }
    }

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd == -1) {
        fprintf(stderr,"Failed to create socket\n");
        return -1;
    }
    if(VERBOSE) fprintf(stderr, "Complete to create socket\n");

    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = INADDR_ANY;
    sa.sin_port = htons(port);
    
    if(bind(sockfd, (struct sockaddr *)&sa, sizeof(sa)) <0) {
        fprintf(stderr,"Failed to bind socket\n");
        return -1;
    } 
    if(VERBOSE) fprintf(stderr, "Complete to bind socket\n");
    
    if(listen(sockfd, LISTENQ) < 0) {
        fprintf(stderr,"Failed to listen socket\n");
        return -1;
    }
    if(VERBOSE) fprintf(stderr, "Listening now.. \n");

    while(1) {
        c_len  = sizeof(ca);
        connfd = accept(sockfd, (struct sockaddr *)&ca, &c_len);
        if(VERBOSE) fprintf(stderr,"New connection estabilshed with fd %d\n", connfd);
        if((t = fork()) == 0) {
            while((t = process(connfd))) {
                fprintf(stderr,"[%d] sent %d bytes of string.\n", connfd, t);
            }
            
            close(connfd);
            return 0;
        }
        else if(t == -1) {
            fprintf(stderr,"Failed to fork a child.\n");
            return -1;
        }
    }
}

int process(int connfd) {
    int t;
    uint16_t chk, _checksum; uint32_t msg_len, payload_len; 
    char op, shift, _shift;
    char *t_msg = (char *)malloc(MSG_MAX);
    char *buf = (char *)malloc(MSG_MAX);

    if(VERBOSE) fprintf(stderr,"[%d]> Waiting to recieve header\n", connfd);

    t = read_n(connfd, t_msg, 8);
    
    if(VERBOSE) fprintf(stderr,"[%d]> Recieved header\n", connfd);
    
    if(t == 0) {
        return -1;
    }
    else if (t < 0) {
        fprintf(stderr,"[%d] Socket read failed\n", connfd);
        exit(-1);
    }
    else if(t < 8) {
        fprintf(stderr,"[%d] Error in request (malformed header)\n", connfd);
        close(connfd);
        exit(-1);
    }
    op = t_msg[0];
    shift =  t_msg[1];

    if(op != OP_ENC && op != OP_DEC) {
        fprintf(stderr,"[%d] Error in request (op)\n %d is unknown op\n", connfd, op);
        exit(-1);
    }

    chk = unpack(t_msg + 2);
    msg_len = (unpack(t_msg + 4) << 16) + unpack(t_msg+6);
    payload_len = msg_len - 8;
    if(VERBOSE) fprintf(stderr,"[%d]> Waiting to recieve string\n", connfd);
    
    t = read_n(connfd, buf, payload_len);
    if(VERBOSE) fprintf(stderr,"[%d]> Received string\n", connfd);
    
    if(t < (int)payload_len) {
        fprintf(stderr,"[%d] Error in request (message length)\nExpected %d bytes, but %d bytes recieved\n", connfd, payload_len, t);
        exit(-1);
    }

    _checksum = checksum(op, shift, msg_len, payload_len, buf);

    if(VERBOSE) 

    if(_checksum != chk) {
        fprintf(stderr,"[%d] Error in request (checksum)\nExcpected %x as checksum, but %x was recieved as checksum\n", connfd, _checksum, chk);
        exit(-1);
    }
    
    _shift = (shift % 26 + 26) % 26;
    if(op == OP_DEC)
        _shift = 26 - _shift;
    
    str_crypt(buf, _shift, payload_len);
   
    free(t_msg); 
    t = build_packet(&t_msg, op, shift, payload_len, buf);
    write(connfd, t_msg, t);
    free(buf);

    return payload_len; 
}

int str_crypt(char *buf, int key, int size) {
    int i=0;
    if(key == 0)
        return size;
    for(; i<size; i++) {
        if('A' <= buf[i] && buf[i] <= 'Z')
            buf[i] += U2L;
        if('a' <= buf[i] && buf[i] <= 'z')
            buf[i] = 'a' + ((buf[i] - 'a' + key) % 26);
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
