/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_


#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Host.hpp>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <list>
#include <queue>
#include <set>
#include <map>
#include <utility>

#include <E/E_TimerModule.hpp>

#define TCP_FLAG_FIN 1
#define TCP_FLAG_SYN 2
#define TCP_FLAG_ACK 16
#define TCP_WIN_SIZE 51200
#define TCP_DATA_MAX 512

#define RTT 100
#define RTT_K 4
#define RTT_ALPHA 0.125
#define RTT_BETA 0.25

#define DEFAULT_TIMEOUT 100
#define TCP_MSL 60000

namespace E
{


enum TcpState
{
    CLOSED,
    LISTEN,
    SYNSENT,
    SYNRCVD,
    ESTAB,
    FINWAIT_1,
    CLOSING,
    CLOSE_WAIT,
    FINWAIT_2,
    LAST_ACK,
    TIMED_WAIT
};

enum CongestionState
{
    SLOW_START,
    AVOIDANCE,
    FAST_RECOV
};

typedef std::pair<int, int> Desc_t; // (pid, fid)
typedef std::pair<uint32_t, uint16_t> Addr_t; //(ip address, port)
typedef struct sockaddr SA;
typedef struct sockaddr_in SA_in;

typedef struct _SockBuf {
    uint32_t seq;
    uint16_t len;
    Packet *pkt;
    struct _Socket *socket;
    UUID timerUUID;
    TcpState state;
} SocketBuffer;

typedef struct _SockDataBuf {
    int32_t seq;
    uint16_t len;
    uint16_t offset;
    uint8_t *buf;
    bool acked = false;

} SocketDataBuffer;

struct Cmp{
    bool operator()(const SocketDataBuffer *x, const SocketDataBuffer *y) const {
        return x->seq < y->seq;
    }
};

typedef struct _Socket
{
	//process information
	int pid;
	int fd;

	//socket info
	int type;
	int protocol;

    //Socket Essentials
    Addr_t localAddr;
	Addr_t remoteAddr = Addr_t(-1, -1);
    TcpState state = TcpState::CLOSED;

    uint32_t seqNum = 0;
    uint32_t ackNum = 0;
    
    //About data transmission
    uint16_t winSize = TCP_WIN_SIZE;
    uint16_t remoteWinSize = TCP_WIN_SIZE;
    std::list<SocketBuffer *> sendBuf;
    std::set<SocketDataBuffer *, Cmp> localBuf;
    bool getEOF = false;
    uint32_t nextAck;

    //About Congestion Control
    uint16_t cwnd = TCP_DATA_MAX;
    uint32_t ssthresh = 128 * TCP_DATA_MAX;
    CongestionState congState = SLOW_START;

    float SRTT = RTT;
    float RTTVAR = RTT/2;
    uint32_t RTO = 3 * RTT;

    //For fast-retransmission
    uint32_t lastAck = 0;
    uint32_t lastAckCnt = 0;

    uint16_t szSendBuf = 0;
    uint16_t szLocalBuf = 0;
    uint32_t backlogLimit;
    uint32_t numBacklogs;
    std::map<Addr_t, struct _Socket *> backlogs;
    std::set<struct _Socket *> established;

    //Syscall blocking
    bool isSyscallWaiting = false;
    UUID waitingSyscall;
    int waitingSyscallType;
    SA *waitingSA;
    socklen_t *waitingSocklen;
    uint8_t *waitingBuf;
    uint32_t waitingCnt;
    uint32_t waitingRemain;
    uint16_t waitingRet;

    //bool isServer = false;
    bool isMaster = false;
    bool isBound;

    bool isProcessingData = false;

    //Timer
    UUID timerUUID;    
} Socket;


typedef struct _TCP {
    uint16_t srcPort;
    uint16_t dstPort;
    uint32_t seqNum;
    uint32_t ackNum;
    uint8_t offset;
    uint8_t flag;
    uint16_t winSize;
    uint16_t checksum;
    uint16_t urg;
    uint8_t *data;
} TCPSegment;

class TCPAssignment : public HostModule, public NetworkModule, public SystemCallInterface, private NetworkLog, private TimerModule
{
private:
	//(int pid, int fd) ->
	std::map<Desc_t, Socket *> Sockets;

	//(uint32_t ip, int port) -> int socketIndex
	std::map<Addr_t, Socket *> localSockets;
    std::map<Addr_t, Socket *> remoteSockets;
	
private:
	virtual void timerCallback(void* payload) final;

	Socket *getSocketByDescriptor(int pid, int fd);
	Socket *findSocketByLocalIP(uint32_t ip, int port);
	Socket *findSocketByRemoteIP(uint32_t ip, int port);
    uint16_t calculateTCPChecksum(int32_t, int32_t, TCPSegment, uint32_t);
    uint32_t generateTCPSegment(uint8_t **out, uint16_t srcPort, uint16_t dstPort,
                               uint32_t seqNum, uint32_t ackNum, uint8_t flag, uint16_t winSize,
                               const uint8_t *data, uint32_t dataLength);
    Packet *generateTCPPacket(int32_t srcIP, int32_t dstIP, const uint8_t *segment, uint32_t segmentLength);
    Packet *generateReplyACK(int32_t srcIP, int32_t dstIP, uint32_t seq, TCPSegment tcp, uint16_t newWinSize);
    Packet *generateReplyDataACK(int32_t srcIP, int32_t dstIP, uint32_t seq, uint32_t ack, TCPSegment tcp, uint16_t newWinSize);
    int implicitBind(int pid, int sockfd, uint32_t dstIP);
    Socket *dupSocket(const Socket *orig);
    void finalizeServerEstablish(Socket *m, Socket *socket);
    void dumpSocket(const Socket *s);
    void cleanSocket(Socket *);
    void sendPacketAndQueue(Socket *t, Packet *pkt, uint16_t len, uint32_t timeout = 0);
    
public:
	TCPAssignment(Host* host);
	virtual void initialize();
	virtual void finalize();
	virtual ~TCPAssignment();
protected:
	virtual void systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param) final;
	virtual void packetArrived(std::string fromModule, Packet* packet) final;
	
	/* Syscall Implementations */
    // KENS LAB 1
	virtual int syscall_socket(int pid, int type, int protocol);
	virtual int syscall_close(int pid, int sockfd);
	virtual int syscall_bind(int pid, int sockfd, SA *my_addr, socklen_t addrlen);
	virtual int syscall_getsockname(int pid, int sockfd, SA *addr, socklen_t *addrlen);
    
    // KENS LAB 2
    virtual int syscall_connect(UUID syscallUUID, int pid, int sockfd, SA *addr, socklen_t addrlen);
    virtual int syscall_getpeername(int pid, int sockfd, SA *addr, socklen_t *addrlen);
    virtual int syscall_listen(int pid, int sockfd, int backlog);
    virtual int syscall_accept(UUID syscallUUID, int pid, int sockfd, SA *addr, socklen_t *addrlen);

    // KENS LAB 3
    virtual int syscall_write(UUID syscallUUID, int pid, int sockfd, const void *buf, size_t count);
    virtual int syscall_read(UUID syscallUUID, int pid, int sockfd, void *buf, size_t count);

};

class TCPAssignmentProvider
{
private:
	TCPAssignmentProvider() {}
	~TCPAssignmentProvider() {}
public:
	static HostModule* allocate(Host* host) { return new TCPAssignment(host); }
};

}


#endif /* E_TCPASSIGNMENT_HPP_ */
