/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */


#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <cerrno>
#include <list>
#include <map>
#include <queue>
#include <E/Networking/E_Packet.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include <E/E_TimeUtil.hpp>
#include "TCPAssignment.hpp"

namespace E
{

TCPAssignment::TCPAssignment(Host* host) : HostModule("TCP", host),
		NetworkModule(this->getHostModuleName(), host->getNetworkSystem()),
		SystemCallInterface(AF_INET, IPPROTO_TCP, host),
		NetworkLog(host->getNetworkSystem()),
		TimerModule(host->getSystem())
{

}

TCPAssignment::~TCPAssignment()
{

}

void TCPAssignment::initialize()
{

}

void TCPAssignment::finalize()
{

}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param)
{
	int ret = -1;
	switch(param.syscallNumber)
	{
	case SOCKET:
		ret = this->syscall_socket(pid, param.param1_int, param.param2_int);
	    break;
	case CLOSE:
		ret = this->syscall_close(pid, param.param1_int);
        break;
	case READ:
		ret = this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
        if(ret != -2) {
            this->returnSystemCall(syscallUUID, ret);
        }
		return;
	case WRITE:
		ret = this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
        if(ret != -2) {
            this->returnSystemCall(syscallUUID, ret);
        }
		return;
	case CONNECT:
		ret = this->syscall_connect(syscallUUID, pid, param.param1_int,
		        static_cast<SA *>(param.param2_ptr), (socklen_t)param.param3_int);
        if(ret == -1) {
            this->returnSystemCall(syscallUUID, -1);
        }
        return;
	case LISTEN:
		ret = this->syscall_listen(pid, param.param1_int, param.param2_int);
		break;
	case ACCEPT:
        ret = this->syscall_accept(syscallUUID, pid, param.param1_int,
				static_cast<SA*>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
        if(ret == -1) {
            this->returnSystemCall(syscallUUID, -1);
        }
		return;
	case BIND:
		ret = this->syscall_bind(pid, param.param1_int,
				static_cast<SA *>(param.param2_ptr),
				(socklen_t) param.param3_int);
		break;
	case GETSOCKNAME:
		ret = this->syscall_getsockname(pid, param.param1_int,
				static_cast<SA *>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	case GETPEERNAME:
		ret = this->syscall_getpeername(pid, param.param1_int,
				static_cast<SA *>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
        break;
	default:
		assert(0);
	}

    this->returnSystemCall(syscallUUID, ret);
}

void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{
    uint32_t srcIP;
    uint32_t dstIP;
    TCPSegment tcp;
    uint16_t len;
    //bool isServer = false;

    packet->readData(14+2, &len, 2);
    packet->readData(14+12, &srcIP, 4);
    packet->readData(14+16, &dstIP, 4);

    len = ntohs(len); //IP + TCP Header length

    packet->readData(34, &tcp, 20);
    if(len == 40)
        tcp.data = NULL;
    else {
        tcp.data = new uint8_t[len - 40];   //data length
        packet->readData(54, tcp.data, len-40);    //len-40 : tcp segment data length
    }

    bool isSYN = tcp.flag & TCP_FLAG_SYN;
    bool isFIN = tcp.flag & TCP_FLAG_FIN;
    bool isACK = tcp.flag & TCP_FLAG_ACK;


    /*printf("\nSYN ACK FIN : %d %d %d\n", isSYN, isACK, isFIN);
    printf("%d %d %d %d\n", ntohs(tcp.srcPort), ntohs(tcp.dstPort), ntohl(tcp.seqNum), ntohl(tcp.ackNum));
    printf("%d %d\n\n", srcIP, dstIP);/**/
    Socket *t = this->findSocketByLocalIP(dstIP, tcp.dstPort);
    //resolve master sockets
    Socket *r = this->findSocketByRemoteIP(srcIP, tcp.srcPort);
    Socket *m;

    if(t == NULL) {
        t = findSocketByLocalIP(0, tcp.dstPort); //INADDR_ANY
        if(t == NULL) {
            this->freePacket(packet);
            if(tcp.data != NULL) delete[] tcp.data;
            return;
        }
        if(t != NULL) t->localAddr = Addr_t(dstIP, tcp.dstPort);
    }
    if(t->isMaster && r != NULL) {
        m = t;
        t = r;
    }
    else if(isACK && t->isMaster && r== NULL) {
        m = t;
        if(t == NULL)
            t = m->backlogs[Addr_t(srcIP, tcp.srcPort)];

        //Even null
        if(t == NULL) {
            this->freePacket(packet);
            if(tcp.data != NULL) delete[] tcp.data;
            return;
        }
    }

    //this->dumpSocket(t);

    if(isSYN) {
        if(t->state == TcpState::LISTEN) {
            //if exceed backlog limit
            if(t->backlogLimit == t->numBacklogs) {
                this->freePacket(packet);
                if(tcp.data != NULL) delete[] tcp.data;
                return;
            }

            Socket *newSocket = dupSocket(t);

            newSocket->state = TcpState::SYNRCVD;
            newSocket->remoteAddr = Addr_t(srcIP, tcp.srcPort);
            //printf("something here\n");
            //this->dumpSocket(newSocket);
            this->remoteSockets[newSocket->remoteAddr] = newSocket;
            t->backlogs[newSocket->remoteAddr] = newSocket;
            t->numBacklogs++;
        
            //send SYNACK

            Packet *reply = generateReplyACK(srcIP, dstIP, newSocket->seqNum++, tcp, t->winSize);
            this->sendPacket("IPv4", reply);
            newSocket->ackNum = ntohl(tcp.seqNum)+1;
        }
        else if(t->state == TcpState::SYNSENT) {
            /* if(!isACK || ntohl(tcp.ackNum) != t->seqNum) {
                this->freePacket(packet);
                return;
            }*/
            //If syn sent, and received syn

            if(isACK && ntohl(tcp.ackNum) == t->seqNum) { //When received valid synack
                //If valid synack,
                t->state = ESTAB;

                //Send ACK of SYNACK
                tcp.flag = 0;
                Packet *reply = generateReplyACK(srcIP, dstIP, t->seqNum, tcp, t->winSize);
                this->sendPacket("IPv4", reply);
                t->ackNum = ntohl(tcp.seqNum)+1;

                if(t->isSyscallWaiting) {
                    this->returnSystemCall(t->waitingSyscall, 0);
                    t->isSyscallWaiting = false;
                }
            }
            else if(!isACK && Addr_t(srcIP, tcp.srcPort) == t->remoteAddr) {
                //Simultaneous open, which is SYN and (recieved.src == current.dst)
                Packet *reply = generateReplyACK(srcIP, dstIP, t->seqNum, tcp, t->winSize);
                this->sendPacket("IPv4", reply);
                t->ackNum = ntohl(tcp.seqNum)+1;
                t->state = TcpState::SYNRCVD;
            }
        }
        else if(isACK && t->state == TcpState::SYNRCVD) {
            if(ntohl(tcp.ackNum) != t->seqNum) {
                this->freePacket(packet);
                return;
            }
            //Send ACK of SYNACK
            tcp.flag = 0;
            Packet *reply = generateReplyACK(srcIP, dstIP, t->seqNum, tcp, t->winSize);
            this->sendPacket("IPv4", reply);
            t->ackNum = ntohl(tcp.seqNum)+1;

            t->state = ESTAB;
            if(t->isSyscallWaiting) {
                this->returnSystemCall(t->waitingSyscall, 0);
                t->isSyscallWaiting = false;
            }
        }
    }
    else if (isFIN && isACK) {
        /*if(ntohl(tcp.ackNum) != t->seqNum) { 
            //ignore not proper ACK            
            this->freePacket(packet);
            if(tcp.data != NULL) delete[] tcp.data;
            return;
        }*/
        if(t->state == TcpState::ESTAB) {
            t->state = TcpState::CLOSE_WAIT;
            tcp.flag = 0;
            Packet *reply = generateReplyACK(srcIP, dstIP, t->seqNum, tcp, t->winSize);
            this->sendPacket("IPv4", reply); 
            t->ackNum = ntohl(tcp.seqNum)+1;
        }
        else if(t->state == TcpState::FINWAIT_1) {
            //Simultaneous Close
            t->state = TcpState::CLOSING;
            tcp.flag = 0;
            Packet *reply = generateReplyACK(srcIP, dstIP, t->seqNum, tcp, t->winSize);
            this->sendPacket("IPv4", reply);
            t->ackNum = ntohl(tcp.seqNum)+1;
        }
        else if(t->state == TcpState::FINWAIT_2) {
            t->state = TcpState::TIMED_WAIT;
            tcp.flag = 0;
            Packet *reply = generateReplyACK(srcIP, dstIP, t->seqNum, tcp, t->winSize);
            this->sendPacket("IPv4", reply);
            t->ackNum = ntohl(tcp.seqNum)+1;
            t->timerUUID = this->addTimer(t, TimeUtil::makeTime(2 * TCP_MSL,TimeUtil::SEC));

        }
        else if(t->state == TcpState::TIMED_WAIT) {
            tcp.flag = 0;
            Packet * reply = generateReplyACK(srcIP, dstIP, t->seqNum, tcp, t->winSize);
            this->sendPacket("IPv4", reply);
            t->ackNum = ntohl(tcp.seqNum)+1;

            this->cancelTimer(t->timerUUID);
            t->timerUUID = this->addTimer(t, TimeUtil::makeTime(2 * TCP_MSL,TimeUtil::SEC));
        }
    }
    else if(isACK) {
        //printf("ack dumped for tcp ack %d (which seq : %d)\n", ntohl(tcp.ackNum), t->seqNum);
        //this->dumpSocket(t);

        //Firstly check wheter ackNum is proper,
        bool proper = false;
        bool isRecv = false;
        if(ntohl(tcp.ackNum) == t->seqNum) //data receiver side
            proper = isRecv = true;
        else { //data sender side
            //find if there is unacked packet in local buffer
            for(auto iter = t->sendBuf.begin(); iter != t->sendBuf.end(); iter++) {
                SocketBuffer *sb = (SocketBuffer *)(*iter);
    
                if(ntohl(tcp.ackNum) == sb->seq + sb->len) { 
                    //if find
                    t->sendBuf.erase(iter);
                    t->szSendBuf -= sb->len;
                    proper = true;
                    
                    delete[] sb->buf;
                    delete sb;
                    
                    if(t->isSyscallWaiting) {
                        this->returnSystemCall(t->waitingSyscall, t->waitingRet);
                        t->isSyscallWaiting = false;
                    }
                    break;   
                }
            }
        }

        if(!proper) { 
            //ignore improper ACK            
            this->freePacket(packet);
            if(tcp.data != NULL) delete[] tcp.data;
            return;
        }
        if(t->state == TcpState::SYNRCVD) {
            //If before ESTABLISHED, handle it
            t->state = TcpState::ESTAB;
            m->backlogs.erase(t->remoteAddr);
            m->numBacklogs--;
            
            if(m->isSyscallWaiting) {
                finalizeServerEstablish(m, t);
            }
            else {
                m->established.push(t);
            }
        }
        else if(t->state == TcpState::FINWAIT_1) {
            t->state = TcpState::FINWAIT_2;
        }
        else if(t->state == TcpState::LAST_ACK) {
            t->state = TcpState::CLOSED;
            this->cleanSocket(t);
        }
        else if(t->state == TcpState::CLOSING) {
            t->state = TcpState::TIMED_WAIT;
            t->timerUUID = this->addTimer(t, TimeUtil::makeTime(2 * TCP_MSL,TimeUtil::SEC));
        }
        else if(t->state == TcpState::ESTAB && isRecv && len > 40) {
            //TODO : out of order arrival
            //if data received,
            SocketBuffer *res = new SocketBuffer;
            res->seq = tcp.seqNum;
            res->len = len - 40; // remove of IP+TCP header size
            res->buf = new uint8_t[len - 40];
            res->offset = 0;
            memcpy(res->buf, tcp.data, res->len);
            
            t->winSize -= res->len;

            if(t->isSyscallWaiting) {
                if(t->waitingRemain == res->len) {
                    memcpy(t->waitingBuf, res->buf, t->waitingRemain);
                    t->winSize += t->waitingRemain;

                    t->isSyscallWaiting = false;
                    this->returnSystemCall(t->waitingSyscall, t->waitingCnt);
                }
                else if (t->waitingRemain < res->len) {
                    memcpy(t->waitingBuf, res->buf, t->waitingRemain);
                    t->winSize += t->waitingRemain;
                    t->isSyscallWaiting = false;
                    this->returnSystemCall(t->waitingSyscall, t->waitingCnt);
                    res->offset += t->waitingRemain;
                    t->localBuf.push_back(res);
                }
                else {
                    memcpy(t->waitingBuf, res->buf, res->len);
                    t->winSize += res->len;
                    t->waitingRemain -= res->len;
                    t->waitingBuf = &t->waitingBuf[res->len];
                }
            }
            else
                t->localBuf.push_back(res);
            
            //Send ACK of data transmission
            Packet * reply = generateReplyDataACK(srcIP, dstIP, t->seqNum, ntohl(tcp.seqNum) + res->len, tcp, t->winSize);
            this->sendPacket("IPv4", reply);
        }
    }
    if(tcp.data != NULL) delete[] tcp.data;
}

void TCPAssignment::timerCallback(void* payload)
{
    Socket *t = (Socket *)payload;
    if(t->state == TcpState::TIMED_WAIT) {
        t->state = TcpState::CLOSED;
        this->cleanSocket(t);
    }
}

/* Helper functions */
Socket *TCPAssignment::getSocketByDescriptor(int pid, int fd)
{
	auto t = Desc_t(pid, fd);
	if (this->Sockets.count(t) == 0)
		return NULL;

	return this->Sockets[t];
}

Socket *TCPAssignment::findSocketByLocalIP(uint32_t ip, int port)
{
	auto t = Addr_t(ip, port);
	if (this->localSockets.count(t) == 0)
		return NULL;

	return this->localSockets[t];
}

Socket *TCPAssignment::findSocketByRemoteIP(uint32_t ip, int port)
{
	auto t = Addr_t(ip, port);
	if (this->remoteSockets.count(t) == 0)
		return NULL;

	return this->remoteSockets[t];
}

int TCPAssignment::implicitBind(int pid, int sockfd, uint32_t dstIP)
{
    uint32_t ip;
    int pt = this->getHost()->getRoutingTable((uint8_t *)&dstIP);
    if(!this->getHost()->getIPAddr((uint8_t *)&ip, pt))
        return -1;


    Socket *t = getSocketByDescriptor(pid, sockfd);
    
    if(t == NULL)
        return -1;
    else if(t->isBound)
        return -1;

    SA_in sa;
    sa.sin_addr.s_addr = ip;

    for(int i=32688; i<65536; i++) {
        sa.sin_port = htons((uint16_t)i);
        if(this->syscall_bind(pid, sockfd, (SA *)&sa, sizeof(sa)) == 0) {
            return i;
        }
    }    
    return -1;
}

uint32_t TCPAssignment::generateTCPSegment(uint8_t **out, uint16_t srcPort, uint16_t dstPort,
                            uint32_t seqNum, uint32_t ackNum, uint8_t flag, uint16_t winSize,
                            const uint8_t *data, uint32_t dataLength)
{
    uint8_t *t = new uint8_t[20 + dataLength];
    winSize = htons(winSize);

    memcpy(t, &srcPort, 2);
    memcpy(t+2, &dstPort, 2);

    *(uint32_t *)&t[4] = htonl(seqNum);
    *(uint32_t *)&t[8] = htonl(ackNum);
    t[12] = 80;
    t[13] = flag;
    memcpy(t+14, &winSize, 2);
    memset(t+16, 0, 4);

    if(dataLength > 0)
        memcpy(t+20, data, dataLength);

    *out = t;
    return (20 + dataLength);
}

Packet *TCPAssignment::generateTCPPacket(int32_t srcIP, int32_t dstIP, const uint8_t *segment, uint32_t segmentLength)
{
    uint16_t checksum = ~NetworkUtil::tcp_sum(srcIP, dstIP, segment, segmentLength);
    *(uint16_t *)&segment[16] = htons(checksum);
    uint8_t *buf = new uint8_t[14 + 20 + segmentLength]; //Ethernet + IP + TCP
    memset(buf, 0, 34+segmentLength);

    *(uint16_t *)&buf[14+2]  = htons(segmentLength + 20);
    *(uint32_t *)&buf[14+12] = srcIP;
    *(uint32_t *)&buf[14+16] = dstIP;
    memcpy(&buf[34], segment, segmentLength);


    Packet *t = this->allocatePacket(34+segmentLength);
    t->writeData(0, buf, 34+segmentLength);

    //If error, remove this
    delete[] buf;
    return t;
}

Packet *TCPAssignment::generateReplyACK(int32_t srcIP, int32_t dstIP, uint32_t seq, TCPSegment tcp, uint16_t newWinSize)
{
    uint8_t *x;
    uint32_t sz = this->generateTCPSegment(&x, tcp.dstPort, tcp.srcPort, seq, ntohl(tcp.seqNum) + 1,
                                           tcp.flag | TCP_FLAG_ACK, newWinSize, NULL, 0);
    Packet *t = generateTCPPacket(dstIP, srcIP, x, sz);
    delete[] x;
    return t;
}

Packet *TCPAssignment::generateReplyDataACK(int32_t srcIP, int32_t dstIP, uint32_t seq, uint32_t ack, TCPSegment tcp, uint16_t newWinSize)
{
    uint8_t *x;
    uint32_t sz = this->generateTCPSegment(&x, tcp.dstPort, tcp.srcPort, seq, ack,
                                           tcp.flag | TCP_FLAG_ACK, newWinSize, NULL, 0);
    Packet *t = generateTCPPacket(dstIP, srcIP, x, sz);
    delete[] x;
    return t;
}

Socket *TCPAssignment::dupSocket(const Socket *orig)
{
    //printf("Socket dup called~\n");

    Socket *t = new Socket;
    
    //this->dumpSocket(orig);
    t->pid = orig->pid;
    t->fd = -1;
    t->type = orig->type;
    t->protocol = orig->protocol;
    t->localAddr = orig->localAddr;
    t->remoteAddr = orig->remoteAddr;
    t->state = orig->state;
    t->seqNum = 0;
    t->ackNum = 0;
    t->backlogLimit = 0;
    t->numBacklogs = 0;
    t->backlogs = std::map<Addr_t, Socket *>{};
    t->established = std::queue<Socket *>{};
    t->isSyscallWaiting = false;
    t->waitingSA = NULL;
    t->waitingSocklen = NULL;
    t->isMaster = false;
    t->isBound = orig->isBound;

    //this->dumpSocket(t);
    //printf("Socket dup END~\n");
    
    return t;
}

void TCPAssignment::finalizeServerEstablish(Socket *m, Socket *est)
{
    assert(m->isSyscallWaiting);

    int connfd = this->createFileDescriptor(est->pid);
    if(connfd < 0) {      
        this->returnSystemCall(m->waitingSyscall, -1);
        m->isSyscallWaiting = false;
        return;
    }
 
    est->fd = connfd;
    this->Sockets[Desc_t(est->pid, connfd)] = est;
    //this->remoteSockets[est->remoteAddr] = est;

    SA_in *output = (SA_in *)m->waitingSA;
    socklen_t *outputLen = m->waitingSocklen;

    output->sin_family = AF_INET;
    output->sin_port = est->remoteAddr.second;
    output->sin_addr.s_addr = est->remoteAddr.first;
    memset(&output->sin_zero, 0, 8);
    *outputLen = sizeof(SA_in);

    /*printf("--------syscall returned------\n");
    printf("ret : %d\n", connfd);
    this->dumpSocket(est);
    printf("---------syscall returned-----\n\n"); */

    this->returnSystemCall(m->waitingSyscall, connfd);
    m->isSyscallWaiting = false;
    m->waitingSA = NULL;
    m->waitingSocklen = NULL;
}

void TCPAssignment::dumpSocket(const Socket *s)
{
    printf("<<\n");
    printf("pid / fd : %d %d\n", s->pid, s->fd);
    printf("lAddr => %d:%d\n", s->localAddr.first, s->localAddr.second);
    printf("rAddr => %d:%d\n", s->remoteAddr.first, s->remoteAddr.second);
    printf("isMaster : %d\n", s->isMaster);
    printf("Backlog : %d / %d\n", s->numBacklogs, s->backlogLimit);
    printf("State : %d\n", s->state);
    printf("\n");
}

void TCPAssignment::cleanSocket(Socket *t)
{
    auto t1 = Desc_t(t->pid, t->fd);
	this->Sockets.erase(t1);
	if(this->localSockets.count(t->localAddr))
		this->localSockets.erase(t->localAddr);

    if(this->remoteSockets.count(t->remoteAddr) != 0)
	    this->remoteSockets.erase(t->remoteAddr);

	removeFileDescriptor(t->pid, t->fd);
	delete t;
}

//KENS LAB 1
int TCPAssignment::syscall_socket(int pid, int type, int protocol)
{
	Socket *t =  new Socket;
	int fd = this->createFileDescriptor(pid);
	if(t == NULL)
		return -1;
	if (fd < 0)
		return -1;
	
	t->pid = pid;
	t->fd = fd;
	t->type = type;
	t->protocol = protocol;
    t->isBound = false;
    t->state = CLOSED;

	this->Sockets[Desc_t(pid, fd)] = t;
	return fd;
}

int TCPAssignment::syscall_close(int pid, int sockfd)
{
	Socket *t = this->getSocketByDescriptor(pid, sockfd);
	if(t == NULL)
		return -1;

    //Lab 2-2 Start
    //Send FIN here
    if(t->state == ESTAB || t->state == CLOSE_WAIT) {

        uint8_t *fin;
        uint32_t sz = this->generateTCPSegment(&fin, t->localAddr.second, t->remoteAddr.second,
                                        t->seqNum, t->ackNum, TCP_FLAG_FIN | TCP_FLAG_ACK, t->winSize,
                                        NULL, 0);
        Packet *packet = this->generateTCPPacket(t->localAddr.first, t->remoteAddr.first,
                                            fin, sz);
        this->sendPacket("IPv4", packet);

        SocketBuffer *buf_packet = new SocketBuffer;
        buf_packet->seq = t->seqNum++;
        buf_packet->len = -1;
        buf_packet->offset = 0;
        buf_packet->buf = new uint8_t[sz]; //Save TCP Segment here
        memcpy(buf_packet->buf, fin, sz);
        t->sendBuf.push_back(buf_packet);
        delete[] fin;
    }
    if(t->state == ESTAB) {
        t->state = TcpState::FINWAIT_1;
    }
    else if(t->state == CLOSE_WAIT) {
        t->state = TcpState::LAST_ACK;
    }    
    return 0;
}

int TCPAssignment::syscall_bind(int pid, int sockfd, SA *my_addr, socklen_t addrlen)
{
	Socket *t = this->getSocketByDescriptor(pid, sockfd);
	if(t == NULL) 
		return -1;
	else if(t->isBound)
		return -1;

    SA_in sa = *(SA_in *)my_addr;
	uint32_t ip = (uint32_t)sa.sin_addr.s_addr;
	int port = sa.sin_port;

	if(ip != 0)
	{	// If it's not INADDR_ANY
		Socket *k = this->findSocketByLocalIP(ip, port);
		if(k != NULL)
			return -1;
		//Check if INADDR_ANY is already using the port
		k = this->findSocketByLocalIP(0, port);
		if(k != NULL)
			return -1;
	}
	else
	{	//INADDR_ANY
		//Iterate all bound socket to if they have same port
		for(auto it=this->localSockets.begin(); it != this->localSockets.end(); it++)
		{
			if(port == it->first.second)
				return -1;
		}
	}

	t->localAddr = Desc_t(ip, port);
    t->isBound = true;

	this->localSockets[Addr_t(ip, port)] = t;
	return 0;
}

int TCPAssignment::syscall_getsockname(int pid, int sockfd, SA *addr, socklen_t *addrlen)
{
	Socket *t = this->getSocketByDescriptor(pid, sockfd);
	if(t == NULL || !t->isBound)
		return -1;

	SA_in *sa = (SA_in *)addr; 
	*addrlen = sizeof(SA_in);

	sa->sin_family = AF_INET;
	sa->sin_port = (in_port_t)t->localAddr.second;
	sa->sin_addr.s_addr = t->localAddr.first;
	memset(&sa->sin_zero, 0, 8);

	return 0;

}

// KENS LAB 2
int TCPAssignment::syscall_getpeername(int pid, int sockfd, SA *addr, socklen_t *addrlen) {
	Socket *t = this->getSocketByDescriptor(pid, sockfd);
	if(t == NULL || t->state != ESTAB)
        return -1;

	SA_in *sa = (SA_in *)addr; 
	*addrlen = sizeof(SA_in);

	sa->sin_family = AF_INET;
	sa->sin_port = (in_port_t)t->remoteAddr.second;
	sa->sin_addr.s_addr = t->remoteAddr.first;
	memset(&sa->sin_zero, 0, 8);

	return 0;
}


int TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int sockfd, SA *addr, socklen_t addrlen)
{
    Socket *t = getSocketByDescriptor(pid, sockfd);
    SA_in *sa = (SA_in *)addr;
    if(t == NULL)
        return -1;
    
    if(!t->isBound) {
        //Implicit bind
        if(this->implicitBind(pid, sockfd, sa->sin_addr.s_addr) == -1)
            return -1;
    }    
    //printf("> Implicitly bound! to %d:%d\n", t->localAddr.first, t->localAddr.second);

    //Send SYN here
    uint8_t *syn;
    uint32_t sz = this->generateTCPSegment(&syn, t->localAddr.second, sa->sin_port,
                                     t->seqNum++, 0, TCP_FLAG_SYN, t->winSize,
                                     NULL, 0);
    
    Packet *packet = this->generateTCPPacket(t->localAddr.first, sa->sin_addr.s_addr,
                                          syn, sz);
    
    delete[] syn;
    this->sendPacket("IPv4", packet);
    t->state = TcpState::SYNSENT;
    t->remoteAddr = Addr_t(sa->sin_addr.s_addr, sa->sin_port);
    this->remoteSockets[t->remoteAddr] = t;
    
    t->isSyscallWaiting = true;
    t->waitingSyscall = syscallUUID;
    return 0;
}

int TCPAssignment::syscall_listen(int pid, int sockfd, int backlog)
{
    Socket *t = getSocketByDescriptor(pid, sockfd);
    //printf("Now listening...----------\n");
    //this->dumpSocket(t);
    if(t == NULL || !t->isBound)
        return -1;

    t->backlogLimit = backlog;
    t->numBacklogs = 0;

    t->backlogs = std::map<Addr_t, Socket *>();
    t->established = std::queue<Socket *>();

    //t->isServer = true;
    t->isMaster = true;
    t->state = TcpState::LISTEN;

    
    return 0;
}


int TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int sockfd, SA *addr, socklen_t *addrlen)
{
    //printf("Accept called from pid/fd : %d %d\n", pid, sockfd);
    Socket *t = getSocketByDescriptor(pid, sockfd);
    if(t == NULL || !t->isBound || !t->isMaster)
        return -1;

    t->waitingSA = addr;
    t->waitingSocklen = addrlen;
    t->isSyscallWaiting = true;
    t->waitingSyscall = syscallUUID;

    if(t->established.empty())
        return 0;
    
    Socket *est = t->established.front();
    t->established.pop();
    
    this->finalizeServerEstablish(t, est);
    return 0;
}


// KENS LAB 3
int TCPAssignment::syscall_write(UUID syscallUUID, int pid, int sockfd, const void *buf, size_t count) 
{
    Socket *t = getSocketByDescriptor(pid, sockfd);
    if(t == NULL || t->state != TcpState::ESTAB)
        return -1;
    if(count == 0)
        return 0;
    
    //TODO : deal with initial buffer
    uint8_t *data;
    
    for(size_t i=0; i < count; i += 512) { //As the statement, we should split packets into max-len 512
        int real_len = 512 < (count - i) ? 512 : (count - i);
        uint32_t sz = this->generateTCPSegment(&data, t->localAddr.second, t->remoteAddr.second,
                                               t->seqNum, t->ackNum, TCP_FLAG_ACK, t->winSize,
                                               static_cast<const uint8_t *>(buf)+i, real_len);
        Packet *packet = this->generateTCPPacket(t->localAddr.first, t->remoteAddr.first, data, sz);
        
        this->sendPacket("IPv4", packet);
        
        SocketBuffer *buf_packet = new SocketBuffer;
        buf_packet->seq = t->seqNum;
        buf_packet->len = real_len;
        buf_packet->offset = 0;
        buf_packet->buf = new uint8_t[sz]; //Save TCP Segment here
        memcpy(buf_packet->buf, data, sz);
        t->sendBuf.push_back(buf_packet);
        t->seqNum += real_len;
        t->szSendBuf += real_len;

        delete[] data;
        if(t->szSendBuf > TCP_WIN_SIZE) {
            t->isSyscallWaiting = true;
            t->waitingSyscall = syscallUUID;
            t->waitingRet = i + real_len;
            return -2;

        }
    }
    return count;
}

int TCPAssignment::syscall_read(UUID syscallUUID, int pid, int sockfd, void *buf, size_t count) {
    Socket *t = getSocketByDescriptor(pid, sockfd);
    if(t == NULL || t->state != TcpState::ESTAB)
        return -1;
    if(count == 0)
        return 0;

    uint8_t *copy_buf = static_cast<uint8_t *>(buf);
    size_t remain = count;
    int buf_offset = 0;
    while(remain > 0 && !t->localBuf.empty()) {
        SocketBuffer *first = t->localBuf.front();
        int avail_len = first->len - first->offset;
        if (avail_len <= (int)remain) {
            memcpy(&copy_buf[buf_offset], &first->buf[first->offset], avail_len);
            //first->offset += avail_len;
            t->winSize += avail_len;
            buf_offset += avail_len;
            remain -= avail_len;


            t->localBuf.pop_front();
            delete[] first->buf;
            delete first;
        }
        else {
            memcpy(&copy_buf[buf_offset], &first->buf[first->offset], remain);
            first->offset += remain;
            t->winSize += remain;
            remain -= remain;
            buf_offset += remain;
        }
    }

    if(remain == 0)
        return count;
    if(buf_offset != 0)
        return buf_offset;

    t->isSyscallWaiting = true;
    t->waitingRemain = remain;
    t->waitingCnt = count;
    t->waitingBuf = &copy_buf[buf_offset];
    t->waitingSyscall = syscallUUID;

    return -2;
}


} //Namespace End
