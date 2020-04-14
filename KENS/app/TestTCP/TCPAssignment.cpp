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
#include <map>
#include <queue>
#include <E/Networking/E_Packet.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
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
		//this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case WRITE:
		//this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
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
        packet->readData(54, &tcp.data, len-40);    //len-40 : tcp segment data length
    }
    //printf("%d %d %d %d\n", ntohs(tcp.srcPort), ntohs(tcp.dstPort), ntohl(tcp.seqNum), ntohl(tcp.ackNum));
    //printf("%d %d\n\n", dstIP, tcp.dstPort);
    Socket *t = findSocketByLocalIP(dstIP, tcp.dstPort);

    if(t == NULL) {
        t = findSocketByLocalIP(0, tcp.dstPort); //INADDR_ANY
    }

    if(t == NULL) {
        this->freePacket(packet);
        if(tcp.data != NULL) delete[] tcp.data;
        return;
    }

    bool isSYN = tcp.flag & TCP_FLAG_SYN;
    bool isACK = tcp.flag & TCP_FLAG_ACK;

    if(isSYN) {
        if(t->state == TcpState::SYNSENT) {
            /* if(!isACK || ntohl(tcp.ackNum) != t->seqNum) {
                this->freePacket(packet);
                return;
            }*/
            //If syn sent, and received syn

            if(isACK && ntohl(tcp.ackNum) == t->seqNum) { //When received valid synack
                //If valid synack,
                t->state = ESTAB;

                tcp.flag = 0;
                Packet *reply = generateReplyACK(srcIP, dstIP, t->seqNum++, tcp, len-40);
                this->sendPacket("IPv4", reply);

                if(t->isSyscallWaiting) {
                    this->returnSystemCall(t->waitingSyscall, 0);
                    t->isSyscallWaiting = false;
                }
            }
            else if(!isACK && Addr_t(srcIP, tcp.srcPort) == t->remoteAddr) { //Simultaneous open, which is SYN and (recieved.src == current.dst)
                t->seqNum -= 1;
                Packet *reply = generateReplyACK(srcIP, dstIP, t->seqNum++, tcp, len-40);
                this->sendPacket("IPv4", reply);
                t->state = TcpState::SYNRCVD;
            }
        }
        else if(t->state == TcpState::LISTEN) {
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
            //this->remoteSockets[newSocket->remoteAddr] = newSocket;
            t->backlogs[newSocket->remoteAddr] = newSocket;
            t->numBacklogs++;
        
            //send SYNACK
            Packet *reply = generateReplyACK(srcIP, dstIP, newSocket->seqNum++, tcp, len-40);
            this->sendPacket("IPv4", reply);
        }
        else if(t->state == SYNRCVD) {
            printf("established~");
            if(!isACK || ntohl(tcp.ackNum) != t->seqNum) {
                this->freePacket(packet);
                return;
            }
            t->seqNum++;
            t->state = ESTAB;
            if(t->isSyscallWaiting) {
                this->returnSystemCall(t->waitingSyscall, 0);
                t->isSyscallWaiting = false;
            }
        }
    }
    else if(isACK) {
        Socket *m; //to backup master socket if isMaster
        if(t->isMaster) {
            m = t;
            //If it's server socket, change it to spawned socket
            t = this->findSocketByRemoteIP(srcIP, tcp.srcPort);

            //If it's null may be in backlogs
            if(t == NULL)
                t = m->backlogs[Addr_t(srcIP, tcp.srcPort)];

            //Even null
            if(t == NULL) {
                this->freePacket(packet);
                if(tcp.data != NULL) delete[] tcp.data;
                return;
            }
        }
        //printf("ack dumped for tcp ack %d \n", ntohl(tcp.ackNum));
        //this->dumpSocket(t);
        
        if(ntohl(tcp.ackNum) != t->seqNum) { 
            //ignore not proper ACK            
            this->freePacket(packet);
            if(tcp.data != NULL) delete[] tcp.data;
            return;
        }
        
        if(t->state == SYNRCVD) {
            //If before ESTABLISHED, handle it
            t->state = ESTAB;
            m->backlogs.erase(t->remoteAddr);
            m->numBacklogs--;
            
            if(m->isSyscallWaiting) {
                finalizeServerEstablish(m, t);
            }
            else {
                m->established.push(t);
            }
        }
        t->seqNum++;
    }
    if(tcp.data != NULL) delete[] tcp.data;
}

void TCPAssignment::timerCallback(void* payload)
{

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
                            uint8_t *data, uint32_t dataLength)
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

Packet *TCPAssignment::generateReplyACK(int32_t srcIP, int32_t dstIP, uint16_t seq, TCPSegment tcp, uint32_t dataLength)
{
    uint8_t *x;
    uint32_t sz = this->generateTCPSegment(&x, tcp.dstPort, tcp.srcPort, seq, ntohl(tcp.seqNum) + 1,
                                           tcp.flag | TCP_FLAG_ACK, TCP_WIN_SIZE, tcp.data, dataLength);
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
    this->remoteSockets[est->remoteAddr] = est;

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
    printf("\n");
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

	auto t1 = Desc_t(t->pid, t->fd);
	this->Sockets.erase(t1);
	if(t->isBound)
		this->localSockets.erase(t->localAddr);
	
    if(this->remoteSockets.count(t->remoteAddr) != 0)
	    this->remoteSockets.erase(t->remoteAddr);

	delete t;
	removeFileDescriptor(pid, sockfd);
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
                                     t->seqNum++, 0, TCP_FLAG_SYN, TCP_WIN_SIZE,
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
    
    assert(est->state == TcpState::ESTAB);
    
    this->finalizeServerEstablish(t, est);
    return 0;
}

} //Namespace End
