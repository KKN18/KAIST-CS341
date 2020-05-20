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

#define SYSCALL_DEBUG 0

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
/*    std::set<Socket *> st;

    //Clear sockets first
    for(auto it = this->Sockets.begin(); it != this->Sockets.end(); it++) {
        Socket *t = it->second;
        t->backlogs.clear();
        t->established.clear();
        st.insert((Socket *)it->second);
    }

    //And other remain sockets
    for(auto it = this->localSockets.begin(); it != this->localSockets.end(); it++) {
        Socket *t = it->second;
        t->backlogs.clear();
        t->established.clear();
        st.insert((Socket *)it->second);
    }
    for(auto it = this->remoteSockets.begin(); it != this->remoteSockets.end(); it++) { 
        Socket *t = it->second;
        t->backlogs.clear();
        t->established.clear();
        st.insert((Socket *)it->second);
    }
    for(auto it = st.begin(); it != st.end(); it++)
        delete *it;*/

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

    //printf("packet arrived~\n");

    len = ntohs(len); //IP + TCP Header length

    packet->readData(34, &tcp, 20);
    if(len == 40)
        tcp.data = NULL;
    else {
        tcp.data = new uint8_t[len - 40];   //data length
        packet->readData(54, tcp.data, len-40);    //len-40 : tcp segment data length
    }

    //Check Checksum here
    uint16_t calcChecksum = calculateTCPChecksum(srcIP, dstIP, tcp, len - 20); //Ethernet 14 byte, IP 20 byte
    if(calcChecksum != tcp.checksum) {
        //printf("wrong checksum~\n");
        this->freePacket(packet);
        if(tcp.data != NULL) delete[] tcp.data;
        return;
    }

    bool isSYN = tcp.flag & TCP_FLAG_SYN;
    bool isFIN = tcp.flag & TCP_FLAG_FIN;
    bool isACK = tcp.flag & TCP_FLAG_ACK;

    
    Socket *t = this->findSocketByLocalIP(dstIP, tcp.dstPort);
    //resolve master sockets
    Socket *r = this->findSocketByRemoteIP(srcIP, tcp.srcPort);
    Socket *m = NULL;

    
    /*printf("\n\n");
    printf("SYN ACK FIN : %d %d %d\n", isSYN, isACK, isFIN);
    printf("%d %d %d %d\n", tcp.srcPort, tcp.dstPort, ntohl(tcp.seqNum), ntohl(tcp.ackNum));
    printf("%d %d %d\n", srcIP, dstIP, len);//*/
    //this->dumpSocket(t);
    if(t == NULL) {
        t = findSocketByLocalIP(0, tcp.dstPort); //INADDR_ANY
        if(t == NULL) {
            this->freePacket(packet);
            if(tcp.data != NULL) {
                delete[] tcp.data;
            }
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
    t->remoteWinSize = ntohs(tcp.winSize);
    /*printf("\n\n");
    printf("SYN ACK FIN : %d %d %d\n", isSYN, isACK, isFIN);
    printf("%d %d %d %d\n", tcp.srcPort, tcp.dstPort, ntohl(tcp.seqNum), ntohl(tcp.ackNum));
    printf("%d\n", t->seqNum);*/
    
    //Firstly check wheter ackNum is proper,
    bool proper = false;
    bool isRecv = len > 40;

    //dumpSocket(t);
    if(ntohl(tcp.ackNum) == t->seqNum) //data receiver side
        proper = true;
    //printf("packet received~\n");
    

    if(isFIN) {
        if(t->state < TcpState::ESTAB) {
            //If before establish
            this->freePacket(packet);
            assert(tcp.data == NULL);
            return;
        }
        else if(t->state == TcpState::ESTAB) {
            if(t->nextAck != ntohl(tcp.seqNum)) {
                //If wrong sequence number, (there is missing packets before)
                //then ignore FIN packet
                this->freePacket(packet);
                assert(tcp.data == NULL);
                return;
            }
            else if(isRecv) {
                //If it's data receiver side
                t->getEOF = true;
                if(t->isSyscallWaiting && t->waitingSyscallType == READ) {
                    this->returnSystemCall(t->waitingSyscall, 0);
                    t->isSyscallWaiting = false;
                }
                this->freePacket(packet);
                assert(tcp.data == NULL);
                return;
            }
        }
    }
    /*if (isFIN && (t->state < TcpState::ESTAB || (t->state == TcpState::ESTAB &&
                    (t->nextAck != ntohl(tcp.seqNum) || t->isSyscallWaiting)))) {
        //ignore FIN while processing data transmissions
        this->freePacket(packet);
        if(tcp.data != NULL) {
            delete[] tcp.data;
        }

        printf("nextAck, seq : %d %d\n", t->nextAck, ntohl(tcp.seqNum));
        if(t->nextAck != ntohl(tcp.seqNum) && t->state >= TcpState::ESTAB) {
            //When
            //data out!
            if(SYSCALL_DEBUG) printf("Syscall returned! - pos1\n");
            assert(t->waitingSyscallType == READ);
            this->returnSystemCall(t->waitingSyscall, 0);
            t->isSyscallWaiting = false;
            return;
        }
        else if(t->isSyscallWaiting && t->state >= TcpState::ESTAB) {
            //EOF case
            if(SYSCALL_DEBUG) printf("Syscall returned! - pos2\n");
            assert(t->waitingSyscallType == READ);
            this->returnSystemCall(t->waitingSyscall, -1);
            t->isSyscallWaiting = false;
            proper = true;
        }
        /*else if(t->isSyscallWaiting && t->state == TcpState::ESTAB) {
            this->returnSystemCall(t->waitingSyscall, 0);
            t->isSyscallWaiting = false;
        }
        else {
            return;
        }
    }*/
    else if (isACK) { //data sender side
        //bool isFound = false;
        //find if there is unacked packet in local buffer
        for(auto iter = t->sendBuf.begin(); iter != t->sendBuf.end();) {
            SocketBuffer *sb = (SocketBuffer *)(*iter);
            //printf("ack, sbseq, sblen, state: %d %d %d\n",ntohl(tcp.ackNum), sb->seq, sb->len, sb->state);
            if(ntohl(tcp.ackNum) < sb->seq + sb->len)
                break;
            if(ntohl(tcp.ackNum) == sb->seq + sb->len) {
                //if find
                //isFound = true;

                iter = t->sendBuf.erase(iter);
                t->szSendBuf -= sb->len;
                proper = true;
                
                this->cancelTimer(sb->timerUUID);
                this->freePacket(sb->pkt);
                sb->pkt = NULL;
                sb->socket = NULL;
                TcpState tmp = sb->state;
                delete sb;

                    //printf("hi2 %d %d\n", isRecv, t->isSyscallWaiting);
                
                if(t->waitingSyscallType == WRITE && t->isSyscallWaiting) {
                    if(SYSCALL_DEBUG) printf("Syscall returned! - pos3\n");
                    this->returnSystemCall(t->waitingSyscall, t->waitingRet);
                    t->isSyscallWaiting = false;
                    break;
                }
                if((tmp != TcpState::ESTAB) || (!isFIN && tmp != TcpState::FINWAIT_2))
                    break;
            }
            else if((sb->state == TcpState::ESTAB || (!isFIN && sb->state != TcpState::FINWAIT_2)) && ntohl(tcp.ackNum) >= sb->seq + sb->len) {
                iter = t->sendBuf.erase(iter);
                t->szSendBuf -= sb->len;

                this->cancelTimer(sb->timerUUID);
                this->freePacket(sb->pkt);
                sb->pkt = NULL;
                sb->socket = NULL;
                delete sb;
            }
            else
                iter++;
        }
        /*if(!isFound) {
            if(t->lastAck == ntohl(tcp.ackNum))
                t->lastAckCnt++;
            else {
                t->lastAckCnt = 0;
                t->lastAck = ntohl(tcp.ackNum);
            }

            if(t->lastAckCnt == 3) {
                //Retransmit all in here (Fast retransmission)
                printf("retransmit %d~\n", t->sendBuf.size());
                for(auto iter = t->sendBuf.begin(); iter != t->sendBuf.end(); iter++) {
                    SocketBuffer *sb = (SocketBuffer *)(*iter);
                    if(sb->pkt == NULL)
                        continue;
                    this->cancelTimer(sb->timerUUID);
                    this->sendPacket("IPv4", this->clonePacket(sb->pkt));
                    sb->timerUUID = this->addTimer(sb, TimeUtil::makeTime(DEFAULT_TIMEOUT, TimeUtil::MSEC));
                }
                t->lastAckCnt = 0;
            }
        }*/
    }

    //simultaneous cases
    if(isFIN && isACK && t->state == TcpState::FINWAIT_1) {
        proper = true;
    }
    else if(isSYN && t->state == TcpState::SYNSENT) {
        proper = true;
    }
    else if((isSYN || (isACK && !isSYN && !isFIN)) && t->state == TcpState::SYNRCVD) {
        proper = true;
    }
    else if(isSYN && t->state == TcpState::ESTAB) {
        //In this case, the last SYNACK is lost. Send again 
        tcp.flag = 0;
        Packet *reply = generateReplyACK(srcIP, dstIP, t->seqNum, tcp, t->winSize);
        this->sendPacket("IPv4", reply);

        t->ackNum = ntohl(tcp.seqNum)+1;
        t->nextAck = ntohl(tcp.seqNum)+1;
        return;
    }
    else if(isFIN && t->state == TcpState::CLOSING) {
        //IN this case, the last ACK of FINACK is lost. Send again 
        tcp.flag = 0;
        Packet *reply = generateReplyACK(srcIP, dstIP, t->seqNum, tcp, t->winSize);
        this->sendPacket("IPv4", reply);
        return;
    } 
    else if(isFIN && isACK && (t->state > TcpState::ESTAB)) {
        proper = true;
    }
    /*else if(isFIN && isACK && t->state == TcpState::SYNRCVD && proper) {
        t->state = TcpState::ESTAB;
        if(t->isSyscallWaiting) {
            this->returnSystemCall(t->waitingSyscall, 0);
            t->isSyscallWaiting = false;
        }
    }*/
    

    if(!proper) { 
        //ignore improper ACK
        this->freePacket(packet);
        if(tcp.data != NULL) delete[] tcp.data;
        return;
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
            sendPacketAndQueue(newSocket, reply, 0);
            newSocket->ackNum = ntohl(tcp.seqNum)+1;
            //In here, if SYN (from SYNSENT) is in buffer, we have to clear it
            
              printf("segfault 4\n");
            for(auto iter = newSocket->sendBuf.begin(); iter != newSocket->sendBuf.end();) {
                SocketBuffer *sb = (SocketBuffer *)(*iter);
                if(sb->state == TcpState::SYNSENT) {
                    this->cancelTimer(sb->timerUUID);
                    this->freePacket(sb->pkt);
                    sb->socket = NULL;
                    iter = newSocket->sendBuf.erase(iter);
                    delete sb;
                    break;
                }
                else
                    iter++;
                
            }

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
                t->nextAck = ntohl(tcp.seqNum)+1;

                if(t->isSyscallWaiting) {
                    this->returnSystemCall(t->waitingSyscall, 0);
                    t->isSyscallWaiting = false;
                }
            }
            else if(!isACK && Addr_t(srcIP, tcp.srcPort) == t->remoteAddr) {
                //simultaneous open, which is SYN and (recieved.src == current.dst)
                Packet *reply = generateReplyACK(srcIP, dstIP, t->seqNum - 1 , tcp, t->winSize);
                
            printf("segfault 5\n");
                for(auto iter = t->sendBuf.begin(); iter != t->sendBuf.end(); iter++) {
                    SocketBuffer *sb = (SocketBuffer *)(*iter);
                    if(sb->state == TcpState::SYNSENT) {
                        this->cancelTimer(sb->timerUUID);
                        this->freePacket(sb->pkt);
                sb->pkt = NULL;
                        sb->socket = NULL;
                        iter = t->sendBuf.erase(iter);
                        delete sb;
                    }
                    else
                        iter++;
                    
                }


                t->state = TcpState::SYNRCVD;
                sendPacketAndQueue(t, reply, 0);
                t->ackNum = ntohl(tcp.seqNum)+1;
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
            t->nextAck = ntohl(tcp.seqNum);
            if(t->isSyscallWaiting) {
            if(SYSCALL_DEBUG) printf("Syscall returned! - pos5\n");
                this->returnSystemCall(t->waitingSyscall, 0);
                t->isSyscallWaiting = false;
            }
        }
    }
    else if (isFIN && isACK) {
        /* if(ntohl(tcp.ackNum) != t->seqNum) { 
            //ignore not proper ACK            
            this->freePacket(packet);
            if(tcp.data != NULL) delete[] tcp.data;
            return;
        } */
        if(t->state == TcpState::ESTAB) {
            t->state = TcpState::CLOSE_WAIT;
            tcp.flag = 0;
            Packet *reply = generateReplyACK(srcIP, dstIP, t->seqNum, tcp, t->winSize);
            this->sendPacket("IPv4", reply);
            t->ackNum = ntohl(tcp.seqNum)+1;

            //this->syscall_close(t->pid, t->fd);
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
            this->sendPacketAndQueue(t, reply, 0, 2 * TCP_MSL);
            t->ackNum = ntohl(tcp.seqNum)+1;
        }
        else if(t->state == TcpState::TIMED_WAIT) {
            tcp.flag = 0;
            
            printf("segfault 6\n");
            for(auto iter = t->sendBuf.begin(); iter != t->sendBuf.end(); iter++) {
                SocketBuffer *sb = (SocketBuffer *)(*iter);
                //printf("sb seq, len : %d %d\n", sb->seq, sb->len);
                if(sb->socket->state== TcpState::TIMED_WAIT) { 
                    if(sb->pkt != NULL) {
                        Packet *tmp = this->clonePacket(sb->pkt);
                        this->sendPacket("IPv4", tmp);
                        sb->timerUUID = this->addTimer(sb, TimeUtil::makeTime(2 * TCP_MSL, TimeUtil::MSEC));
                    }
                    break;   
                }
            }
        }
    }
    else if(isACK) {
        //printf("ack dumped for tcp ack %d (which seq : %d)\n", ntohl(tcp.ackNum), t->seqNum);
        //this->dumpSocket(t);

        if(t->state == TcpState::SYNRCVD && m != NULL) { //If m is null, it's a case of simultaneous open
            //If before ESTABLISHED, handle it
            t->state = TcpState::ESTAB;
            m->backlogs.erase(t->remoteAddr);
            m->numBacklogs--;
            
            t->ackNum = ntohl(tcp.seqNum);
            t->nextAck = ntohl(tcp.seqNum);

            if(m->isSyscallWaiting) {
                finalizeServerEstablish(m, t);
            }
            else {
                m->established.insert(t);
            }
        }
        else if(t->state == TcpState::SYNRCVD)
        {
            t->state = TcpState::ESTAB;
            t->ackNum = ntohl(tcp.seqNum);
            t->nextAck = t->ackNum;
            if(t->isSyscallWaiting) {
            if(SYSCALL_DEBUG) printf("Syscall returned! - pos6\n");
                this->returnSystemCall(t->waitingSyscall, 0);
                t->isSyscallWaiting = false;
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
            //Simultaneous closing
            t->state = TcpState::TIMED_WAIT;
            SocketBuffer *sb = new SocketBuffer;
            sb->socket = t;
            sb->state = TcpState::TIMED_WAIT;
            sb->pkt = NULL;
            //Simultaneous closing
            sb->timerUUID = this->addTimer(sb, TimeUtil::makeTime(2 * TCP_MSL, TimeUtil::MSEC));
            t->sendBuf.push_back(sb);
            //t->timerUUID = this->addTimer(t, TimeUtil::makeTime(2 * TCP_MSL,TimeUtil::SEC));
        }
        else if((t->state == TcpState::ESTAB || t->state == TcpState::FINWAIT_2) && isRecv && len > 40) {
            //TODO : out of order arrival
            //if data received,
            SocketDataBuffer *res = new SocketDataBuffer;
            res->seq = ntohl(tcp.seqNum);
            res->len = len - 40; // remove of IP+TCP header size
            res->buf = new uint8_t[len - 40];
            res->offset = 0;
            memcpy(res->buf, tcp.data, res->len);
            /*
            if(t->localBuf.count(res) != 0) {
                SocketDataBuffer *sdb = *(SocketDataBuffer *)t->localBuf.find(res);
                if(sdb->acked) {    //if already acked
                    Packet * reply = generateReplyDataACK(srcIP, dstIP, t->seqNum, sdb->seq + sdb->len, tcp, t->winSize);
                    this->sendPacket("IPv4", reply);
                }

                delete[] res->buf;
                delete res;
                return;
            }*/
            //printf("seq, nextAck : %d %d", res->seq, t->nextAck);
            if(res->seq < (int32_t)t->nextAck) { //If already acked
                Packet * reply = generateReplyDataACK(srcIP, dstIP, t->seqNum, res->seq + res->len, tcp, t->winSize);
                this->sendPacket("IPv4", reply);
                delete[] res->buf;
                delete res;
                
                this->freePacket(packet);   
                if(tcp.data != NULL) delete[] tcp.data;
                return;
            }

            t->localBuf.insert(res);           
            t->winSize -= res->len;
            //printf("\nres : %d %d\n", res->seq, res->len);
            //TODO: cumulative ack
            //dump localBuf here
            bool acked = false;
            for(auto iter = t->localBuf.begin(); iter != t->localBuf.end(); iter++) {
                SocketDataBuffer *sdb = (SocketDataBuffer *)(*iter);
                if(sdb->acked == true)
                    continue;

                //printf("sdb_seq : %d\n", sdb->seq);
                if(sdb->seq == (int32_t)t->nextAck) {
                    t->nextAck += sdb->len;

                    Packet * reply = generateReplyDataACK(srcIP, dstIP, t->seqNum, t->nextAck, tcp, t->winSize);
                    this->sendPacket("IPv4", reply);
                    //printf("ACKED~~~\n");
                    acked = true;
                    sdb->acked = true;
                }
                else {
                    break;
                }
            }

            if(acked && t->isSyscallWaiting) {
                if(SYSCALL_DEBUG) printf("Syscall returned! - pos7\n");
            
                assert(t->waitingSyscallType == READ);
                this->returnSystemCall(t->waitingSyscall, 0);
                t->isSyscallWaiting = false;
            }

        }
    }
    
    this->freePacket(packet);
    if(tcp.data != NULL) {
        delete[] tcp.data;
    }

    return;
}

void TCPAssignment::timerCallback(void* payload)
{
    printf("payload : %p\n", payload);
    SocketBuffer *sb = (SocketBuffer *)payload;
    printf("sb : %d %d %d\n", sb->seq, sb->len, sb->state);
    this->cancelTimer(sb->timerUUID);
    //-Socket(sb->socket);
    if(sb->state == TcpState::TIMED_WAIT) {
        //sb->socket->state = TcpState::CLOSED;
        if(sb->pkt != NULL)
            this->freePacket(sb->pkt);
        this->cleanSocket(sb->socket);
        sb->socket = NULL;
        delete sb;
        return;
    }
    if(sb->pkt == NULL || sb->socket == NULL)
        return;
    assert(sb->pkt != NULL && sb->socket != NULL);
    Packet *tmp = this->clonePacket(sb->pkt);
    this->sendPacket("IPv4", tmp);
    sb->timerUUID = this->addTimer(sb, TimeUtil::makeTime(DEFAULT_TIMEOUT, TimeUtil::MSEC));
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

uint16_t TCPAssignment::calculateTCPChecksum(int32_t srcIP, int32_t dstIP, TCPSegment segment, uint32_t segmentLength)
{
    uint8_t *tmp = new uint8_t[segmentLength];
    TCPSegment tcp = segment;
    tcp.checksum = 0;
    memcpy(tmp, &tcp, 20);

    if(segmentLength > 20)
        memcpy(&tmp[20], tcp.data, segmentLength - 20);
    
    uint16_t chk = ~NetworkUtil::tcp_sum(srcIP, dstIP, tmp, segmentLength);
    delete[] tmp;
    return htons(chk);
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
            if(SYSCALL_DEBUG) printf("Syscall returned! - pos8\n");
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
/*
    printf("--------syscall returned------\n");
    printf("ret : %d\n", connfd);
    this->dumpSocket(est);
    printf("---------syscall returned-----\n\n");
*/
            if(SYSCALL_DEBUG) printf("Syscall returned! - pos9\n");
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
    printf("seqNum : %d\n", s->seqNum);
    printf("\n");
}

void TCPAssignment::cleanSocket(Socket *t)
{
    auto t1 = Desc_t(t->pid, t->fd);
	this->Sockets.erase(t1);
	if((t->isMaster || t->remoteAddr == Addr_t(-1, -1)) && this->localSockets.count(t->localAddr))
		this->localSockets.erase(t->localAddr);

    if(this->remoteSockets.count(t->remoteAddr) != 0)
	    this->remoteSockets.erase(t->remoteAddr);

	removeFileDescriptor(t->pid, t->fd);
	delete t;
}

void TCPAssignment::sendPacketAndQueue(Socket *t, Packet *pkt, uint16_t len, uint32_t timeout) {
   
    SocketBuffer *buf_packet = new SocketBuffer;
    buf_packet->seq = t->seqNum;
    buf_packet->len = len;
    assert(pkt != NULL);
    buf_packet->pkt = this->clonePacket(pkt);
    buf_packet->socket = t;
    buf_packet->state = t->state;

    buf_packet->timerUUID = this->addTimer(buf_packet, TimeUtil::makeTime(timeout, TimeUtil::MSEC));

    this->sendPacket("IPv4", pkt);
    t->sendBuf.push_back(buf_packet);
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

        if(t->state == ESTAB) {
            t->state = TcpState::FINWAIT_1;
        }
        else if(t->state == CLOSE_WAIT) {
            t->state = TcpState::LAST_ACK;
        } 
        
        t->seqNum++;
        
        sendPacketAndQueue(t, packet, 0);
        delete[] fin;
    }
    if(t->state == CLOSED) {
        this->cleanSocket(t);
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
	//printf("Perrname called : %d\n", t->state);
    if(t == NULL || t->state < TcpState::ESTAB)
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

    t->isMaster = false;
    t->state = TcpState::SYNSENT;
    sendPacketAndQueue(t, packet, 0);

    t->remoteAddr = Addr_t(sa->sin_addr.s_addr, sa->sin_port);
    this->remoteSockets[t->remoteAddr] = t;
    
    t->isSyscallWaiting = true;
    t->waitingSyscallType = CONNECT;
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
    t->established = std::set<Socket *>();

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
    t->waitingSyscallType = ACCEPT;
    t->waitingSyscall = syscallUUID;

    if(t->established.empty())
        return 0;
    
    Socket *est = (Socket *)(*t->established.begin());
    t->established.erase(t->established.begin());
    
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
        
        sendPacketAndQueue(t, packet, real_len);

        t->seqNum += real_len;
        t->szSendBuf += real_len;

        delete[] data;
        if(t->szSendBuf > t->remoteWinSize) {
            t->isSyscallWaiting = true;
            t->waitingSyscallType = WRITE;
            t->waitingSyscall = syscallUUID;
            t->waitingRet = i + real_len;
            if(SYSCALL_DEBUG) printf("Waiting write here\n");
            return -2;
        }
    }
    return count;
}

int TCPAssignment::syscall_read(UUID syscallUUID, int pid, int sockfd, void *buf, size_t count) {
    Socket *t = getSocketByDescriptor(pid, sockfd);
    if(t == NULL || t->state != TcpState::ESTAB || t->getEOF == true)
        return -1;
    if(count == 0)
        return 0;
    uint8_t *copy_buf = static_cast<uint8_t *>(buf);
    size_t remain = count;
    int buf_offset = 0;

    while(remain > 0 && !t->localBuf.empty()) {
        auto iter = t->localBuf.begin();
        SocketDataBuffer *sdb = (SocketDataBuffer *)(* iter);
        if(!sdb->acked)
            break;

        int avail_len = sdb->len - sdb->offset;

        if (avail_len <= (int)remain) {
            memcpy(&copy_buf[buf_offset], &sdb->buf[sdb->offset], avail_len);
            //first->offset += avail_len;
            t->winSize += avail_len;
            buf_offset += avail_len;
            remain -= avail_len;

            t->localBuf.erase(iter);
            delete[] sdb->buf;
            delete sdb;
        }
        else {
            memcpy(&copy_buf[buf_offset], &sdb->buf[sdb->offset], remain);
            sdb->offset += remain;
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
    t->waitingSyscallType = READ;
    t->waitingCnt = count;
    t->waitingBuf = &copy_buf[buf_offset];
    t->waitingSyscall = syscallUUID;

    return -2;
}


} //Namespace End