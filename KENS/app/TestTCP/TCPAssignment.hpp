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
#include <vector>
#include <utility>

#include <E/E_TimerModule.hpp>

namespace E
{

typedef struct _Socket
{
	//process information
	int pid;
	int fd;

	//socket info
	int type;
	int protocol;
	uint32_t ip;
	int port;

	bool isBound;
} Socket;

class TCPAssignment : public HostModule, public NetworkModule, public SystemCallInterface, private NetworkLog, private TimerModule
{
private:
	//(int pid, int fd)
	std::map<std::pair<int, int>, Socket *> localSockets;
	//(uint32_t ip, int port) -> int socketIndex
	std::map<std::pair<uint32_t, int>, Socket *> boundSockets;
	
private:
	virtual void timerCallback(void* payload) final;

	Socket *getSocketByDescriptor(int pid, int fd);
	Socket *findSocketByIP(uint32_t ip, int port);

public:
	TCPAssignment(Host* host);
	virtual void initialize();
	virtual void finalize();
	virtual ~TCPAssignment();
protected:
	virtual void systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param) final;
	virtual void packetArrived(std::string fromModule, Packet* packet) final;
	
	/* Syscall Implementations */
	virtual int syscall_socket(int pid, int type, int protocol);
	virtual int syscall_close(int pid, int sockfd);
	virtual int syscall_bind(int pid, int sockfd, struct sockaddr *my_addr, socklen_t addrlen);
	virtual int syscall_getsockname(int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen);
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
