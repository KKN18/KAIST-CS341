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
		//this->syscall_connect(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
		break;
	case LISTEN:
		//this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case ACCEPT:
		//this->syscall_accept(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		break;
	case BIND:
		ret = this->syscall_bind(pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				(socklen_t) param.param3_int);
		break;
	case GETSOCKNAME:
		ret = this->syscall_getsockname(pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	case GETPEERNAME:
		//this->syscall_getpeername(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr *>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		break;
	default:
		assert(0);
	}

	returnSystemCall(syscallUUID, ret);
}

void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{

}

void TCPAssignment::timerCallback(void* payload)
{

}

Socket *TCPAssignment::getSocketByDescriptor(int pid, int fd) {
	auto t = std::pair<int, int>(pid, fd);
	if (this->localSockets.count(t) == 0)
		return NULL;

	return this->localSockets[t];
}

Socket *TCPAssignment::findSocketByIP(uint32_t ip, int port) {
	auto t = std::pair<uint32_t, int>(ip, port);
	if (this->boundSockets.count(t) == 0)
		return NULL;

	return this->boundSockets[t];
}

int TCPAssignment::syscall_socket(int pid, int type, int protocol)
{
	Socket *t = (Socket *)malloc(sizeof(Socket));
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

	this->localSockets[std::pair<int, int>(pid, fd)] = t;
	return fd;
}

int TCPAssignment::syscall_close(int pid, int sockfd)
{
	Socket *t = this->getSocketByDescriptor(pid, sockfd);
	if(t == NULL)
		return -1;

	auto t1 = std::pair<int, int>(t->pid, t->fd);
	auto t2 = std::pair<uint32_t, int>(t->ip, t->port);
	this->localSockets.erase(t1);
	if(t->isBound)
		this->boundSockets.erase(t2);
	
	free(t);
	removeFileDescriptor(pid, sockfd);
	return 0;
}

int TCPAssignment::syscall_bind(int pid, int sockfd, struct sockaddr *my_addr, socklen_t addrlen)
{
	Socket *t = this->getSocketByDescriptor(pid, sockfd);
	if(t == NULL) 
		return -1;
	
	else if(t->isBound)
		return -1;

	struct sockaddr_in sa = *(struct sockaddr_in *)my_addr;

	uint32_t ip = (int)sa.sin_addr.s_addr;
	int port = (int)sa.sin_port;

	if(ip != 0)
	{	// If it's not INADDR_ANY
		Socket *k = this->findSocketByIP(ip, port);
		if(k != NULL)
			return -1;
		//Check if INADDR_ANY is already using the port
		k = this->findSocketByIP(0, port);
		if(k != NULL)
			return -1;
	}
	else
	{	//INADDR_ANY
		//Iterate all bound socket to if they have same port
		for(auto it=this->boundSockets.begin(); it != this->boundSockets.end(); it++)
		{
			if(port == it->first.second)
				return -1;
		}
	}

	t->ip = ip;
	t->port = port;
	t->isBound = true;

	this->boundSockets[std::pair<uint32_t, int>(ip, port)] = t;
	return 0;
}

int TCPAssignment::syscall_getsockname(int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	Socket *t = this->getSocketByDescriptor(pid, sockfd);
	if(t == NULL || !t->isBound)
		return -1;

	struct sockaddr_in *sa = (struct sockaddr_in *)addr; 
	*addrlen = sizeof(struct sockaddr_in);

	sa->sin_family = AF_INET;
	sa->sin_port = (in_port_t)t->port;
	sa->sin_addr.s_addr = t->ip;
	memset(&sa->sin_zero, 0, 8);

	return 0;

}

} //Namespace End
