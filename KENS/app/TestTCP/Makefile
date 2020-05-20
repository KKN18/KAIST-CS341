PROGRAM= testTCP
EXTRA_CXXFLAGS+= -std=gnu++11 #-fsanitize=address -lasan
EXTRA_LIBS+= -lgtest -lgtest_main
include ../../mk/find_tcp_solution.mk

EXTRA_OBJS+= $(TCP_SOLUTION)

include ../../mk/Makefile
