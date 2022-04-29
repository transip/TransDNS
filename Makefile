SOURCES=	axfr.cpp\
		base32.cpp \
		base64.cpp \
		dns.cpp \
		dns_compress.cpp \
		dns_data.cpp \
		dns_read.cpp \
		dns_util.cpp \
		edns.cpp \
		hash.cpp \
		hash_cache.cpp \
		log.cpp \
		notify.cpp \
		nsec3.cpp \
		misc.cpp \
		request_context.cpp \
		response_info.cpp \
		settings.cpp \
		simple_config.cpp \
		transdns.cpp

GIT_VERSION := TransDNS\ $(shell git describe --abbrev=4 --dirty --always --tags)
CXX=clang++
CXXFLAGS=-c -std=c++11 -I/usr/local/include/c++/v1 -I/usr/local/include -O2 -ggdb -ffast-math -D_THREAD_SAFE -Wall -Wuninitialized -Wunreachable-code -Wunused -ferror-limit=100 -DVERSION=\"$(GIT_VERSION)\"
LDFLAGS=-ggdb -O2 -L/usr/local/lib/mysql -pthread -lcrypto -lmysqlclient -ffast-math -D_THREAD_SAFE


EXECUTABLE=transdns
OBJS = $(SOURCES:%.cpp=%.o)
OUT_DIR=.
OUT_OBJS=$(OBJS:%=$(OUT_DIR)/%)
TIMEGM_OUT_OBJS=./misc.o ./timegm_test.o
DOMAINLENGTH_OUT_OBJS=./base32.o ./base64.o ./dns.o ./dns_util.o ./domain_length_test.o ./misc.o

$(EXECUTABLE) : $(OUT_OBJS)
	@$(CXX) $(LDFLAGS) -o $@ $(OUT_OBJS) $(LIBS)

%.o : .%.cpp
	@$(CXX) $(CXXFLAGS) $< -o $@

.PHONY: clean all

clean:
	@rm -f $(OUT_DIR)/*.o

install: all
	@install -o root -g wheel -m 700 transdns ${DESTDIR}/usr/local/bin/

timegmtest: $(TIMEGM_OUT_OBJS)
	@$(CXX) $(LDFLAGS) -o $@ $(TIMEGM_OUT_OBJS)

domainlengthtest: $(DOMAINLENGTH_OUT_OBJS)
	@$(CXX) $(LDFLAGS) -o $@ $(DOMAINLENGTH_OUT_OBJS)

all: ${EXECUTABLE}

format:
	clang-format40 -style=webkit -i *.cpp *.h
