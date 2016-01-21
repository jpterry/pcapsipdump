#uncommend next line for regex support
#DEFS ?= -DUSE_REGEXP
LIBS ?= -lpcap -lstdc++

all: pcapsipdump

pcapsipdump: pcapsipdump.cpp calltable.cpp calltable.h
	@$(CXX) $(CPPFLAGS) $(LDFLAGS) $(LIBS) $(DEFS) makefile-helpers/check_libpcap.c -o /dev/null $(LIBS) 2>/dev/null || (\
	  echo "Required library not found: pcap "; \
	  echo "Please install it in your distribution-specific manner, e.g.:"; \
	  echo " yum install libpcap-devel"; \
	  echo " apt-get install libpcap-dev"; \
	  echo " cd ~ports/net/libpcap && make install"; \
	  false)
	$(CXX) $(CPPFLAGS) $(LDFLAGS) $(DEFS) pcapsipdump.cpp calltable.cpp -o pcapsipdump $(LIBS)

pcapsipdump-debug: pcapsipdump.cpp calltable.cpp calltable.h
	$(CXX) $(CPPFLAGS) $(LDFLAGS) $(DEFS) -ggdb pcapsipdump.cpp calltable.cpp -o pcapsipdump-debug  $(LIBS)

clean:
	rm -f pcapsipdump

install:
	install pcapsipdump ${DESTDIR}/usr/sbin/pcapsipdump
	install redhat/pcapsipdump.init ${DESTDIR}/etc/rc.d/init.d/pcapsipdump
	install redhat/pcapsipdump.sysconfig ${DESTDIR}/etc/sysconfig/pcapsipdump
	mkdir -p ${DESTDIR}/var/spool/pcapsipdump
	chmod 0700 ${DESTDIR}/var/spool/pcapsipdump
