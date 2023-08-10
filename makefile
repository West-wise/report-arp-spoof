LDLIBS=-lpcap

all: arp-spoof


main.o: mac.h ip.h ethhdr.h arphdr.h AttackerInfo.h SenderUtil.h TargetUtil.h main.cpp

arphdr.o: mac.h ip.h arphdr.h arphdr.cpp

ethhdr.o: mac.h ethhdr.h ethhdr.cpp

ip.o: ip.h ip.cpp

mac.o : mac.h mac.cpp

AttackerInfo.o : AttackerInfo.h AttackerInfo.cpp

SenderUtil.o : SenderUtil.h SenderUtil.cpp

TargetUtil.o : TargetUtil.h	TargetUtil.cpp

arp-spoof : main.o arphdr.o ethhdr.o ip.o mac.o AttackerInfo.o SenderUtil.o TargetUtil.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f send-arp-test *.o
