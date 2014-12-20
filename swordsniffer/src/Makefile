object=sniffer.o pcapfunction.o signalfunction.o
swordSniffer:$(object)
	gcc -g -o swordsniffer $(object) `pkg-config --cflags --libs gtk+-3.0` -export-dynamic -lpcap -lpthread

sniffer.o:sniffer.c sniffer.h
	gcc -w -g -c sniffer.c sniffer.h `pkg-config --cflags --libs gtk+-3.0` -export-dynamic
pcapfunction.o:pcapfunction.c pcapfunction.h 
	gcc -w -g -c pcapfunction.c pcapfunction.h `pkg-config --cflags --libs gtk+-3.0` -export-dynamic -lpcap
signalfunction.o:signalfunction.c
	gcc -w -g -c signalfunction.c `pkg-config --cflags --libs gtk+-3.0` -export-dynamic -lpthread -lpcap

.PHONY:clean
clean:
	rm $(object)
