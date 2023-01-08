LDLIBS=-lpcap

all: airodump

main.o: airodump.h main.cpp

airodump.o: airodump.h airodump.cpp

airodump: main.o airodump.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f airodump *.o