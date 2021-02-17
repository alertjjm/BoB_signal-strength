LDLIBS=-lpcap

all: signal-strength

signal-strength: main.o header.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f signal-strength *.o