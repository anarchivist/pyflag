INCL	= -I../iosubsys/misc
CFLAGS	= -g -Wall $(INCL)
BINS	= ../bin

$(BINS)/raid_info: raid_info.o
	$(CC) $(CFLAGS) -o $@ raid_info.o $(LIBS)

clean:
	rm -f $(BINS)/raid_info *.o
