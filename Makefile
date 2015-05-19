PROGS=ifcfg-generator
GENERATOR_OBJS=ifcfg-generator.o shvar.o ifcfg-parser.o shared.o

all:	$(PROGS)

shvar.o: shvar.c
	$(CC) $(CFLAGS) `pkg-config glib-2.0 --cflags` -c shvar.c -o shvar.o

shared.o: shared.c
	$(CC) $(CFLAGS) `pkg-config glib-2.0 --cflags` -c shared.c -o shared.o

ifcfg-generator.o: ifcfg-generator.c ifcfg-generator.h shared.h
	$(CC) $(CFLAGS) -g `pkg-config glib-2.0 --cflags` -c ifcfg-generator.c -o ifcfg-generator.o

ifcfg-parser.o: ifcfg-parser.c ifcfg-parser.h ifcfg-generator.h
	$(CC) $(CFLAGS) -g `pkg-config glib-2.0 --cflags` -c ifcfg-parser.c -o ifcfg-parser.o

ifcfg-generator: $(GENERATOR_OBJS)
	$(CC) $(LDFLAGS) -o $@ $(GENERATOR_OBJS) `pkg-config glib-2.0 --libs`

clean:
	rm -f $(PROGS) *.o *~
