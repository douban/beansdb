include $(GOROOT)/src/Make.inc

TARG=btest
CGOFILES=htree.go bitcask.go codec.go
CGO_OFILES=record.o codec.o htree.o bitcask.o quicklz.o hint.o diskmgr.o
CGO_LDFLAGS=-lpthread
CLEANFILES += btest

include $(GOROOT)/src/Make.pkg

%.o: ../%.c ../%.h
		gcc -DNDEBUG $(_CGO_CFLAGS_$(GOARCH)) -O2 -g -c -fPIC $(CFLAGS) $< 
%.o: fnv1a.h

t: install main.go
	gofmt -w -l -spaces=true -tabwidth=4 -tabindent=false *.go
	$(GC) main.go
	$(LD) -o htree main.$(O)
	6prof -d 10 htree  

th: ../htree.h ../htree.c test_htree.c ../record.c ../bitcask.c
	gcc -pg -lpthread -o th test_htree.c
	./th

tr: test_record.c ../record.c
	gcc -O3 -pg -o tr test_record.c
	time ./tr
