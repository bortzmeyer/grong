include $(GOROOT)/src/Make.$(GOARCH)

TARBALL=/tmp/grong.tar.gz

all: server

test: server
	./server -debug=4

server.$O: responder.$O types.$O

responder.$O: types.$O

%.$O: %.go 
	${GC} $<
	gopack grc types.a types.8 # Workaround a bug in the linker

server: server.$O
	${LD} -o $@ server.$O

dist: clean
	(cd ..; tar czvf ${TARBALL} grong/*)

clean:
	rm -f server *~ *.$O *.a
