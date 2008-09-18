include Makefile.cf

WASPVM_EXE ?= $(ROOT)/stubs/waspvm-$(PLATFORM)$(EXE)
WASPC_EXE ?= $(ROOT)/waspc$(EXE)
WASP_EXE ?= $(ROOT)/wasp$(EXE)
WASPDOC_EXE ?= $(ROOT)/waspdoc$(EXE)
MOSREF_EXE ?= $(ROOT)/mosref$(EXE)
WASPLD_EXE ?= $(ROOT)/waspld$(EXE)

CFLAGS += -Ivm -I.

SOFLAGS += -shared

SALSA_OBJS += vm/salsa20$(OBJ) vm/salsa$(OBJ)
CURVE_OBJS += vm/curve$(OBJ) vm/curve25519_i64$(OBJ)

WASPVM_OBJS += vm/boolean$(OBJ) vm/channel$(OBJ) vm/closure$(OBJ) vm/connection$(OBJ) vm/core$(OBJ) vm/error$(OBJ) vm/file$(OBJ) vm/format$(OBJ) vm/init$(OBJ) vm/list$(OBJ) vm/memory$(OBJ) vm/mq$(OBJ) vm/number$(OBJ) vm/package$(OBJ) vm/parse$(OBJ) vm/primitive$(OBJ) vm/print$(OBJ) vm/procedure$(OBJ) vm/process$(OBJ) vm/queue$(OBJ) vm/string$(OBJ) vm/tag$(OBJ) vm/tree$(OBJ) vm/vector$(OBJ) vm/vm$(OBJ) vm/multimethod$(OBJ) vm/shell$(OBJ) vm/os$(OBJ) vm/time$(OBJ) vm/regex$(OBJ) vm/filesystem$(OBJ) $(CURVE_OBJS) $(SALSA_OBJS) vm/crc32$(OBJ) $(LIBRX)

# vm/plugin$(OBJ)  -- Disabled until after 1.0

LIBWASPVM ?= libwaspvm$(SO)

$(WASPVM_EXE): vm/waspvm$(OBJ) $(WASPVM_OBJS) $(LIBRX)
	$(CC) $(CFLAGS) $(LDFLAGS) $(WASPVM_OBJS) $< $(EXEFLAGS) -o $@
	test z$(DEBUG) = z && strip $(WASPVM_EXE) || true

#TODO: This currently relies on a precompiled set of modules.
$(WASPC_EXE): $(WASPVM_EXE) $(WASPLD_EXE)
	cp mod/local-config.ms mod/site/config.ms
	cp mod/local-config.mo mod/site/config.mo
	cd mod && $(WASPLD_EXE) $(WASPVM_EXE) $(shell cat mod/waspc.mf) $(WASPC_EXE)
	chmod +rx $(WASPC_EXE)

$(WASPDOC_EXE): $(WASPC_EXE) $(WASPVM_EXE)
	cd mod && $(WASPC_EXE) -exe $(WASPDOC_EXE) -stub $(WASPVM_EXE) bin/waspdoc
	chmod +rx $(WASPDOC_EXE)

$(MOSREF_EXE): $(WASPC_EXE) $(WASPVM_EXE)
	cd mod && $(WASPC_EXE) -exe $(MOSREF_EXE) -stub $(WASPVM_EXE) bin/mosref
	chmod +rx $(MOSREF_EXE)

$(WASP_EXE): $(WASPC_EXE) $(WASPVM_EXE) 
	cd mod && $(WASPC_EXE) -exe $(WASP_EXE) -stub $(WASPVM_EXE) bin/wasp
	chmod +rx $(WASP_EXE)

$(LIBRX):
	cd rx && make lib

install: $(WASPDOC_EXE) $(WASP_EXE) $(WASPC_EXE) $(WASPVM_EXE)
	cd mod && $(WASP_EXE) bin/install.ms

zip-package: 
	bzr export ../waspvm-$(VERSION).zip 

exe-package: $(WASPDOC_EXE) $(WASP_EXE) $(WASPC_EXE) $(WASPVM_EXE)
	./package.sh $(PLATFORM) waspvm-$(VERSION)-$(PLATFORM)

debug: $(WASP_EXE)
	if which rlwrap; then cd mod && rlwrap gdb $(WASP_EXE); else cd mod && gdb $(WASP_EXE); fi
	
valgrind: $(WASP_EXE)
	if which rlwrap; then cd mod && rlwrap valgrind --leak-check=full $(WASP_EXE); else cd mod && valgrind --leak-check=full $(WASP_EXE); fi
	
repl: $(WASP_EXE)
	if which rlwrap; then cd mod && rlwrap $(WASP_EXE); else cd mod && $(WASP_EXE); fi

objects: $(WASPVM_OBJS)

%$(EXE): vm/%$(OBJ) $(WASPVM_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(WASPVM_OBJS) $< $(EXEFLAGS) -o $@
	test z$(DEBUG) = z && strip $(WASPVM_EXE) || true

vm/%$(OBJ): vm/%.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

bootstrap:
	cd mod && waspc */*.ms

clean:
	rm -f vm/*$(OBJ) $(WASPDOC_EXE) $(WASPVM_EXE) $(WASPC_EXE) $(WASPLD_EXE) $(WASP_EXE)
	cd rx && make clean
	rm -rf package

test: test-waspvm test-mosref test-affiliation
test-waspvm: test-url test-http-url test-spawn-connection
test-mosref: test-bridge test-curve25519 test-salsa test-socks test-mosref-base

test-%: test/%.ms $(WASP_EXE) 
	cd mod && $(WASP_EXE) ../$<

sref: $(MOSREF_EXE)
	if which rlwrap; then cd mod && rlwrap $(MOSREF_EXE); else cd mod && $(MOSREF_EXE); fi

