ROOT=$(shell pwd)

EXE = 
OBJ = .o

WASPVM_EXE ?= $(ROOT)/waspvm$(EXE)
WASPC_EXE ?= $(ROOT)/waspc$(EXE)
WASP_EXE ?= $(ROOT)/wasp$(EXE)
WASPLD_EXE ?= $(ROOT)/waspld$(EXE)

CFLAGS ?= 
CFLAGS += -Ivm
LDFLAGS += -ldl
CPPFLAGS += -DWASP_PLATFORM='"generic"' -DWASP_VERSION='"0.3"' -DWASP_USE_SYNC_TERM -DWASP_SO='".so"'

WASPVM_OBJS += vm/boolean.o vm/channel.o vm/closure.o vm/connection.o vm/core.o vm/error.o vm/file.o vm/format.o vm/init.o vm/list.o vm/memory.o vm/mq.o vm/number.o vm/package.o vm/parse.o vm/primitive.o vm/print.o vm/procedure.o vm/process.o vm/queue.o vm/string.o vm/tag.o vm/tree.o vm/vector.o vm/vm.o vm/multimethod.o vm/plugin.o vm/shell.o

build: $(WASP_EXE) $(WASPC_EXE) $(WASPVM_EXE)

install: $(WASP_EXE)
	cd mod && $(WASP_EXE) bin/install.ms

repl: $(WASP_EXE)
	if which rlwrap; then cd mod && rlwrap $(WASP_EXE); else cd mod && $(WASP_EXE); fi

$(WASP_EXE): $(WASPC_EXE) $(WASPVM_EXE)
	cd mod && $(WASPC_EXE) -exe $(WASP_EXE) -stub $(WASPVM_EXE) bin/wasp
	chmod +rx $(WASP_EXE)

#TODO: This currently relies on a precompiled set of modules.
$(WASPC_EXE): $(WASPVM_EXE) $(WASPLD_EXE)
	cd mod && $(WASPLD_EXE) $(WASPVM_EXE) $(shell cat mod/waspc.mf) $(WASPC_EXE)
	chmod +rx $(WASPC_EXE)

$(WASPVM_EXE): $(WASPVM_OBJS) vm/waspvm.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(WASPVM_EXE) $(WASPVM_OBJS) vm/waspvm.c

$(WASPLD_EXE): $(WASPVM_OBJS) vm/waspld.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(WASPLD_EXE) $(WASPVM_OBJS) vm/waspld.c

vm/%$(OBJ): vm/%.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

clean:
	rm -f vm/*.o $(WASPVM_EXE) $(WASPC_EXE) $(WASPLD_EXE) $(WASP_EXE)
	
