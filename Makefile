EXE = 
OBJ = .o
CFLAGS ?= 
CFLAGS += -Ivm
LDFLAGS += -ldl
CPPFLAGS += -DWASP_PLATFORM='"generic"' -DWASP_VERSION='"0.3"' -DWASP_USE_SYNC_TERM -DWASP_SO='".so"'
WASPVM_EXE ?= ./waspvm-rewind$(EXE)
WASPC_EXE ?= ./waspc-rewind$(EXE)
WASP_EXE ?= ./wasp-rewind$(EXE)
WASPLD_EXE ?= waspld-rewind$(EXE)
WASPVM_OBJS += vm/boolean.o vm/channel.o vm/closure.o vm/connection.o vm/core.o vm/error.o vm/file.o vm/format.o vm/init.o vm/list.o vm/memory.o vm/mq.o vm/number.o vm/package.o vm/parse.o vm/primitive.o vm/print.o vm/procedure.o vm/process.o vm/queue.o vm/string.o vm/tag.o vm/tree.o vm/vector.o vm/vm.o vm/multimethod.o vm/plugin.o

$(WASP_EXE): $(WASPC_EXE) $(WASPVM_EXE)
	$(WASPC_EXE) -exe $(WASP_EXE) -stub $(WASPVM_EXE) bin/wasp
	chmod +rx $(WASPC_EXE)

#TODO: This currently relies on an installed WaspVM Devel toolchain.
$(WASPC_EXE): $(WASPVM_EXE)
	waspc -exe $(WASPC_EXE) -stub $(WASPVM_EXE) bin/waspc
	chmod +rx $(WASPC_EXE)

$(WASPVM_EXE): $(WASPVM_OBJS) vm/waspvm.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(WASPVM_EXE) $(WASPVM_OBJS) vm/waspvm.c

$(WASPLD_EXE): $(WASPVM_OBJS) vm/waspld.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(WASPLD_EXE) $(WASPVM_OBJS) vm/waspld.c

vm/%$(OBJ): vm/%.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

clean:
	rm -f vm/*.o $(WASPVM_EXE) $(WASPC_EXE)
	
