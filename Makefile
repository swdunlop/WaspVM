EXE = 
OBJ = .o
CFLAGS ?= 
CFLAGS += -Ivm
CPPFLAGS += -DWASP_PLATFORM='"generic"' -DWASP_VERSION='"0.3"' -DWASP_USE_SYNC_TERM
WASPVM_EXE ?= waspvm-rewind$(EXE)
WASPC_EXE ?= waspc-rewind$(EXE)
WASPVM_OBJS += vm/boolean.o vm/channel.o vm/closure.o vm/connection.o vm/core.o vm/error.o vm/file.o vm/format.o vm/init.o vm/list.o vm/memory.o vm/mq.o vm/number.o vm/package.o vm/parse.o vm/primitive.o vm/print.o vm/procedure.o vm/process.o vm/queue.o vm/string.o vm/tag.o vm/tree.o vm/vector.o vm/vm.o

#TODO: This currently relies on an installed WaspVM Devel toolchain.
$(WASPC_EXE): $(WASPVM_EXE)
	waspc -exe waspc-rewind -stub $(WASPVM_EXE) bin/waspc

$(WASPVM_EXE): $(WASPVM_OBJS) bin/waspvm.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(WASPVM_EXE) $(WASPVM_OBJS) bin/waspvm.c

vm/%$(OBJ): vm/%.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

clean:
	rm -f vm/*.o $(WASPVM_EXE)
	
