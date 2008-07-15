ROOT=$(shell pwd)
SYS=sys

EXE = 
OBJ = .o
SO = .so

WASPVM_EXE ?= $(ROOT)/waspvm$(EXE)
WASPC_EXE ?= $(ROOT)/waspc$(EXE)
WASP_EXE ?= $(ROOT)/wasp$(EXE)
WASPDOC_EXE ?= $(ROOT)/waspdoc$(EXE)
WASPLD_EXE ?= $(ROOT)/waspld$(EXE)

CFLAGS ?= 
CFLAGS += -Ivm
LDFLAGS += -levent
CPPFLAGS += -DWASP_PLATFORM='"generic"' -DWASP_VERSION='"0.3"' -DWASP_SO='".so"'

EXEFLAGS += -rdynamic -ldl
SOFLAGS += -shared

WASPVM_OBJS += vm/boolean.o vm/channel.o vm/closure.o vm/connection.o vm/core.o vm/error.o vm/file.o vm/format.o vm/init.o vm/list.o vm/memory.o vm/mq.o vm/number.o vm/package.o vm/parse.o vm/primitive.o vm/print.o vm/procedure.o vm/process.o vm/queue.o vm/string.o vm/tag.o vm/tree.o vm/vector.o vm/vm.o vm/multimethod.o vm/plugin.o vm/shell.o vm/os.o

SYS_REGEX ?= $(SYS)/regex$(SO)
SYS_FILESYSTEM ?= $(SYS)/filesystem$(SO)
SUBSYSTEMS += $(SYS_REGEX) $(SYS_FILESYSTEM)

build: $(WASPDOC_EXE) $(WASP_EXE) $(WASPC_EXE) $(WASPVM_EXE)

install: $(WASPDOC_EXE) $(WASP_EXE) $(WASPC_EXE) $(WASPVM_EXE)
	cd mod && $(WASP_EXE) bin/install.ms

repl: $(WASP_EXE)
	if which rlwrap; then cd mod && rlwrap $(WASP_EXE); else cd mod && $(WASP_EXE); fi

objects: $(WASPVM_OBJS)

$(WASPDOC_EXE): $(WASPC_EXE) $(WASPVM_EXE) $(SUBSYSTEMS)
	cd mod && $(WASPC_EXE) -exe $(WASPDOC_EXE) -stub $(WASPVM_EXE) bin/waspdoc
	chmod +rx $(WASPDOC_EXE)

$(WASP_EXE): $(WASPC_EXE) $(WASPVM_EXE) $(SUBSYSTEMS)
	cd mod && $(WASPC_EXE) -exe $(WASP_EXE) -stub $(WASPVM_EXE) bin/wasp
	chmod +rx $(WASP_EXE)

#TODO: This currently relies on a precompiled set of modules.
$(WASPC_EXE): $(WASPVM_EXE) $(WASPLD_EXE)
	cd mod && $(WASPLD_EXE) $(WASPVM_EXE) $(shell cat mod/waspc.mf) $(WASPC_EXE)
	chmod +rx $(WASPC_EXE)

%$(EXE): vm/%.c $(WASPVM_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(EXEFLAGS) -o $@ $(WASPVM_OBJS) $<

vm/%$(OBJ): vm/%.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

sys/%$(SO): sys/%.c
	$(CC) $(LDFLAGS) $(SOFLAGS) $(CFLAGS) $(CPPFLAGS) $< -o $@

bootstrap:
	cd mod && waspc */*.ms

clean:
	rm -f vm/*.o $(WASPVM_EXE) $(WASPC_EXE) $(WASPLD_EXE) $(WASP_EXE) sys/*.so
	
