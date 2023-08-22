.PHONY: clean

CLANG:=clang
VMLINUX:=vmlinux.h
CFLAGS:= -g -Wall
OUTPUT:=.output
ARCH := $(shell uname -m | sed 's/x86_64/x86/')
BPFTOOL=/usr/local/sbin/bpftool
_dummy := $(shell mkdir -p  $(OUTPUT))


all : $(OUTPUT)/my_prog.o $(OUTPUT)/my_prog.bpf.o $(OUTPUT)/my_prog.skel.h my_prog

#Compiler le prorgramme BPF kernel en fichier objet
$(OUTPUT)/my_prog.bpf.o: my_prog.bpf.c
	$(CLANG) $(CFLAGS) -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -c my_prog.bpf.c -o $@ 


#Génerer le squelette 
$(OUTPUT)/my_prog.skel.h: $(OUTPUT)/my_prog.bpf.o | $(OUTPUT) $(BPFTOOL)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(shell $(BPFTOOL) gen skeleton $(OUTPUT)/my_prog.bpf.o > $@)


#Compiler le programme user en fichier objet
$(OUTPUT)/my_prog.o: my_prog.c $(OUTPUT)/my_prog.skel.h
	$(CC) $(CFLAGS) -I $(OUTPUT)/ -lbpf -c my_prog.c -o $@

#Build le binaire
my_prog : $(OUTPUT)/my_prog.o
	$(Q) $(CC) $(CFLAGS) $^ -lbpf -lelf -lz -o $@


clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) *.o
	$(rm my_prog)
