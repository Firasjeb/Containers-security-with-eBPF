.PHONY: clean

CLANG:=clang
VMLINUX:=vmlinux.h
CFLAGS:= -g -Wall
OUTPUT:=.output
ARCH := $(shell uname -m | sed 's/x86_64/x86/')
BPFTOOL=/usr/local/sbin/bpftool
_dummy := $(shell mkdir -p  $(OUTPUT))


all : $(OUTPUT)/ktls_sniff.o $(OUTPUT)/ktls_sniff.bpf.o $(OUTPUT)/ktls_sniff.skel.h ktls_sniff

#Compiler le prorgramme BPF kernel en fichier objet
$(OUTPUT)/ktls_sniff.bpf.o: ktls_sniff.bpf.c
	$(CLANG) $(CFLAGS) -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -c ktls_sniff.bpf.c -o $@ 


#Génerer le squelette 
$(OUTPUT)/ktls_sniff.skel.h: $(OUTPUT)/ktls_sniff.bpf.o | $(OUTPUT) $(BPFTOOL)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(shell $(BPFTOOL) gen skeleton $(OUTPUT)/ktls_sniff.bpf.o > $@)


#Compiler le programme user en fichier objet
$(OUTPUT)/ktls_sniff.o: ktls_sniff.c $(OUTPUT)/ktls_sniff.skel.h
	$(CC) $(CFLAGS) -I $(OUTPUT)/ -lbpf -c ktls_sniff.c -o $@

#Build le binaire
ktls_sniff : $(OUTPUT)/ktls_sniff.o
	$(Q) $(CC) $(CFLAGS) $^ -lbpf -lelf -lz -o $@


clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) *.o
