.PHONY: clean

CLANG:=clang
VMLINUX:=vmlinux.h
CFLAGS:= -g -Wall
OUTPUT:=.output
ARCH := $(shell uname -m | sed 's/x86_64/x86/')
BPFTOOL=/usr/local/sbin/bpftool
_dummy := $(shell mkdir -p  $(OUTPUT))


all : $(OUTPUT)/kvm_sniff.o $(OUTPUT)/kvm_sniff.bpf.o $(OUTPUT)/kvm_sniff.skel.h kvm_sniff

#Compiler le prorgramme BPF kernel en fichier objet
$(OUTPUT)/kvm_sniff.bpf.o: kvm_sniff.bpf.c
	$(CLANG) $(CFLAGS) -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -c kvm_sniff.bpf.c -o $@ 


#Génerer le squelette 
$(OUTPUT)/kvm_sniff.skel.h: $(OUTPUT)/kvm_sniff.bpf.o | $(OUTPUT) $(BPFTOOL)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(shell $(BPFTOOL) gen skeleton $(OUTPUT)/kvm_sniff.bpf.o > $@)


#Compiler le programme user en fichier objet
$(OUTPUT)/kvm_sniff.o: kvm_sniff.c $(OUTPUT)/kvm_sniff.skel.h
	$(CC) $(CFLAGS) -I $(OUTPUT)/ -lbpf -c kvm_sniff.c -o $@

#Build le binaire
kvm_sniff : $(OUTPUT)/kvm_sniff.o
	$(Q) $(CC) $(CFLAGS) $^ -lbpf -lelf -lz -o $@


clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) *.o
