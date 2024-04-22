rm ./out/nikss.bc
rm ./out/nikss.c
rm ./out/nikss.o

# rm ./juniper.bc
# rm ./juniper.c
# rm ./juniper.o

echo -e "\033[1;36mcompiling nikss.p4 \033[0m" 
make -f /home/faris/p4/p4c/backends/ebpf/runtime/kernel.mk BPFOBJ=./out/nikss.o P4FILE=./src/nikss.p4 ARGS="-DPSA_PORT_RECIRCULATE=2" P4ARGS="--Wdisable=unused" psa

# echo ""
# echo ""
# echo ""
# echo -e "\033[1;34mcompiling juniper.p4 \033[0m"
# make -f ~/p4/p4c/backends/ebpf/runtime/kernel.mk BPFOBJ=juniper.o P4FILE=juniper.p4 ARGS="-DPSA_PORT_RECIRCULATE=2" P4ARGS="--Wdisable=unused" psa
