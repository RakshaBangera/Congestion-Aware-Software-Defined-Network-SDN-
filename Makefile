#
#Makefile for CSCI551 Project B
#

all: cperf arbiter
#Create object file for fastPass_client.c
cperf: fastpass_client.c	
	gcc -O2 -o cperf  fastpass_client.c -lpthread		
	
#Create object file for arbiter.cperf
arbiter: arbiter.c	
	gcc -O2 -o arbiter arbiter.c -lpthread
	
#Clean cperf.o and arbiter.object	
clean: 
	rm -rf cperf arbiter		
