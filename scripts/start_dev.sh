#!/bin/bash

# 0. Check arguments
VM=${1:-"backup-std"}
MOUNTPOINT=${2:-"/home/agusti/sshfs"}
VMUSER=${3:-"root"}
VMMOUNT=${4:-"/home/agusti"}
IP=${5:-""}
VBOPTS="--type headless"

# 1. Start VM
VBoxManage startvm $VM $VBOPTS

# 2. Wait to star VM
[ -z "$IP" ] && {
	while $(VBoxManage guestproperty get backup-std "/VirtualBox/GuestInfo/Net/0/V4/IP" | grep -qe "^No value") ; 
	do 
		sleep 1; 
	done; 
	IP=$(VBoxManage guestproperty get backup-std "/VirtualBox/GuestInfo/Net/0/V4/IP"|cut -d " " -f 2)
}
# 2. sshfs
sshfs $VMUSER@$IP:$VMMOUNT $MOUNTPOINT


