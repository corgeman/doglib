#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>

int main(){
    setbuf(stdout,0);
    mmap(0,0x3000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0); // resolve mmap earlier
    char buf[0x10];
    printf("stdout: %p\n", stdout);
    printf("munmap addr:");
    read(0,buf,0x10-1);
    unsigned long munmap_addr = strtoul(buf,NULL,16);
    printf("munmap size:");
    read(0,buf,0x10-1);
    unsigned long munmap_size = strtoul(buf,NULL,16);
    munmap(munmap_addr,munmap_size);
    printf("munmap success");
    mmap(munmap_addr,munmap_size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    read(0,munmap_addr,munmap_size);
    puts("cat /flag.txt");
    return 0;
}