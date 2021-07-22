#include <stdint.h>
#include <stdio.h>
#include <arpa/inet.h>


uint32_t transfer(char *f){

    FILE* fp = fopen(f,"rb");
    uint32_t buffer;

    fread(&buffer,1,sizeof(uint32_t),fp);

    return ntohl(buffer);

}

int main(int argc, char** argv)
{
      uint32_t n1 = transfer(argv[1]);
      uint32_t n2 = transfer(argv[2]);

    printf("%d(0x%x) + %d(0x%x) = %d(0x%x)\n",n1,n1,n2,n2,n1+n2,n1+n2);

}
