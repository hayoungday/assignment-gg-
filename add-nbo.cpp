#include <stdint.h>
#include <stdio.h>
#include <arpa/inet.h>

int main(int argc, char** argv)
{
    uint8_t file1[4];
    uint8_t file2[4];

    FILE* fp1 = fopen(argv[1],"rb");
    FILE* fp2 = fopen(argv[2],"rb");

    fread(file1,1,4,fp1);
    fread(file2,1,4,fp2);

    uint32_t* p1 = reinterpret_cast<uint32_t*>(file1);
    uint32_t n1 = ntohl(*p1);

    uint32_t* p2 = reinterpret_cast<uint32_t*>(file2);
    uint32_t n2 = ntohl(*p2);

    printf("%d(0x%x) + %d(0x%x) = %d(0x%x)\n",n1,n1,n2,n2,n1+n2,n1+n2);

}
