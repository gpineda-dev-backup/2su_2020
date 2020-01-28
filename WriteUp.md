# INSA - 2su : IoT security WriteUp

## A- Crack Emily


#### i) Introduction
Let's following the awesome [Emily's tutorial](https://archive.emily.st/2015/01/27/reverse-engineering/) to understand basis of reverse engineering with a simple c program   which check if the user input is a valid password or not.

```c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int is_valid(const char* password) {
    if (strcmp(password, "poop") == 0) { //valid password
        return 1;
    } else {
        return 0;
    }
}

int main()
{
    char* input = malloc(256);
    printf("Please input a word: ");
    scanf("%s", input);

    if (is_valid(input)) {
        printf("That's correct!\n");
    } else {
        printf("That's not correct!\n");
    }

    free(input);
    return 0;
}

```

#### ii) Analysis

We can start by looking for strings into the compiled binary, see above the output. 
```bash
$ strings program | less

AWAVA
AUATL
[]A\A]A^A_
poop
Please input a word: 
That's correct!
That's not correct!
;*3$"

```

Let's now understand what the code is doing, so by using objdump we get 


#### iii) Patch

