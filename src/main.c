#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/util.h"

// mclang compile main.mclang

int main(int argc, char** argv){
    if (argc <3){
        return 1;
    }

    if (strcmp(argv[1],"com") == 0) {
        char* source = read_ascii_file(argv[2]);
        printf("%s\n", source);
        free(source);
    }
    return 0;
}
