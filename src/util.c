#include "../include/util.h"

char* read_ascii_file(const char* path) {

    // create file in memory
    FILE* file = fopen(path, "r");
    if (!file) {
        printf("Failed to read file '%s'. Try checking the permissions.", path);
        return NULL;
    }

    // get file size
    fseek(file, 0, SEEK_END);
    int size = ftell(file);
    fseek(file, 0, SEEK_SET);

    // allocate memory
    char* buf = (char*) malloc(sizeof(char) * (size + 1));
    if (!buf) {
        printf("Failed to allocate memory for file '%s'. Full memory?", path);
        return NULL;
    }
    fread(buf, 1, size, file);
    // ends the file with a null terminated byte (just in case)
    buf[size] = '\0';

    fclose(file);


    // return file
    return buf;
}