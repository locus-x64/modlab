#include <stdio.h>

int main() {
    FILE *file;
    char filename[] = "example.txt";
    char ch;

    // Open file in read mode
    file = fopen(filename, "r");

    // Check if file opened successfully
    if (file == NULL) {
        printf("Could not open file %s\n", filename);
        return 1;
    }

    // Read and display the file content character by character
    while ((ch = fgetc(file)) != EOF) {
        putchar(ch);
    }

    // Close the file
    fclose(file);

    return 0;
}
