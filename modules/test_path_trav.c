#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>

#define BASE_DIR "/tmp"

// Function to check if the file is within the base directory
int is_within_base_dir(const char *filepath) {
    // Ensure the path starts with BASE_DIR
    return strncmp(filepath, BASE_DIR, strlen(BASE_DIR)) == 0;
}

// Function to read a file and print its content if within BASE_DIR
void read_file(const char *filepath) {
    // Check if the file is within the base directory
    if (!is_within_base_dir(filepath)) {
        fprintf(stderr, "Error: Access denied to files outside %s\n", BASE_DIR);
        return;
    }

    FILE *file = fopen(filepath, "r");
    if (file == NULL) {
        perror("Error opening file");
        return;
    }

    // Read file content and print to stdout
    char ch;
    while ((ch = fgetc(file)) != EOF) {
        putchar(ch);
    }

    fclose(file);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <relative or absolute path>\n", argv[0]);
        return 1;
    }

    // Attempt to read file directly
    printf("Attempting to read file: %s\n", argv[1]);
    read_file(argv[1]);

    // Attempt to read file using path traversal
    char traversal_path[512];
    snprintf(traversal_path, sizeof(traversal_path), "%s/%s", BASE_DIR, argv[1]);
    printf("Attempting to read file with path traversal: %s\n", traversal_path);
    read_file(traversal_path);

    return 0;
}
