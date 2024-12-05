#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_PATH_LENGTH 1024


/*
int check_path_traversal(const char *path) {

    char * path_copy = strdup(path);

    char *token = strtok(path_copy, "/");

    int counter = 0;

    while (token != NULL) {
        // printf("token: %s\n",token);
        if (strcmp(token, "..") == 0) {
            if(counter > 0)
                counter--;
            // printf("----Pop\n");
        } else if (strcmp(token, ".") == 0) {
            printf("----ignore");
        }
        else {
            counter++;
            printf("---- Push\n");

        }
        if (counter == 0) { free(path_copy); return 0; }

        token = strtok(NULL, "/");
        
    }
    free(path_copy);
    return 1;
}
*/

int check_path_traversal(const char *path) {

    char *path_copy = strdup(path);
    if (!path_copy) {
        return 0; // Memory allocation failure
    }

    char *token;
    char *rest = path_copy; // Used with `strsep` to iterate through the string

    int counter = 0;

    token = strsep(&rest, "/");

    while ((token = strsep(&rest, "/")) != NULL) {
        // printf("token: %s\n",token);
        if (strcmp(token, "..") == 0) {
            if (counter > 0) {
                counter--;
            }
            printf("----Pop\n");
        } else if (strcmp(token, ".") == 0) {
            printf("----ignore\n");
        } else if (*token != '\0') { // Ignore empty tokens caused by `//`
            counter++;
            printf("----Push\n");
        }

        if (counter == 0) {
            free(path_copy);
            return 0;
        }
    }

    free(path_copy);
    return 1;
}


int main() {
    // Test cases
    const char *test_paths[] = {
        "/var/tmp/../abc",  // Should return 1
        "/var/tmp/../abc/xyx/./../usr/lib",  // Should return 0
        "/../../.././././../",  // Should return 0 (edge case)
        "/home/user/.local/../../user2/../../tmp",  // Should return 1
        "/var/www/images/../../../etc/passwd"
    };

    for (int i = 0; i < 5; i++) {
        int result = check_path_traversal(test_paths[i]);
        puts("---------------");
        printf("Path: %s => %s\n", test_paths[i], result ? "easy" : "alert");
        puts("---------------");
    }

    return 0;
}
