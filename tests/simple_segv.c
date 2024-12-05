#include <stdio.h>
#include <stdlib.h>

int main() {
    int f_pid = fork();
    if (f_pid == 0) {
        
        int *p = NULL;
        *p = 42;
        return 0;
    } else {
        int status;
        waitpid(f_pid, &status, 0);
    }
}