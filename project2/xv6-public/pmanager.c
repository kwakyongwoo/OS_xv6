#include "types.h"
#include "stat.h"
#include "user.h"

#define BUFFER_SIZE 200

int main(int argc, char *argv[]) {

    char buffer[BUFFER_SIZE];

    while (1) {
        printf(1, ">> ");

        // 빈 문자열로 초기화
        memset(buffer, ' ', BUFFER_SIZE);
        gets(buffer, BUFFER_SIZE);

        if (buffer[0] == ' ') { // 비어있는 입력이라면
            printf(2, "ERROR: Invalid Input\n");
            exit();
        }

        if (buffer[0] == 'l' && buffer[1] == 'i' && buffer[2] == 's' && buffer[3] == 't' && buffer[4] == '\n') {
printf(1, "list\n");
        }

        else if (buffer[0] == 'k' && buffer[1] == 'i' && buffer[2] == 'l' && buffer[3] == 'l' && buffer[4] == ' ') {
printf(1, "kill\n");
        }

        else if (buffer[0] == 'e' && buffer[1] == 'x' && buffer[2] == 'e' && buffer[3] == 'c' && buffer[4] == 'u' && buffer[5] == 't' && buffer[6] == 'e' && buffer[7] == ' ') {
printf(1, "execute\n");
        }

        else if (buffer[0] == 'm' && buffer[1] == 'e' && buffer[2] == 'm' && buffer[3] == 'l' && buffer[4] == 'i' && buffer[5] == 'm' && buffer[6] == ' ') {
printf(1, "memlim\n");
        }

        else if (buffer[0] == 'e' && buffer[1] == 'x' && buffer[2] == 'i' && buffer[3] == 't' && buffer[4] == '\n')
            exit();

        else
            printf(1, "Invalid Input\n");
    }

    exit();
}
