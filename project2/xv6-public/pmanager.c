#include "types.h"
#include "stat.h"
#include "user.h"
#include "fcntl.h"

#define BUFFER_SIZE 1000

int
getcmd(char *buf, int nbuf)
{
  printf(2, ">> ");
  memset(buf, 0, nbuf);
  gets(buf, nbuf);
  if(buf[0] == 0) // EOF
    return -1;
  return 0;
}

int main(int argc, char *argv[]) {

    char buf[BUFFER_SIZE];
    int fd;

    // Ensure that three file descriptors are open.
    while((fd = open("console", O_RDWR)) >= 0){
        if(fd >= 3){
            close(fd);
            break;
        }
    }

loop:
    memset(buf, 0, sizeof(buf));
    while (getcmd(buf, sizeof(buf)) >= 0) {

        if (buf[0] == 'l' && buf[1] == 'i' && buf[2] == 's' && buf[3] == 't' && buf[4] == '\n') {
            plist();
            printf(1, "\n");
        }

        else if (buf[0] == 'k' && buf[1] == 'i' && buf[2] == 'l' && buf[3] == 'l' && buf[4] == ' ') {
            int i = 5;
            int pid = 0;

            while (buf[i] != '\n') {
                if (buf[i] < 48 || buf[i] > 57) {
                    printf(2, "Invalid Input: pid must be integer\n");
                    goto loop;
                }

                pid *= 10;
                pid += buf[i] - 48;
                i++;

                if (pid > 1000000000) {
                    printf(2, "Invalid Input: pid must be less than 1000000000\n");
                    goto loop;
                }
            }

            if(kill(pid) == -1)
                printf(2, "FAILED: %s\n", buf);
            else
                printf(1, "SUCCESS: %s\n", buf);
        }

        else if (buf[0] == 'e' && buf[1] == 'x' && buf[2] == 'e' && buf[3] == 'c' && buf[4] == 'u' && buf[5] == 't' && buf[6] == 'e' && buf[7] == ' ') {
            int i = 8;
            char path[1000];
            
            while (buf[i] != ' ') {
                if (i - 8 > 50) {
                    printf(2, "Invalid Input: path must not exceed 50 in length\n");
                    goto loop;
                }
                path[i - 8] = buf[i];
                i++;
            }

            int stackSize = 0;

            i++;
            while (buf[i] != '\n') {
                if (buf[i] < 48 || buf[i] > 57) {
                    printf(2, "Invalid Input: stack size must be integer\n");
                    goto loop;
                }
                stackSize *= 10;
                stackSize += buf[i] - 48;
                i++;

                if (stackSize > 1000000000) {
                    printf(2, "Invalid Input: stackSize must be less than 1000000000\n");
                    goto loop;
                }
            }

            int pid = fork();
            char *arg[2];

            arg[0] = path;
            arg[1] = 0;

            if (pid == 0) {
                pid = fork();
                if (pid == 0) {
                    exec2(arg[0], arg, stackSize);
                    printf(2, "FAILED: %s\n", buf);
                }
                exit();
            }
            else if (pid > 0)
                wait();
            else
                printf(2, "FAILED: %s\n", buf);
        }

        else if (buf[0] == 'm' && buf[1] == 'e' && buf[2] == 'm' && buf[3] == 'l' && buf[4] == 'i' && buf[5] == 'm' && buf[6] == ' ') {
            int i = 7;
            int pid = 0;

            while (buf[i] != ' ') {
                if (buf[i] < 48 || buf[i] > 57) {
                    printf(2, "Invalid Input: pid must be integer\n");
                    goto loop;
                }
        
                pid *= 10;
                pid += buf[i] - 48;
                i++;

                if (pid > 1000000000) {
                    printf(2, "Invalid Input: pid must be less than 1000000000\n");
                    goto loop;
                }
            }

            i++;

            int limit = 0;
            while (buf[i] != '\n') {
                if (buf[i] < 48 || buf[i] > 57) {
                    printf(2, "Invalid Input: limit must be integer\n");
                    goto loop;
                }
            
                limit *= 10;
                limit += buf[i] - 48;
                i++;

                if (limit > 1000000000) {
                    printf(2, "Invalid Input: limit must be less than 1000000000\n");
                    goto loop;
                }
            }

            if(setmemorylimit(pid, limit) == -1)
                printf(2, "FAILED: %s\n", buf);
            else
                printf(2, "SUCCESS: %s\n", buf);

        }

        else if (buf[0] == 'e' && buf[1] == 'x' && buf[2] == 'i' && buf[3] == 't' && buf[4] == '\n')
            exit();

        else
            printf(1, "Invalid Input\n");
    }

    exit();
}
