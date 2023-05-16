#include "types.h"
#include "stat.h"
#include "user.h"

#define NUM_LOOP 1000000

#define NUM_THREAD 4
#define MAX_LEVEL 3

int parent;

int fork_children()
{
  int i, p;
  for (i = 0; i < NUM_THREAD; i++)
    if ((p = fork()) == 0)
    {
      sleep(10);
      return getpid();
    }
  return parent;
}

void exit_children()
{
  if (getpid() != parent)
    exit();
  while (wait() != -1);
}

int main(int argc, char *argv[])
{
  int i, pid;
  int count[MAX_LEVEL] = {0};

  parent = getpid();

  printf(1, "MLFQ test start\n");

  printf(1, "[Test 1] default\n");
  pid = fork_children();
  if (pid != parent)
  {
    for (i = 0; i < NUM_LOOP; i++) {
      if(i == 10000) {
        // schedulerLock(2018007874);
        __asm__("int $129");
        // sleep(10);
        // __asm__("int $130");
      }
      int x = getLevel();
    //   printf(1,"In User , pid : %d , qLevel :%d\n",pid,x);
      count[x]++;
    }
    printf(1, "Process %d\n", pid);
    for (i = 0; i < MAX_LEVEL; i++)
      printf(1, "pid : %d,L%d: %d\n", pid, i, count[i]);
  }
  exit_children();
  printf(1, "[Test 1] finished\n");
  exit();
}