#include "types.h"
#include "stat.h"
#include "user.h"

#define NUM_LOOP 100000
#define NUM_YIELD 20000
#define NUM_SLEEP 500

#define NUM_THREAD 4
#define MAX_LEVEL 3 // 3
#define PASSWORD 2018007874
int parent;

int fork_children()
{
  int i, p;
  for (i = 0; i < NUM_THREAD; i++) {
    p = fork();
    if (p == 0)
    {
      sleep(10);
      return getpid();
    }
  }
  return parent;
}


int fork_children2()
{
  int i, p;
  for (i = 0; i < NUM_THREAD; i++)
  {
    if ((p = fork()) == 0)
    {
      int pid = getpid();
      printf(1, "before sleep pid: %d, lv: %d\n", pid, getLevel());
      sleep(5);
      printf(1, "after sleep pid: %d, lv: %d\n", pid, getLevel());
      return getpid();
    }
    else
    {
      setPriority(p, i);
      // if (r < 0)
      // {
      //   printf(1, "setPriority returned %d\n", r);
      //   exit();
      // }
    }
  }
  return parent;
}

int max_level;

int fork_children3()
{
  int i, p;
  for (i = 0; i < NUM_THREAD; i++)
  {
    if ((p = fork()) == 0)
    {
      sleep(10);
      max_level = i;
      return getpid();
    }
  }
  return parent;
}
void exit_children()
{
  if (getpid() != parent) {
    exit();
  }
  while (wait() != -1);
}

int main(int argc, char* argv[])
{
  int child;

  parent = getpid();

  printf(1, "MLFQ test start\n");

  // printf(1, "[Test 1] default\n");
  // int i, pid;
  // int count[MAX_LEVEL] = { 0, 0, 0 };
  // pid = fork_children();

  // if (pid != parent)
  // {
  //   for (i = 0; i < NUM_LOOP; i++)
  //   {
  //     int x = getLevel();
  //     if (x < 0 || x > 2)
  //     {
  //       printf(1, "Wrong level: %d\n", x);
  //       exit();
  //     }
  //     count[x]++;
  //   }
  //   printf(1, "Process %d\n", pid);
  //   for (i = 0; i < MAX_LEVEL; i++)
  //     printf(1, "Process %d , L%d: %d\n", pid, i, count[i]);
  // }
  // exit_children();
  // printf(1, "[Test 1] finished\n");
  // // // 예상 출력 결과
  // // /*
  // // MLFQ test start
  // // [Test 1] default
  // // Process pid1
  // // process pid1 결과
  // // Process pid2
  // // process pid2 결과
  // // Process pid3
  // // process pid3 결과
  // // Process pid4
  // // process pid4 결과
  // // Process pid5
  // // process pid5 결과
  // // [Test 1] finished
  // // => pid1에서 pid5로 갈수록 count[i]의 비율이 잘 맞아야(1:1:2(?))한다.
  // // => pid1은 count[2]의 비율이 커야한다.
  // // // NUM_LOOP 처리속도에 따라 다를수도 있다.
  // // */


  // printf(1, "[Test 2] priorities\n");
  // pid = fork_children2();

  // if (pid != parent)
  // {
  //   for (i = 0; i < NUM_LOOP; i++)
  //   {
  //     int x = getLevel();
  //     if (x < 0 || x > 2)
  //     {
  //       printf(1, "Wrong level: %d\n", x);
  //       exit();
  //     }
  //     count[x]++;
  //   }
  //   printf(1, "Process %d\n", pid);
  //   for (i = 0; i < MAX_LEVEL; i++)
  //     printf(1, "Process %d , L%d: %d\n", pid, i, count[i]);

  // }
  // exit_children();
  // printf(1, "[Test 2] finished\n");
  // // // 예상 출력 결과
  // // /*
  // // MLFQ test start
  // // [Test 2] priorities

  // // // NUM_LOOP 처리속도에 따라 다를수도 있다.
  // // Process pid1
  // // process pid1 결과
  // // Process pid2
  // // process pid2 결과
  // // Process pid3
  // // process pid3 결과
  // // Process pid4
  // // process pid4 결과
  // // Process pid5
  // // process pid5 결과
  // // [Test 2] finished
  // // => pid5에서 pid1로 갈수록 count[i]의 비율이 잘 맞아야(1:1:2(?))한다.
  // // => pid5는 count[2]의 비율이 커야한다.
  // // => setPriority가 어느 순간 의미 없어짐 => priorityBoosting하면 똑같이 priroty=3이 되기 때문
  // // */
  // printf(1, "[Test 3] yield\n");
  // pid = fork_children2();

  // if (pid != parent)
  // {
  //   for (i = 0; i < NUM_YIELD; i++)
  //   {
  //     int x = getLevel();
  //     if (x < 0 || x > 2)
  //     {
  //       printf(1, "Wrong level: %d\n", x);
  //       exit();
  //     }
  //     count[x]++;
  //     yield();
  //   }
  //   printf(1, "Process %d\n", pid);
  //   for (i = 0; i < MAX_LEVEL; i++)
  //     printf(1, "Process %d , L%d: %d\n", pid, i, count[i]);

  // }
  // exit_children();
  // printf(1, "[Test 3] finished\n");
  // // 예상 출력 결과
  // /*
  // MLFQ test start
  // [Test 3] yield

  // // NUM_LOOP 처리속도에 따라 다를수도 있다.
  // Process pid1
  // process pid1 결과
  // Process pid2
  // process pid2 결과
  // Process pid3
  // process pid3 결과
  // Process pid4
  // process pid4 결과
  // Process pid5
  // process pid5 결과
  // [Test 3] finished
  // => pid1에서 pid5로 갈수록 count[i]의 비율이 잘 맞아야(1:1:2(?))한다.
  // => pid1은 count[2]의 비율이 커야한다.
  // => Test 1의 결과와 비슷할 것으로 생각
  // => yield를 하더라도, 다른 process도 마찬가지로 yield하므로 동등할 것으로 생각
  // */

  // printf(1, "[Test 4] sleep\n");
  // pid = fork_children2();
  // if (pid != parent)
  // {
  //   int my_pid = getpid();
  //   printf(1, "pid: %d fork: %d\n", my_pid, getLevel());

  //   for (i = 0; i < NUM_SLEEP; i++)
  //   {
  //     int x = getLevel();
  //     if (x < 0 || x > 2)
  //     {
  //       printf(1, "Wrong level: %d\n", x);
  //       exit();
  //     }
  //     count[x]++;
  //     sleep(1);
  //   }
  //   sleep(my_pid * 3);
  //   printf(1, "Process %d\n", pid);
  //   for (i = 0; i < MAX_LEVEL; i++)
  //     printf(1, "Process %d , L%d: %d\n", pid, i, count[i]);

  // }
  // exit_children();
  // printf(1, "[Test 4] finished\n");
  // // 예상 출력 결과
  // /*
  // MLFQ test start
  // [Test 4] sleep

  // // NUM_LOOP 처리속도에 따라 다를수도 있다.
  // Process pid1
  // process pid1 결과
  // Process pid2
  // process pid2 결과
  // Process pid3
  // process pid3 결과
  // Process pid4
  // process pid4 결과
  // Process pid5
  // process pid5 결과
  // [Test 4] finished
  // => pid1에서 pid5로 갈수록 count[i]의 비율이 잘 맞아야(1:1:2(?))한다.
  // => pid1은 count[2]의 비율이 커야한다.
  // => Test 1의 결과와 비슷할 것으로 생각
  // => sleep을 하더라도, 다른 process 역시 sleep하기 때문에 동등할 것으로 생각
  // */
  // printf(1, "[Test 5] max level\n");
  // pid = fork_children3();

  // if (pid != parent)
  // {
  //   for (i = 0; i < NUM_LOOP; i++)
  //   {
  //     int x = getLevel();
  //     if (x < 0 || x > 2)
  //     {
  //       printf(1, "Wrong level: %d\n", x);
  //       exit();
  //     }
  //     count[x]++;
  //     if (x > max_level)
  //       yield();
  //   }
  //   printf(1, "Process %d\n", pid);
  //   for (i = 0; i < MAX_LEVEL; i++)
  //     printf(1, "Process %d , L%d: %d\n", pid, i, count[i]);

  // }
  // exit_children();
  // printf(1, "[Test 5] finished\n");
  // // // 예상 출력 결과
  // // /*
  // // MLFQ test start
  // // [Test 5] max level
  // // => 이 부분은 우리 과제랑 많이 다르기 때문에 의미 없을 듯
  // // => 굳이 고치려면 NUM_THREAD를 2로 고침(max_level =1 설정됨)
  // // => max_level이 1이니까 L2에서 실행되면 바로 yield함
  // // => 그런데 우리 과제에는 yield에 따른 L0로의 이동이 없어서 의미가 없는 실행이 된다.

  // // // NUM_LOOP 처리속도에 따라 다를수도 있다.
  // // Process pid1
  // // process pid1 결과
  // // Process pid2
  // // process pid2 결과
  // // Process pid3
  // // process pid3 결과
  // // Process pid4
  // // process pid4 결과
  // // Process pid5
  // // process pid5 결과
  // // [Test 5] finished
  // // => pid1에서 pid5로 갈수록 count[i]의 비율이 잘 맞아야(1:1:2(?))한다.
  // // => pid1은 count[2]의 비율이 커야한다.
  // // => Test 1의 결과와 비슷할 것으로 생각
  // // => sleep을 하더라도, 다른 process 역시 sleep하기 때문에 동등할 것으로 생각
  // // */
  // printf(1, "[Test 6] setPriority return value\n");
  // child = fork();

  // if (child == 0)
  // {
  //   // int r;
  //   int grandson;
  //   sleep(10);
  //   grandson = fork();
  //   if (grandson == 0)
  //   {
  //     setPriority(getpid() - 2, 0);
  //     // if (r != -1)
  //     //   printf(1, "wrong: setPriority of parent: expected -1, got %d\n", r);
  //     setPriority(getpid() - 3, 0);
  //     // if (r != -1)
  //     //   printf(1, "wrong: setPriority of ancestor: expected -1, got %d\n", r);
  //   }
  //   else
  //   {
  //     setPriority(grandson, 0);
  //     // if (r != 0)
  //     //   printf(1, "wrong: setPriority of child: expected 0, got %d\n", r);
  //     setPriority(getpid() + 1, 0);
  //     // if (r != -1)
  //     //   printf(1, "wrong: setPriority of other: expected -1, got %d\n", r);
  //   }
  //   sleep(20);
  //   wait();
  // }
  // else
  // {
  //   // int r;
  //   int child2 = fork();
  //   sleep(20);
  //   if (child2 == 0)
  //     sleep(10);
  //   else
  //   {
  //     setPriority(child, -1);
  //     // if (r != -2)
  //     //   printf(1, "wrong: setPriority out of range: expected -2, got %d\n", r);
  //     setPriority(child, 11);
  //     // if (r != -2)
  //     //   printf(1, "wrong: setPriority out of range: expected -2, got %d\n", r);
  //     setPriority(child, 10);
  //     // if (r != 0)
  //     //   printf(1, "wrong: setPriority of child: expected 0, got %d\n", r);
  //     setPriority(child + 1, 10);
  //     // if (r != 0)
  //     //   printf(1, "wrong: setPriority of child: expected 0, got %d\n", r);
  //     setPriority(child + 2, 10);
  //     // if (r != -1)
  //     //   printf(1, "wrong: setPriority of grandson: expected -1, got %d\n", r);
  //     setPriority(parent, 5);
  //     // if (r != -1)
  //     //   printf(1, "wrong: setPriority of self: expected -1, got %d\n", r);
  //   }
  // }

  // exit_children();
  // printf(1, "done\n");
  // printf(1, "[Test 6] finished\n");



  // // 예상 실행 순서
  // /*
  // 1. line 306실행 => child와 parent나눠짐 => Q에 parent - child 순으로 들어잇음
  // 2. 부모 먼저 line 335 else 진입 -> child2 fork() => Q에 parent - child - child2 순서로 들어있음
  // 3. 부모 sleep(20)
  // 4. child 1선택 -> line 312실행 -> sleep(10)
  // 5. child 2선택 -> lien 339실행 -> sleep(20)
  // 6. sleep의 차이로 child 1 먼저 실행, line 313 실행 -> grandson fork() => Q에 parent(sleep) - child(running) - child2(sleep) - grandson(runnable) 순서로 들어이슴
  // 7. child 1이 line 325 실행 -> 자식 priority 0으로 바꿈 -> return 값이 이상하면 알아서 출력
  // 8. child 1이 line 328 실행 -> (getpid() + 1)==child2 의 priority 0으로 바꿈 => 구현따라서 다름 -> 나는 된다.
  // 9. grandson 선택, line 314 진입 -> if문 안에 setPrioirty() => 구현따라서 다름 -> 나는 된다.
  // 10. child1, grandsonn 사망
  // 11. parent 선택, line 342 진입 -> line 344:350 child에 대한 setPriority => 구현따라서 다름 -> 나는 안된다.
  // 12. line 353 실행 -> child2에 대한 setPriority => 구현따라서 다름 -> 나는 된다.
  // 13. line 356 실행 -> grandson에 대한 setPriority => 구현따라서 다름 -> 나는 된다.
  // 14. line 359 실행 -> parent에 대한 setPriority => 구현따라서 다름 -> 나는 된다.
  // 15. 끘
  // */

  // printf(1, "[Test 7] schedulerLock & Unlock Test\n");
  // // schedulerLock(PASSWORD);
  // child = fork();

  // if (child == 0) // child
  // {
  //   // int r;
  //   int grandson;
  //   printf(1, "Before Lock Process : %d \n", getpid());
  //   schedulerLock(PASSWORD);
  //   printf(1, "After Lock Process : %d \n", getpid());
  //   grandson = fork();
  //   if (grandson == 0) // gradnsond
  //   {
  //     printf(1, "GRANDSON : %d\n", getpid());
  //     printf(1, "Before try Unlock Process : %d \n", getpid());
  //     schedulerUnlock(PASSWORD);
  //     printf(1, "After try Unlock Process : %d \n", getpid());
  //     schedulerLock(PASSWORD);

  //   }
  //   else // child
  //   {
  //     printf(1, " CHILD : %d\n", getpid());
  //     printf(1, "Before try Unlock Process : %d \n", getpid());
  //     schedulerUnlock(PASSWORD);
  //     printf(1, "After try Unlock Process : %d \n", getpid());
  //     printf(1, "Process : %d still work \n", getpid());
  //   }
  //   sleep(20);
  //   wait();
  // }
  // else // parent
  // {
  //   printf(1, "Else\n");

  //   // int r;
  //   int child2 = fork();
  //   sleep(20);
  //   if (child2 == 0) {//child2
  //     printf(1, " CHILD2 : %d\n", getpid());

  //     printf(1, "Before try Lock Process : %d \n", getpid());

  //     schedulerLock(PASSWORD);
  //     printf(1, "After try Lock Process : %d \n", getpid());
  //     sleep(2);
  //     for (int i = 0;i < NUM_SLEEP * 1000000;i++) {
  //       if (i % 100000000 == 0) {
  //         printf(1, "spend time for priority boosting while running\n");
  //       }
  //     }
  //     printf(1, "Before try Lock Again Process : %d \n", getpid());

  //     schedulerLock(PASSWORD);
  //     printf(1, "After try Lock Again Process : %d \n", getpid());
  //   }
  //   else
  //   {
  //     printf(1, " PARENT : %d\n", getpid());
  //     schedulerLock(PASSWORD);
  //     printf(1, "test before for sleep priority Boost\n");
  //     sleep(100);
  //     printf(1, "test after for sleep priority Boost\n");

  //   }
  // }
  // printf(1, "Process : %d\n", getpid());

  // exit_children();
  // printf(1, "Process : %d\n", getpid());
  // printf(1, "[Test 7] finished\n");


  printf(1, "[Test 8] schedulerLock / Unlock Normal Case\n");
  child = fork();
  if (child == 0) { //child
    printf(1, "Process %d schedluer Lock\n", getpid());
    schedulerLock(PASSWORD);
    printf(1, "Process %d in Q level %d\n", getpid(), getLevel());
    schedulerUnlock(PASSWORD);
    printf(1, "Process %d schedluer Unlock\n", getpid());
  }
  else { // parent
    printf(1, "Process %d schedluer Lock\n", getpid());
    schedulerLock(PASSWORD);
    printf(1, "Process %d in Q level %d\n", getpid(), getLevel());
    schedulerUnlock(PASSWORD);
    printf(1, "Process %d schedluer Unlock\n", getpid());
  }
  exit_children();
  printf(1, "[Test 8] finished\n");



  printf(1, "[Test 9] schedulerLock / Unlock Wrong Case1 : PASSWORD ERROR\n");
  child = fork();
  if (child == 0) { //child
    printf(1, "Process %d schedluer Lock\n", getpid());
    printf(1, "This procedure intends to scheduler Lock Error for PASSWORD\n");

    schedulerLock(PASSWORD + 1);
    // 아래부분 실행 안되어야함
    printf(1, "Process %d in Q level %d\n", getpid(), getLevel());
    schedulerUnlock(PASSWORD + 1);
    printf(1, "Process %d schedluer Unlock\n", getpid());
  }
  else { // parent
    int child2 = fork();
    if (child2 == 0) {
      printf(1, "Process %d schedluer Lock\n", getpid());
      schedulerLock(PASSWORD);
      printf(1, "Process %d in Q level %d\n", getpid(), getLevel());
      printf(1, "This procedure intends to scheduler Unlock Error for PASSWORD\n");
      schedulerUnlock(PASSWORD + 1);
      //아래 부분 실행 안되어야함.
      printf(1, "Process %d schedluer Unlock\n", getpid());
    }
  }
  exit_children();
  printf(1, "[Test 9] finished\n");



  printf(1, "[Test 10] schedulerLock / Unlock Wrong Case2 : duplication ERROR\n");
  child = fork();
  if (child == 0) { //child
    printf(1, "Process %d schedluer Lock\n", getpid());

    schedulerLock(PASSWORD);
    printf(1, "Process %d in Q level %d\n", getpid(), getLevel());
    // 아래부분 실행 안되어야함
    printf(1, "This procedure intends to scheduler Lock Error for duplication\n");
    schedulerLock(PASSWORD);
    printf(1, "Process %d schedluer Unlock\n", getpid());
  }
  else { // parent
    int child2 = fork();
    if (child2 == 0) {
      printf(1, "Process %d schedluer Lock\n", getpid());
      schedulerLock(PASSWORD);
      printf(1, "Process %d in Q level %d\n", getpid(), getLevel());
      printf(1, "This procedure intends to scheduler Unlock Error for duplication\n");
      schedulerUnlock(PASSWORD);
      printf(1, "Process %d schedluer Unlock\n", getpid());
      schedulerUnlock(PASSWORD);
      //아래 부분 실행 안되어야함.
      printf(1, "Process %d schedluer Unlock Again\n", getpid());

    }
  }
  exit_children();
  printf(1, "[Test 10] finished\n");


  printf(1, "done\n");
  exit();
}

