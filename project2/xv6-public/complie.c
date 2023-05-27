#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void) {
  system("make clean");
  system("make");
  system("make fs.img");
  system("./bootxv6.sh");
  // system("make clean");

  return 0;
}