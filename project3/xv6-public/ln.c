#include "types.h"
#include "stat.h"
#include "user.h"

int
main(int argc, char *argv[])
{
  if(argc != 4){
    printf(2, "Usage: ln -option old new\n");
    exit();
  }

  if (strcmp(argv[1], "-h") == 0) {
    if(link(argv[2], argv[3]) < 0)
      printf(2, "link %s %s %s: failed\n", argv[1], argv[2], argv[3]);
    exit();
  }
  if (strcmp(argv[1], "-s") == 0) {
    if (symlink(argv[2], argv[3]) < 0)
      printf(2, "link %s %s %s: failed\n", argv[1], argv[2], argv[3]);
    exit();
  }
}
