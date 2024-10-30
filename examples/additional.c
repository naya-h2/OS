#include <stdio.h>
#include <stdlib.h>
#include <syscall.h>

int
main (int argc, char **argv)
{
  //argv[0]은 ./additional이겠지
  int a = atoi(argv[1]);
  int b = atoi(argv[2]);
  int c = atoi(argv[3]);
  int d = atoi(argv[4]);

  printf("%d %d\n", fibonacci(a), max_of_four_int(a, b, c, d));

  return EXIT_SUCCESS;
}
