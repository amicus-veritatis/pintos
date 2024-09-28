/* fibonacci.c */

#include <stdio.h>
#include <stdlib.h>
#include <syscall.h>

int
main (int argc, char **argv)
{
  int n;
  if (argc != 2) {
	printf("usage: fibonacci 3\n");
	return EXIT_FAILURE;
  }
  n = atoi(argv[1]);
  printf ("%d\n", fibonacci(n));

  return EXIT_SUCCESS;
}
