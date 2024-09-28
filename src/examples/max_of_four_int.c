/* max_of_four_int.c */

#include <stdio.h>
#include <stdlib.h>
#include <syscall.h>

int
main (int argc, char **argv)
{
  int n[4];
  if (argc != 5) {
	printf("usage: max_of_four_int 1 2 3 4\n");
	return EXIT_FAILURE;
  }
  for (int i=0; i<4; i++) {
     n[i] = atoi(argv[i+1]);
  }
  int ret = max_of_four_int(n[0], n[1], n[2], n[3]);
  printf ("%d\n", ret);

  return EXIT_SUCCESS;
}
