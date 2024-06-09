/*
 * phoenix/final-two, by https://exploit.education
 *
 * This level is linked against ftp://gee.cs.oswego.edu/pub/misc/malloc.c
 * version 2.7.2, with a SHA1 sum of 407329d164e4989b59b9a828760acb720dc5c7db
 *
 * Can you get a shell via heap corruption?
 *
 * ...snip...
 */

// This is a marked-up and slightly modified copy of the challenge C source.
// It doesn't seem to me that this challenge is exploitable.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define REQSZ 128

#define BANNER                                                                 \
  "Welcome to " LEVELNAME ", brought to you by https://exploit.education"

void check_path(char *buf) {
  char *start;
  char *p;
  int l;

  /*
   * Work out old software bug
   */

  // Very contrived code
  // Refactored for ease of understanding

  // find last slash
  p = rindex(buf, '/');

  // get length of path following the slash (incl. /)
  // will straight-up crash if there is no slash
  // the if statement should be moved before this
  l = strlen(p);

  // slash required in buffer
  if (!p)
    return;

  // get ptr to "ROOT"
  start = strstr(buf, "ROOT");

  // "ROOT" required in buffer
  if (!start)
    return;

  // this isn't bounded...
  // we can try to make it land in the previous request
  while (*start != '/')
    start--;
  // write primitive
  // we can overwrite heap metadata & eventually change GOT... but only if
  // destroylist can be modified
  memmove(start, p, l);
}

void get_requests(int in_fd, int out_fd) {
  char *buf;
  // NOTHING WRITES TO THIS ARRAY! WTF
  char *destroylist[256];
  int dll;
  int i;

  dll = 0; // 47 or 0x2f?
  while (1) {
    if (dll >= 255)
      break;

    buf = calloc(REQSZ, 1);
    // each buffer must be exactly 128 bytes
    // note that null byte is not required
    if (read(in_fd, buf, REQSZ) != REQSZ)
      break;

    // each buffer must begin with "FSRD"
    if (strncmp(buf, "FSRD", 4) != 0)
      break;

    check_path(buf + 4);

    dll++;
  }

  for (i = 0; i < dll; i++) {
    write(out_fd, "Process OK\n", strlen("Process OK\n"));
    // The array contains only nullptrs. This challenge doesn't seem to be
    // solvable.
    free(destroylist[i]);
  }
}

int main(int argc, char **argv, char **envp) {
  printf("%s\n", BANNER);
  fflush(stdout);

  get_requests(0, 1);
  return 0;
}