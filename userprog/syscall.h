#ifndef __LIB_USER_SYSCALL_H
#define __LIB_USER_SYSCALL_H

#include <stdbool.h>
#include <debug.h>

/* Process identifier. */
typedef int pid_t;
#define PID_ERROR ((pid_t) -1)

/* Map region identifier. */
typedef int mapid_t;
#define MAP_FAILED ((mapid_t) -1)

/* Maximum characters in a filename written by readdir(). */
#define READDIR_MAX_LEN 14

/* Typical return values from main() and arguments to exit(). */
#define EXIT_SUCCESS 0          /* Successful execution. */
#define EXIT_FAILURE 1          /* Unsuccessful execution. */

#define STD_IN 0
#define STD_OUT 1
#define STD_ERR 2

/* Proj#1 */
void halt (void) NO_RETURN;
void exit (int status) NO_RETURN;
pid_t exec (const char *file);
int wait (pid_t);
int read (int fd, void *buffer, unsigned length);
int write (int fd, const void *buffer, unsigned length);
//추가구현 한다.
int fibonacci(int n);
int max_of_four_int(int a, int b, int c, int d);

void validateAddr(void* addr); 

/* proj#2 */
struct lock fd_lock;

bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
void close (int fd);
int filesize (int fd);
void seek (int fd, unsigned position);
unsigned tell (int fd);

#endif /* lib/user/syscall.h */
