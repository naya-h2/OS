#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/off_t.h"

/* An open file. */
struct file 
  {
    struct inode *inode;        /* File's inode. */
    off_t pos;                  /* Current position. */
    bool deny_write;            /* Has file_deny_write() been called? */
  };

static void syscall_handler (struct intr_frame *);

//invalid pointer면 rejected시키기
void validateAddr(void* addr) {
  if(addr == NULL || is_kernel_vaddr(addr) || pagedir_get_page(thread_current()->pagedir, addr) == NULL || !is_user_vaddr(addr)){
    exit(-1);
  }
}

void
syscall_init (void) 
{
  lock_init(&fd_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  // printf ("system call!\n");

  void* addr = f->esp;
  validateAddr(addr);
  if(*(int32_t*)(f->esp) != SYS_HALT) validateAddr(addr + 4); //syscall0만 아니면 ARG 하나는 무조건 있다
 
  switch(*(int32_t*)(f->esp)){
    case SYS_HALT:                   /* Halt the operating system. */
      halt();
      break;

    case SYS_EXIT:                   /* Terminate this process. */
      exit(*(uint32_t *)(addr + 4));
      break;
    
    case SYS_EXEC:                   /* Start another process. */
      f->eax = exec((const char *)(*(uint32_t *)(addr + 4)));
      break;
    
    case SYS_WAIT:                   /* Wait for a child process to die. */
      f->eax = wait((pid_t *)(*(uint32_t *)(addr + 4)));
      break;

    case SYS_READ:                   /* Read from a file. */
      validateAddr(addr + 8);
      validateAddr(addr + 12);
      f->eax = read((int)*(uint32_t*)(addr + 4), (void*)*(uint32_t*)(addr + 8), (unsigned)*(uint32_t*)(addr + 12));
      break;
    
    case SYS_WRITE:                  /* Write to a file. */
      validateAddr(addr + 8);
      validateAddr(addr + 12);
      // printf("write 들어갈게~ / %s;%d\n", (void*)*(uint32_t*)(addr + 8), (unsigned)*(uint32_t*)(addr + 12));
      f->eax = write((int)*(uint32_t*)(addr + 4), (void*)*(uint32_t*)(addr + 8), (unsigned)*(uint32_t*)(addr + 12));
      break;

    //추가 구현!!! 한다!!
    case SYS_FIBONACCI:
      f->eax = fibonacci((*(uint32_t *)(addr + 4)));
      break;
    
    case SYS_MAXINT:
      validateAddr(addr + 8);
      validateAddr(addr + 12);
      validateAddr(addr + 16);
      f->eax = max_of_four_int((*(uint32_t *)(addr + 4)), (*(uint32_t *)(addr + 8)), (*(uint32_t *)(addr + 12)), (*(uint32_t *)(addr + 16)));
      break;
    
    case SYS_CREATE:
      validateAddr(addr + 8);
      f->eax = create((const char *)(*(uint32_t *)(addr + 4)), (unsigned)*(uint32_t *)(addr + 8));
      break;
    
    case SYS_REMOVE:
      f->eax = remove((const char *)(*(uint32_t *)(addr + 4)));
      break;
    
    case SYS_OPEN:
      f->eax = open((const char *)(*(uint32_t *)(addr + 4)));
      break;
    
    case SYS_CLOSE:
      close((int)*(uint32_t *)(addr + 4));
      break;

    case SYS_FILESIZE:
      f->eax = filesize((int)*(uint32_t *)(addr + 4));
      break;
    
    case SYS_SEEK:
      validateAddr(addr + 8);
      seek((int)*(uint32_t *)(addr + 4), (unsigned)*(uint32_t *)(addr + 8));
      break;

    case SYS_TELL:
      f->eax = tell((int)*(uint32_t *)(addr + 4));
      break;

    default:
      break;
  }

  // printf("switch문 나옴\n"); //여기까지 ok
  // thread_exit ();
}

void halt (){
  shutdown_power_off();
}

void exit (int status) {
  printf("%s: exit(%d)\n", thread_name(), status);
  thread_current()->exit_status = status;
  thread_exit();
}

pid_t exec (const char *file){
  // printf("exec로 들어옴\n");
  return process_execute(file);
}

int wait (pid_t child_tid){
  return process_wait(child_tid);
}

//실제 읽은 바이트 수를 return
int read (int fd, void *buffer, unsigned length){
  validateAddr(buffer); //read-bad-ptr
  if(fd < 0 || fd > FD_TABLE_SIZE - 1 || fd == STD_OUT || fd == STD_ERR) return -1;
  
  lock_acquire(&fd_lock);

  int size = 0;
  if(fd == STD_IN){
    for(;size<length;size++){
      ((char*)buffer)[size] = input_getc();
      if(((char*)buffer)[size] == '\0') break;
    }
  }
  else{
    struct thread *cur_thread = thread_current();
    struct file *cur_file = cur_thread->fdt[fd];
    if(!cur_file) size = -1;
    else{
      size = file_read(cur_file, buffer, length);
    }
  }

  lock_release(&fd_lock);
  if(size < 0) exit(-1);
  return size;
}

int write (int fd, const void *buffer, unsigned length){
  if(fd < 0 || fd > FD_TABLE_SIZE - 1 || fd == STD_IN || fd == STD_ERR) return -1;
  if(length == 0) return 0; //write-zero

  lock_acquire(&fd_lock);
  int real_size = length;

  if(fd == STD_OUT){
    putbuf(buffer, length);
  }
  else{
    struct thread *cur_thread = thread_current();
    struct file *cur_file = cur_thread->fdt[fd];
    if(!cur_file) length = -1;
    else{
      if(cur_file->deny_write) file_deny_write(cur_file); //현재 파일을 읽기 모드로 열기
      real_size = file_write(cur_file, buffer, length);
    }
  }

  lock_release(&fd_lock);
	return real_size;
}

//추가
int fibonacci(int n){
  // printf("너 들어오냐: %d\n", n);
  if(n <= 1) return n;
  int a = 0; //앞의 수
  int b = 1; //뒤 수
  int temp;

  for(int i=2;i<=n;i++){
    temp = a + b;
    a = b; //b를 앞으로 옮기고
    b = temp; //더한 값을 b로
  }

  // printf("피보나치 결과: %d\n", b);

  return b;
}

int max_of_four_int(int a, int b, int c, int d){
  int max = a;
  if(b > max) max = b;
  if(c > max) max = c;
  if(d > max) max = d;

  // printf("max값: %d\n", max);

  return max;
}

/* proj#2 */
bool create (const char *file, unsigned initial_size){
  if(!file) exit(-1);
  return filesys_create(file, initial_size);
}

bool remove (const char *file){
  if(!file) exit(-1);
  return filesys_remove(file);
}

int open (const char *file){
  //파일 열고, 그 파일의 디스크립터를 return
  if(!file) exit(-1);

  lock_acquire(&fd_lock); //lock 갖고 와서
  struct file* temp = filesys_open(file); //file을 열어보기
  if(!temp) {
    lock_release(&fd_lock); //lock 다시 풀고
    return -1;
  }
  
  struct thread *cur = thread_current();
  int fd = -1;
  for(int i=3;i<FD_TABLE_SIZE;i++){
    if(cur->fdt[i]) continue;
    //넣기 전에 검사
    // if(!strcmp(cur->))
    
    cur->fdt[i] = temp;
    fd = i;
    break;
  }

  lock_release(&fd_lock);
  return fd;
}

void close (int fd){
  struct thread *cur_thread = thread_current();
  if(fd < 3 || fd > FD_TABLE_SIZE - 1) return;
  for(int i=3;i<FD_TABLE_SIZE;i++){
    if(!cur_thread->fdt[i]) continue;
    // printf("from syscall\n");
    file_close(cur_thread->fdt[i]);
    cur_thread->fdt[i] = NULL; //fdt 초기화
  }
}

int filesize (int fd){
  struct thread *cur_thread = thread_current();
  struct file *cur_file = cur_thread->fdt[fd];
  
  if(!cur_file) exit(-1);
  return file_length(cur_file);
}

void seek (int fd, unsigned position){
  struct thread *cur_thread = thread_current();
  struct file *cur_file = cur_thread->fdt[fd];
  
  file_seek(cur_file, position);
}

unsigned tell (int fd){
  struct thread *cur_thread = thread_current();
  struct file *cur_file = cur_thread->fdt[fd];
  
  if(!cur_file) exit(-1);
  return file_tell(cur_file);
}