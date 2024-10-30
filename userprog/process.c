#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

#include "filesys/inode.h"
struct inode_disk
  {
    block_sector_t start;               /* First data sector. */
    off_t length;                       /* File size in bytes. */
    unsigned magic;                     /* Magic number. */
    uint32_t unused[125];               /* Not used. */
  };


struct inode 
  {
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    struct inode_disk data;             /* Inode content. */
  };
  

struct file 
  {
    struct inode *inode;        /* File's inode. */
    off_t pos;                  /* Current position. */
    bool deny_write;            /* Has file_deny_write() been called? */
  };

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;

  strlcpy (fn_copy, file_name, PGSIZE);

  //복사본을 만들고
  char* file_name_copy = (char*)malloc((strlen(file_name) + 1) * sizeof(char));
  strlcpy(file_name_copy, file_name, strlen(file_name) + 1);

  char* savePtr; //strtok_r에서 공백 다음 단어 포인터를 찾는 데 이용
  char* cmdPtr =  strtok_r(file_name_copy, " ", &savePtr); //공백 기준으로 자른 첫 번째 포인터(ex. echo)

  if(!filesys_open(cmdPtr)) {
    return -1; //파일 없는 경우 예외처리
  }

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (cmdPtr, PRI_DEFAULT, start_process, fn_copy);
  if (tid == TID_ERROR)
    palloc_free_page (fn_copy); 

  free(file_name_copy);
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, &if_.eip, &if_.esp);
  // printf("load done\n");

  // printf("from start %p(%d)\n", thread_current()->ing_file, thread_current()->ing_file->inode->deny_write_cnt);
  /* If load failed, quit. */
  palloc_free_page (file_name);
  if (!success) 
    thread_exit ();

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid UNUSED) 
{
  //child_tid가 끝날때까지 기다려쥬쟈!
  
  //자식들중에 tid 녀석을 찾자.
  struct thread* cur_thread = thread_current();
  struct list_elem* cur_elem = list_begin(&(cur_thread->child));
  
  // printf("tid 찾을 준비\n");

  if(cur_elem == NULL) return -1;

  // printf("일단 있긴 있어!\n");


  while(cur_elem != list_end(&(cur_thread->child))){
    struct thread* tmp = list_entry(cur_elem, struct thread, child_elem);
    if(child_tid == tmp->tid){
      // printf("헤이 너 찾았니???????????\n");
      sema_down(&(tmp->sema_child)); //up될때까지 parent는 대기(lock)
      list_remove(&(tmp->child_elem)); //child를 없앤다
      
      sema_up(&(tmp->sema_mem)); //메모리 lock 풀음
      return tmp->exit_status;
    }
    cur_elem = list_next(cur_elem);
  }

  return -1;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */

    // printf("from process %p(%p)\n", cur->ing_file, cur->ing_file->inode->deny_write_cnt);
    file_close(cur->ing_file); //얘가 범인임.

  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }


  for(int i=3;i<FD_TABLE_SIZE;i++){
    if(!cur->fdt[i]) continue;
    if(cur->fdt[i] == cur->ing_file){
      cur->fdt[i] = NULL;
      continue;
    }
    file_close(cur->fdt[i]); //닫고
    cur->fdt[i] = NULL; //table에 표시
  }


  sema_up(&(cur->sema_child)); //parent 대기 끝
  sema_down(&(cur->sema_mem)); //메모리 lock 걸기

}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
// load 함수 여기
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  // arg passing
  int word_cnt = 0; //단어 몇개일지 추측
  int arr_size = 0; //실제 단어 개수
  char** passing_arr = NULL; //여기에 잘라서 저장하겠음!

  for(int i=0;i<strlen(file_name);i++){
    if(file_name[i] == ' ') word_cnt++;
  }
  word_cnt++; //단어 개수니까 한번더 


  //복사본을 만들고
  char* file_name_copy = (char*)malloc((strlen(file_name) + 1) * sizeof(char));
  strlcpy(file_name_copy, file_name, strlen(file_name) + 1);

  // printf("복사한 문자열: %s\n\n", file_name_copy);

  char* savePtr; //strtok_r에서 공백 다음 단어 포인터를 찾는 데 이용
  char* cmdPtr =  strtok_r(file_name_copy, " ", &savePtr); //공백 기준으로 자른 첫 번째 포인터(ex. echo)

  
  // passing_arr = (char**)realloc(passing_arr, (word_cnt) * sizeof(char)); //row 추가 
  
  passing_arr = (char **)malloc(word_cnt * sizeof(char*)); //포인터 배열을 할당

  /* Open executable file. */
  file = filesys_open (cmdPtr);

  
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", cmdPtr);
      goto done; 
    }
  // printf("from a %p(%d)\n", file, file->inode->deny_write_cnt);
  file_deny_write(file); //실행 파일 읽기 모드로 변경
  // printf("from b %p(%d)\n", file, file->inode->deny_write_cnt);
  


  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;


  // printf("from c %p(%d)\n", file, file->inode->deny_write_cnt);
  // printf("%p\n", &(file->inode->deny_write_cnt));    

  while(cmdPtr != NULL){
    passing_arr[arr_size] = cmdPtr;
    // printf("   잠시만유... %s\n", passing_arr[arr_size]);
    cmdPtr = strtok_r(NULL, " ", &savePtr);
    arr_size++;
  }

// printf("while 나옴? ======= 여기까지 ㅇㅋ\n");
// printf("%p\n", &(file->inode->deny_write_cnt));
// printf("arr_size = %d\n", arr_size);
  
  int total_stack_len = 0;
  char** stack_addr_arr; //여기에 스택 주소 저장할거임
  stack_addr_arr = (char**)malloc((arr_size) * sizeof(char *)); //할당 char이슈가 있었다 ..
    
  
  //단어를 거꾸로 일단 쌓고
  for(int i=arr_size-1;i>=0;i--){
    // printf("~~%s\n", passing_arr[i]);
    // printf("~~!!%d\n", strlen(passing_arr[i]));
    int word_len = strlen(passing_arr[i]) + 1; // \0포함한 글자수
    *esp -= word_len;
    stack_addr_arr[i] = *esp; //주소 저장
    strlcpy(*esp, passing_arr[i], word_len);
    // printf("안희원 바보죠? ==== %s\n", *esp);
    total_stack_len += word_len;
  }

  // printf("거꾸로 다쌓았당!!!!!!!!!!\n\n");
  
  //word alignment를 맞춰보자
  if(total_stack_len%4){
    int q = total_stack_len/4;
    int align = (q+1)*4 - total_stack_len;
    *esp -= align;
  }
    
  
  //구분자 넣기
  *esp -= 4;
  **((uint32_t**)esp)=0;    
  
  //이제 주소를 거꾸로 쌓아보자
  for(int i=arr_size-1;i>=0;i--){
    *esp -= 4; //스택 늘리고
    **((uint32_t**)esp)=stack_addr_arr[i];
  }    
  
  //argv를 넣기
  *esp -= 4;
  **((uint32_t**)esp)= *esp + 4;    
  
  //argc를 넣기
  *esp -=4;
  **((uint32_t**)esp)= arr_size;    
  
  //return address
  *esp -=4;
  **((uint32_t**)esp)= 0;    
  
  //이제 free
  free(file_name_copy);
  free(stack_addr_arr);
  free(passing_arr);

  // printf("hex dump in construct_stack start\n\n");
  // hex_dump(*esp, *esp, 100, true);

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;
  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  if(success)  {
    t->ing_file = file; //현재 실행 파일 저장
    // printf("from c %p(%d)\n", file, file->inode->deny_write_cnt);
    // printf("from d %p(%d)\n", t->ing_file, t->ing_file->inode->deny_write_cnt);
  }
  else {
    // printf("no.1\n");
    file_close (file);
  }
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          return false; 
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;
      else
        palloc_free_page (kpage);
    }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}


