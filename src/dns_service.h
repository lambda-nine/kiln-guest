/* Phase 0 kiln-dns.service's boundary, applied without systemd. */
#include <grp.h>
#include <stddef.h>
#include <sched.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/securebits.h>
#include <sys/resource.h>
#include <sys/sysmacros.h>

#define DNS_UID 65532
#define DNS_GID 65532
#define DNS_CAP (1U << CAP_NET_BIND_SERVICE)

static void dns_fail(const char *what) {
    fprintf(stderr, "KG_FATAL DNS boundary %s: %s\n", what, strerror(errno));
    _exit(126);
}
#define DNS_REQUIRE(ok, what) do { if (!(ok)) dns_fail(what); } while (0)

static void dns_readonly(const char *path) {
    DNS_REQUIRE(!mount(path, path, NULL, MS_BIND, NULL), path);
    DNS_REQUIRE(!mount(NULL, path, NULL, MS_BIND|MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NODEV|MS_NOEXEC, NULL), path);
}
static void dns_filter(void) {
#define DNS_ALLOW(name) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, SYS_##name, 0, 1), BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW)
    const unsigned int namespaces = CLONE_NEWNS|CLONE_NEWCGROUP|CLONE_NEWUTS|
        CLONE_NEWIPC|CLONE_NEWUSER|CLONE_NEWPID|CLONE_NEWNET;
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, AUDIT_ARCH_AARCH64, 1, 0),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, nr)),
        /* glibc falls back to clone when clone3 is unavailable. */
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, SYS_clone3, 0, 1),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ERRNO|ENOSYS),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, SYS_clone, 0, 5),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K, namespaces, 2, 0),
        BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K, CLONE_THREAD, 0, 1),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ERRNO|EPERM),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, SYS_socket, 0, 5),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, AF_INET, 1, 0),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, AF_UNIX, 0, 1),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ERRNO|EPERM),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, nr)),
        DNS_ALLOW(read), DNS_ALLOW(write), DNS_ALLOW(readv), DNS_ALLOW(writev),
        DNS_ALLOW(pread64), DNS_ALLOW(pwrite64), DNS_ALLOW(close), DNS_ALLOW(close_range),
        DNS_ALLOW(openat), DNS_ALLOW(newfstatat), DNS_ALLOW(fstat), DNS_ALLOW(statx),
        DNS_ALLOW(lseek), DNS_ALLOW(readlinkat), DNS_ALLOW(getdents64),
        DNS_ALLOW(faccessat), DNS_ALLOW(faccessat2), DNS_ALLOW(fcntl), DNS_ALLOW(ioctl),
        DNS_ALLOW(mmap), DNS_ALLOW(munmap), DNS_ALLOW(mprotect), DNS_ALLOW(mremap),
        DNS_ALLOW(madvise), DNS_ALLOW(brk), DNS_ALLOW(getrandom),
        DNS_ALLOW(rt_sigaction), DNS_ALLOW(rt_sigprocmask), DNS_ALLOW(rt_sigreturn),
        DNS_ALLOW(sigaltstack), DNS_ALLOW(rt_sigpending), DNS_ALLOW(rt_sigtimedwait),
        DNS_ALLOW(set_tid_address), DNS_ALLOW(set_robust_list), DNS_ALLOW(futex),
        DNS_ALLOW(rseq), DNS_ALLOW(membarrier), DNS_ALLOW(tgkill),
        DNS_ALLOW(getpid), DNS_ALLOW(getppid), DNS_ALLOW(gettid),
        DNS_ALLOW(getuid), DNS_ALLOW(geteuid), DNS_ALLOW(getgid), DNS_ALLOW(getegid),
        DNS_ALLOW(capget), DNS_ALLOW(prctl), DNS_ALLOW(prlimit64),
        DNS_ALLOW(sched_getaffinity), DNS_ALLOW(sched_yield),
        DNS_ALLOW(clock_gettime), DNS_ALLOW(clock_getres), DNS_ALLOW(gettimeofday),
        DNS_ALLOW(clock_nanosleep), DNS_ALLOW(nanosleep), DNS_ALLOW(uname),
        DNS_ALLOW(ppoll), DNS_ALLOW(pselect6), DNS_ALLOW(epoll_create1),
        DNS_ALLOW(epoll_ctl), DNS_ALLOW(epoll_pwait), DNS_ALLOW(epoll_pwait2),
        DNS_ALLOW(eventfd2), DNS_ALLOW(pipe2),
        DNS_ALLOW(bind), DNS_ALLOW(listen), DNS_ALLOW(accept), DNS_ALLOW(accept4),
        DNS_ALLOW(connect), DNS_ALLOW(getsockname), DNS_ALLOW(getpeername),
        DNS_ALLOW(setsockopt), DNS_ALLOW(getsockopt), DNS_ALLOW(shutdown),
        DNS_ALLOW(sendto), DNS_ALLOW(recvfrom), DNS_ALLOW(sendmsg), DNS_ALLOW(recvmsg),
        DNS_ALLOW(sendmmsg), DNS_ALLOW(recvmmsg),
        /* Initial exec of the read-only static kiln binary. NNP and the
           capability bounding set survive subsequent execs as well. */
        DNS_ALLOW(execve), DNS_ALLOW(exit), DNS_ALLOW(exit_group),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ERRNO|EPERM),
    };
    struct sock_fprog program = {.len=sizeof(filter)/sizeof(filter[0]), .filter=filter};
    DNS_REQUIRE(!prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), "no_new_privs");
    DNS_REQUIRE(!syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &program), "seccomp");
#undef DNS_ALLOW
}
static void dns_probe(const char *name, bool ok) {
    printf("KG_TEST %s %s\n", name, ok ? "PASS" : "FAIL"); fflush(stdout);
    if (!ok) _exit(126);
}
static void dns_restrict(bool test) {
    DNS_REQUIRE(!unshare(CLONE_NEWNS), "mount namespace");
    DNS_REQUIRE(!mount(NULL, "/", NULL, MS_REC|MS_PRIVATE, NULL), "private mounts");
    dns_readonly("/run"); dns_readonly("/proc"); dns_readonly("/sys");
    DNS_REQUIRE(!mount("tmpfs", "/var/lib/kiln", "tmpfs", MS_RDONLY|MS_NOSUID|MS_NODEV|MS_NOEXEC,
                      "mode=000,size=4k"), "hide tenant storage");
    DNS_REQUIRE(!mount("tmpfs", "/run/kiln/net/leases", "tmpfs", MS_RDONLY|MS_NOSUID|MS_NODEV|MS_NOEXEC,
                      "mode=000,size=4k"), "hide leases");
    DNS_REQUIRE(!mount("tmpfs", "/tmp", "tmpfs", MS_NOSUID|MS_NODEV|MS_NOEXEC,
                      "mode=0700,uid=65532,gid=65532,size=4M"), "private tmp");
    DNS_REQUIRE(!mount("tmpfs", "/dev", "tmpfs", MS_NOSUID|MS_NOEXEC, "mode=0755,size=64k"), "private devices");
    const char *devices[] = {"/dev/null", "/dev/zero", "/dev/random", "/dev/urandom"};
    const unsigned int minors[] = {3, 5, 8, 9};
    for (size_t i=0; i<4; i++) {
        DNS_REQUIRE(!mknod(devices[i], S_IFCHR|0666, makedev(1,minors[i])), "device");
        DNS_REQUIRE(!chmod(devices[i], 0666), "device mode");
    }
    DNS_REQUIRE(!symlink("/proc/self/fd", "/dev/fd"), "dev fd");
    DNS_REQUIRE(!mount(NULL, "/dev", NULL, MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NOEXEC, NULL), "readonly devices");
    struct rlimit files = {1024,1024}, processes = {64,64}, core = {0,0};
    DNS_REQUIRE(!setrlimit(RLIMIT_NOFILE,&files) && !setrlimit(RLIMIT_NPROC,&processes) &&
                !setrlimit(RLIMIT_CORE,&core), "resource limits");
    /* Drop every bounding capability except low-port bind before changing UID. */
    for (int cap=0; ; cap++) {
        int present=prctl(PR_CAPBSET_READ,cap,0,0,0);
        if (present < 0 && errno == EINVAL) break;
        DNS_REQUIRE(present >= 0, "read bounding set");
        if (cap != CAP_NET_BIND_SERVICE) DNS_REQUIRE(!prctl(PR_CAPBSET_DROP,cap,0,0,0), "drop bounding set");
    }
    DNS_REQUIRE(!prctl(PR_SET_SECUREBITS, SECBIT_NOROOT|SECBIT_NOROOT_LOCKED, 0, 0, 0), "securebits");
    DNS_REQUIRE(!prctl(PR_SET_KEEPCAPS,1,0,0,0), "keep selected capability");
    DNS_REQUIRE(!setgroups(0,NULL) && !setgid(DNS_GID) && !setuid(DNS_UID), "DNS credentials");
    struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3,0};
    struct __user_cap_data_struct caps[2] = {{DNS_CAP,DNS_CAP,DNS_CAP},{0,0,0}};
    DNS_REQUIRE(!syscall(SYS_capset,&header,caps), "selected capability");
    DNS_REQUIRE(!prctl(PR_CAP_AMBIENT,PR_CAP_AMBIENT_RAISE,CAP_NET_BIND_SERVICE,0,0), "ambient bind");
    dns_filter();
    if (test) {
        dns_probe("dns-root-denied", setuid(0) == -1 && errno == EPERM);
        dns_probe("dns-namespace-denied", unshare(CLONE_NEWUSER) == -1 && errno == EPERM);
        dns_probe("dns-netlink-denied", socket(AF_NETLINK,SOCK_RAW|SOCK_CLOEXEC,0) == -1 && errno == EPERM);
        int fd=open("/run/kiln/net/dns/service-write-probe",O_CREAT|O_WRONLY|O_CLOEXEC,0600);
        dns_probe("dns-policy-readonly", fd == -1 && errno == EROFS);
        fd=open("/var/lib/kiln/runs",O_RDONLY|O_CLOEXEC);
        dns_probe("dns-tenant-storage-hidden", fd == -1 && (errno == ENOENT || errno == EACCES));
    }
}
static pid_t start_dns(bool test) {
    pid_t p=fork();
    if (p < 0) die("fork DNS");
    if (!p) {
        DNS_REQUIRE(!setpgid(0,0), "DNS process group");
        dns_restrict(test);
        execl(K,K,"dns",(char *)NULL); dns_fail("exec");
    }
    return p;
}
static void test_dns_status(void) {
    char path[128], line[512]; snprintf(path,sizeof(path),"/proc/%d/status",dns_pid);
    FILE *f=fopen(path,"r"); check("dns-status-readable",f != NULL);
    unsigned int uid[4]={0},gid[4]={0}; unsigned long long inh=0,prm=0,eff=0,bnd=0,amb=0;
    int nnp=0,seccomp=0;
    while (fgets(line,sizeof(line),f)) {
        if (!strncmp(line,"Uid:",4)) (void)sscanf(line+4,"%u%u%u%u",uid,uid+1,uid+2,uid+3);
        if (!strncmp(line,"Gid:",4)) (void)sscanf(line+4,"%u%u%u%u",gid,gid+1,gid+2,gid+3);
        if (!strncmp(line,"CapInh:",7)) (void)sscanf(line+7,"%llx",&inh);
        if (!strncmp(line,"CapPrm:",7)) (void)sscanf(line+7,"%llx",&prm);
        if (!strncmp(line,"CapEff:",7)) (void)sscanf(line+7,"%llx",&eff);
        if (!strncmp(line,"CapBnd:",7)) (void)sscanf(line+7,"%llx",&bnd);
        if (!strncmp(line,"CapAmb:",7)) (void)sscanf(line+7,"%llx",&amb);
        if (!strncmp(line,"NoNewPrivs:",11)) (void)sscanf(line+11,"%d",&nnp);
        if (!strncmp(line,"Seccomp:",8)) (void)sscanf(line+8,"%d",&seccomp);
    }
    fclose(f);
    check("dns-nonroot", uid[0]==DNS_UID && uid[1]==DNS_UID && uid[2]==DNS_UID && uid[3]==DNS_UID &&
          gid[0]==DNS_GID && gid[1]==DNS_GID && gid[2]==DNS_GID && gid[3]==DNS_GID);
    check("dns-only-bind-capability", inh==DNS_CAP && prm==DNS_CAP && eff==DNS_CAP && bnd==DNS_CAP && amb==DNS_CAP);
    check("dns-no-new-privileges", nnp==1); check("dns-seccomp", seccomp==2);
}
#undef DNS_REQUIRE
