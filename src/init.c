#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/reboot.h>
#include <net/if.h>
#include <net/route.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/klog.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/reboot.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static pid_t dns_pid;
static void stop(int status) {
    printf("KG_SHUTDOWN status=%d\n", status); fflush(NULL);
    kill(-1, SIGTERM); usleep(100000); kill(-1, SIGKILL);
    while (waitpid(-1, NULL, WNOHANG) > 0) {}
    sync(); umount2("/var/lib/kiln/runs", 0);
    reboot(LINUX_REBOOT_CMD_POWER_OFF);
    for (;;) pause();
}
static void die(const char *what) {
    fprintf(stderr, "KG_FATAL %s: %s\n", what, strerror(errno)); stop(1);
}
static void mountfs(const char *src, const char *dst, const char *type,
                    unsigned long flags, const char *opts) {
    if (mount(src, dst, type, flags, opts)) die(dst);
}
static void put(const char *path, const char *value) {
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    size_t len = strlen(value);
    if (fd < 0 || write(fd, value, len) != (ssize_t)len) die(path);
    if (close(fd)) die("close");
}
static void put_if_present(const char *path, const char *value) {
    /* Compiling an interface out also removes its sysctl. Other failures
       are fatal; a kernel with the interface must apply the restriction. */
    if (access(path, F_OK)) {
        if (errno == ENOENT) return;
        die(path);
    }
    put(path, value);
}
static void linkfd(const char *target, const char *path) {
    if (symlink(target, path) && errno != EEXIST) die(path);
}
static bool option(const char *word) {
    char buf[4096]; FILE *f = fopen("/proc/cmdline", "r");
    if (!f || !fgets(buf, sizeof(buf), f)) die("cmdline");
    fclose(f);
    char *save = NULL;
    for (char *s = strtok_r(buf, " \n", &save); s; s = strtok_r(NULL, " \n", &save))
        if (!strcmp(s, word)) return true;
    return false;
}
static pid_t spawn(char *const argv[], int out, int err) {
    pid_t p = fork();
    if (p < 0) die("fork");
    if (!p) {
        if (setpgid(0, 0)) _exit(126);
        /* e48f0e7 expects traversable cgroup directories and a readable
           sandbox resolv.conf. Runtime state has its own explicit modes. */
        umask(022);
        if (out >= 0 && dup2(out, STDOUT_FILENO) < 0) _exit(126);
        if (err >= 0 && dup2(err, STDERR_FILENO) < 0) _exit(126);
        sigset_t empty; sigemptyset(&empty); sigprocmask(SIG_SETMASK, &empty, NULL);
        execv(argv[0], argv); perror(argv[0]); _exit(127);
    }
    return p;
}
static int collect(pid_t p) {
    int status;
    while (waitpid(p, &status, 0) < 0) if (errno != EINTR) die("waitpid");
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}
static int run(char *const argv[]) { return collect(spawn(argv, -1, -1)); }
static int redirected(char *const argv[]) {
    int fd=open("/run/exec-test.log",O_CREAT|O_TRUNC|O_RDWR|O_CLOEXEC|O_NOFOLLOW,0600);
    if (fd < 0) die("exec log");
    pid_t p=spawn(argv,fd,fd); int rc=collect(p);
    if (lseek(fd,0,SEEK_SET)<0) die("exec log seek");
    char buf[1024]; ssize_t n;
    while ((n=read(fd,buf,sizeof(buf)))>0) {
        if (fwrite(buf,1,(size_t)n,stdout)!=(size_t)n) die("exec log output");
    }
    close(fd); return rc;
}
#define K "/usr/bin/kiln"
#define RUN(...) run((char *const[]){K, __VA_ARGS__, NULL})
#define EXEC(...) redirected((char *const[]){K, "exec", __VA_ARGS__, NULL})
static void check(const char *name, bool ok) {
    printf("KG_TEST %s %s\n", name, ok ? "PASS" : "FAIL"); fflush(stdout);
    if (!ok) stop(2);
}
#include "dns_service.h"
static void test_work_disk(void) {
    struct statvfs flags;
    check("work-disk-flags", !statvfs("/var/lib/kiln/runs",&flags) &&
          (flags.f_flag & (ST_NOEXEC|ST_NOSUID|ST_NODEV)) == (ST_NOEXEC|ST_NOSUID|ST_NODEV));
    const char *path="/var/lib/kiln/runs/.exec-probe";
    int src=open("/init",O_RDONLY|O_CLOEXEC);
    int dst=open(path,O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC|O_NOFOLLOW,0700);
    if (src < 0 || dst < 0) die("work exec probe");
    char buf[65536]; ssize_t n;
    while ((n=read(src,buf,sizeof(buf))) > 0) {
        ssize_t done=0;
        while (done < n) {
            ssize_t written=write(dst,buf+done,(size_t)(n-done));
            if (written < 0 && errno == EINTR) continue;
            if (written <= 0) die("copy exec probe");
            done+=written;
        }
    }
    if (n < 0 || fchmod(dst,0755)) die("exec probe mode");
    close(src); if (close(dst)) die("exec probe close");
    pid_t p=fork(); if (p < 0) die("exec probe fork");
    if (!p) { execl(path,path,(char *)NULL); _exit(errno == EACCES ? 0 : 1); }
    check("work-direct-exec-denied",collect(p) == 0);
    if (unlink(path)) die("exec probe unlink");
    check("overlay-workspace-exec",RUN("run","--","sh","-c",
          "awk '$2==\"/\" && $3==\"overlay\" {print; if ($4 !~ /(^|,)noexec(,|$)/) ok=1} END{exit !ok}' /proc/mounts && cp /bin/busybox /workspace/busybox && /workspace/busybox true") == 0);
}
static void loopback(void) {
    int fd = socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC, 0);
    if (fd < 0) die("loopback socket");
    struct ifreq req = {0}; strcpy(req.ifr_name, "lo");
    if (ioctl(fd, SIOCGIFFLAGS, &req)) die("lo flags");
    req.ifr_flags |= IFF_UP;
    if (ioctl(fd, SIOCSIFFLAGS, &req)) die("lo up");
    close(fd);
}
static void network(void) {
    /* Test-only fixed /30 link. Phase 1b must supply per-session addressing. */
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) die("network socket");
    struct ifreq req = {0}; strcpy(req.ifr_name, "eth0");
    struct sockaddr_in *a = (struct sockaddr_in *)&req.ifr_addr;
    a->sin_family = AF_INET; inet_pton(AF_INET, "172.30.99.2", &a->sin_addr);
    if (ioctl(fd, SIOCSIFADDR, &req)) die("eth0 address");
    inet_pton(AF_INET, "255.255.255.252", &a->sin_addr);
    if (ioctl(fd, SIOCSIFNETMASK, &req)) die("eth0 mask");
    req.ifr_flags = IFF_UP;
    if (ioctl(fd, SIOCSIFFLAGS, &req)) die("eth0 up");
    struct rtentry route = {0};
    ((struct sockaddr_in *)&route.rt_dst)->sin_family = AF_INET;
    ((struct sockaddr_in *)&route.rt_genmask)->sin_family = AF_INET;
    a = (struct sockaddr_in *)&route.rt_gateway; a->sin_family = AF_INET;
    inet_pton(AF_INET, "172.30.99.1", &a->sin_addr);
    route.rt_flags = RTF_UP | RTF_GATEWAY; route.rt_dev = "eth0";
    if (ioctl(fd, SIOCADDRT, &route)) die("default route");
    close(fd);
}
static void tests(bool net) {
    int logsize=klogctl(10,NULL,0);
    check("kernel-log-bounded", logsize > 0 && logsize <= 1024*1024);
    char *log=calloc(1,(size_t)logsize+1); if (!log) die("kernel log allocation");
    check("kernel-log-readable", klogctl(3,log,logsize) >= 0);
    check("kaslr-enabled", strstr(log,"KASLR enabled") != NULL &&
          strstr(log,"KASLR disabled") == NULL);
    free(log);
    test_dns_status();
    test_work_disk();
    check("kexec-load-absent", syscall(SYS_kexec_load, 0, 0, NULL, 0) == -1 && errno == ENOSYS);
    check("kexec-file-absent", syscall(SYS_kexec_file_load, -1, -1, 0, NULL, 0) == -1 && errno == ENOSYS);
    const char *kexec = "/proc/sys/kernel/kexec_load_disabled";
    FILE *kf = fopen(kexec, "r");
    if (!kf) check("kexec-sysctl-compiled-out", errno == ENOENT);
    else {
        int value = 0; int n = fscanf(kf, "%d", &value); fclose(kf);
        check("kexec-sysctl-disabled", n == 1 && value == 1);
        int fd = open(kexec, O_WRONLY|O_CLOEXEC);
        check("kexec-sysctl-irreversible", fd >= 0 && write(fd, "0\n", 2) == -1);
        close(fd);
    }
    check("bpf-syscall-absent", syscall(SYS_bpf, 0, NULL, 0) == -1 && errno == ENOSYS);
    check("io-uring-absent", syscall(SYS_io_uring_setup, 0, NULL) == -1 && errno == ENOSYS);
    check("userfaultfd-absent", syscall(SYS_userfaultfd, 0) == -1 && errno == ENOSYS);
    check("perf-events-absent", syscall(SYS_perf_event_open, NULL, 0, -1, -1, 0) == -1 && errno == ENOSYS);
    check("modules-absent", syscall(SYS_init_module, NULL, 0, "") == -1 && errno == ENOSYS);
    check("proc-kcore-absent", access("/proc/kcore", F_OK) == -1 && errno == ENOENT);
    check("devmem-absent", access("/dev/mem", F_OK) == -1 && errno == ENOENT);
    check("devkmem-absent", access("/dev/kmem", F_OK) == -1 && errno == ENOENT);
    check("debugfs-absent", mount("debugfs", "/tmp", "debugfs", 0, NULL) == -1);
    char lockdown[128] = {0}; FILE *lf = fopen("/sys/kernel/security/lockdown", "r");
    check("lockdown-readable", lf && fgets(lockdown, sizeof(lockdown), lf)); fclose(lf);
    check("lockdown-confidentiality", strstr(lockdown, "[confidentiality]") != NULL);
    check("readonly", RUN("run", "--read-only", "--", "sh", "-c",
        "! touch /etc/should-fail && touch /workspace/ok") == 0);
    check("limits", RUN("run", "--memory", "64M", "--pids", "16", "--disk", "16M", "--", "sh", "-c",
        "test $(cat /sys/fs/cgroup/memory.max) = 67108864 && test $(cat /sys/fs/cgroup/pids.max) = 16 && ! dd if=/dev/zero of=/workspace/big bs=1M count=24") == 0);
    check("memory-oom", RUN("run", "--memory", "32M", "--", "awk",
        "BEGIN { s=\"x\"; for(i=0;i<30;i++) s=s s; print length(s) }") == 137);
    check("pids-enforced", RUN("run", "--pids", "2", "--", "xargs", "true") != 0);
    int fds[2]; if (pipe2(fds, O_CLOEXEC)) die("pipe");
    pid_t p = spawn((char *const[]){K,"create","--memory","64M","--pids","16","--disk","16M",NULL}, fds[1], -1);
    close(fds[1]); char id[128] = {0}; ssize_t n = read(fds[0], id, sizeof(id)-1); close(fds[0]);
    check("create", collect(p) == 0 && n > 0);
    id[strcspn(id, "\r\n")] = 0;
    check("exec-write", EXEC(id, "--", "sh", "-c", "echo preserved >/workspace/message") == 0);
    check("exec-persist", EXEC(id, "--", "sh", "-c", "test $(cat /workspace/message) = preserved") == 0);
    check("rm", RUN("rm", id) == 0);
    check("exec-removed", EXEC(id, "--", "true") != 0);
    check("net-full-rules", RUN("run", "--net", "full", "--", "true") == 0);
    check("allow-rules", RUN("run", "--allow", "1.1.1.1:80", "--", "true") == 0);
    check("private-denied", RUN("run", "--allow", "169.254.169.254:80", "--", "true") != 0);
    if (net) {
        check("full-dns", RUN("run", "--net", "full", "--", "nslookup", "example.com") == 0);
        check("full-egress", RUN("run", "--net", "full", "--", "wget", "-T", "10", "-qO", "/dev/null", "http://example.com") == 0);
        check("allow-egress", RUN("run", "--allow", "example.com:80", "--", "wget", "-T", "10", "-qO", "/dev/null", "http://example.com") == 0);
        check("allow-dns-denied", RUN("run", "--allow", "example.com:80", "--", "nslookup", "example.net") != 0);
    }
    check("nft-ruleset", run((char *const[]){"/usr/sbin/nft","list","ruleset",NULL}) == 0);
    printf("KG_TESTS_COMPLETE\n"); fflush(stdout); stop(0);
}
int main(void) {
    if (getpid() != 1) { fputs("must run as PID 1\n", stderr); return 1; }
    umask(077);
    clearenv(); setenv("PATH", "/usr/bin:/usr/sbin", 1); setenv("HOME", "/", 1);
    setenv("LANG", "C", 1);
    setvbuf(stdout, NULL, _IOLBF, 0); setvbuf(stderr, NULL, _IOLBF, 0);
    mountfs("proc", "/proc", "proc", MS_NOSUID|MS_NODEV|MS_NOEXEC, NULL);
    put_if_present("/proc/sys/kernel/kexec_load_disabled", "1\n");
    mountfs("sysfs", "/sys", "sysfs", MS_NOSUID|MS_NODEV|MS_NOEXEC, NULL);
    mountfs("securityfs", "/sys/kernel/security", "securityfs", MS_NOSUID|MS_NODEV|MS_NOEXEC, NULL);
    /* devtmpfs is mounted by the kernel; refuse a missing console/device tree. */
    if (access("/dev/vdb", F_OK)) die("work disk");
    int null = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (null < 0 || dup2(null, STDIN_FILENO) < 0) die("stdin");
    close(null);
    linkfd("/proc/self/fd", "/dev/fd");
    linkfd("/proc/self/fd/0", "/dev/stdin");
    linkfd("/proc/self/fd/1", "/dev/stdout");
    linkfd("/proc/self/fd/2", "/dev/stderr");
    mountfs("tmpfs", "/run", "tmpfs", MS_NOSUID|MS_NODEV|MS_NOEXEC, "mode=0755,size=16M");
    mountfs("tmpfs", "/tmp", "tmpfs", MS_NOSUID|MS_NODEV|MS_NOEXEC, "mode=1777,size=32M");
    mountfs("cgroup2", "/sys/fs/cgroup", "cgroup2", MS_NOSUID|MS_NODEV|MS_NOEXEC, NULL);
    mountfs("/dev/vdb", "/var/lib/kiln/runs", "xfs", MS_NOSUID|MS_NODEV|MS_NOEXEC, "prjquota");
    put("/proc/sys/kernel/kptr_restrict", "2\n");
    put("/proc/sys/kernel/dmesg_restrict", "1\n");
    put_if_present("/proc/sys/kernel/unprivileged_bpf_disabled", "1\n");
    loopback();
    if (option("kiln.net=1")) network();
    check("first-true", RUN("run", "--", "true") == 0);
    puts("KG_FIRST_COMMAND");
    const char *dirs[] = {"/run/kiln", "/run/kiln/net", "/run/kiln/net/dns", "/run/kiln/net/leases"};
    for (size_t i=0; i<sizeof(dirs)/sizeof(dirs[0]); i++) {
        if (mkdir(dirs[i],0755) && errno != EEXIST) die("DNS runtime directory");
        if (chmod(dirs[i],0755)) die("DNS runtime directory mode");
    }
    check("network-setup", RUN("network-setup") == 0);
    dns_pid = start_dns(option("kiln.test=1"));
    bool ready = false;
    for (int i=0; i<100; i++) {
        int fd = socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (fd < 0) die("DNS probe socket");
        struct sockaddr_in a = {.sin_family=AF_INET, .sin_port=htons(53)};
        inet_pton(AF_INET, "10.88.0.1", &a.sin_addr);
        int rc = connect(fd, (struct sockaddr *)&a, sizeof(a));
        if (rc && errno == EINPROGRESS) {
            struct pollfd pollfd = {.fd=fd, .events=POLLOUT};
            int error=ETIMEDOUT; socklen_t size=sizeof(error);
            if (poll(&pollfd,1,100)>0 && !getsockopt(fd,SOL_SOCKET,SO_ERROR,&error,&size)) rc=error ? -1 : 0;
        }
        close(fd);
        if (!rc) { ready=true; break; }
        if (waitpid(dns_pid, NULL, WNOHANG) != 0) die("kiln dns exited");
        usleep(10000);
    }
    check("dns-ready", ready);
    puts("KG_READY");
    /* Phase 1b broker hook: disabled. No vsock or serial command listener. */
    if (option("kiln.test=1")) tests(option("kiln.net=1"));
    sigset_t signals; sigemptyset(&signals);
    sigaddset(&signals, SIGTERM); sigaddset(&signals, SIGINT);
    sigaddset(&signals, SIGHUP); sigaddset(&signals, SIGCHLD);
    if (sigprocmask(SIG_BLOCK, &signals, NULL)) die("sigprocmask");
    int sfd = signalfd(-1, &signals, SFD_CLOEXEC);
    if (sfd < 0) die("signalfd");
    for (;;) {
        int status; pid_t p;
        while ((p=waitpid(-1, &status, WNOHANG)) > 0)
            if (p == dns_pid) { errno=ECHILD; die("kiln dns died"); }
        struct signalfd_siginfo info;
        if (read(sfd, &info, sizeof(info)) != (ssize_t)sizeof(info)) {
            if (errno == EINTR) continue;
            die("signalfd read");
        }
        if (info.ssi_signo != SIGCHLD) stop(0);
    }
}
