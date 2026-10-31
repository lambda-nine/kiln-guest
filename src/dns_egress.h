/* Fixed upstream matches immutable /etc/resolv.conf. Independent of kiln's
 * reconciled inet table, so later sandbox rule updates cannot erase it. */
static void install_dns_egress(void) {
    const char *rules=
        "table inet kg_dns {\n"
        " chain output { type filter hook output priority -10; policy accept;\n"
        "  meta skuid 65532 ip daddr 1.1.1.1 meta l4proto { tcp, udp } th dport 53 counter accept\n"
        /* Only replies to existing client flows, never new service-originated
         * connections to tenants. TCP SYN-ACK and UDP replies are tracked. */
        "  meta skuid 65532 ct direction reply ct state established ip saddr 10.88.0.1 ip daddr 10.88.0.0/16 meta l4proto { tcp, udp } th sport 53 counter accept\n"
        "  meta skuid 65532 counter reject with icmpx type admin-prohibited\n"
        " }\n}\n";
    int fd=open("/run/dns-egress.nft",O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC|O_NOFOLLOW,0600);
    if (fd<0 || write(fd,rules,strlen(rules))!=(ssize_t)strlen(rules)) die("DNS egress file");
    if (close(fd)) die("DNS egress close");
    if (run((char *const[]){"/usr/sbin/nft","-f","/run/dns-egress.nft",NULL})) die("DNS egress policy");
}
static bool dns_udp_send(const char *ip, unsigned short port) {
    int fd=socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0);
    if (fd<0) dns_fail("egress probe socket");
    struct sockaddr_in a={.sin_family=AF_INET,.sin_port=htons(port)};
    if (inet_pton(AF_INET,ip,&a.sin_addr)!=1) dns_fail("egress probe address");
    /* A valid DNS query for the root NS; no private application data. */
    const unsigned char query[]={0x4b,0x47,1,0,0,1,0,0,0,0,0,0,0,0,2,0,1};
    ssize_t n=sendto(fd,query,sizeof(query),0,(struct sockaddr *)&a,sizeof(a));
    int error=errno; close(fd); errno=error;
    return n==(ssize_t)sizeof(query);
}
static bool dns_tcp_denied(const char *ip, unsigned short port) {
    int fd=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK,0);
    if (fd<0) dns_fail("TCP egress probe socket");
    struct sockaddr_in a={.sin_family=AF_INET,.sin_port=htons(port)};
    if (inet_pton(AF_INET,ip,&a.sin_addr)!=1) dns_fail("TCP egress address");
    int rc=connect(fd,(struct sockaddr *)&a,sizeof(a)), error=errno;
    if (rc<0 && error==EINPROGRESS) {
        struct pollfd p={.fd=fd,.events=POLLOUT}; socklen_t size=sizeof(error);
        if (poll(&p,1,1000)<=0 || getsockopt(fd,SOL_SOCKET,SO_ERROR,&error,&size)) error=0;
    }
    close(fd); printf("KG_DNS_TCP_DENIAL errno=%d\n",error);
    return error==EACCES || error==EPERM || error==EHOSTUNREACH;
}
static void test_dns_egress(void) {
    dns_probe("dns-upstream-query-allowed",dns_udp_send("1.1.1.1",53));
    dns_probe("dns-private-egress-denied",!dns_udp_send("172.30.99.1",53) && (errno==EACCES || errno==EPERM));
    dns_probe("dns-other-resolver-denied",!dns_udp_send("8.8.8.8",53) && (errno==EACCES || errno==EPERM));
    dns_probe("dns-upstream-wrong-port-denied",!dns_udp_send("1.1.1.1",80) && (errno==EACCES || errno==EPERM));
    dns_probe("dns-tenant-egress-denied",!dns_udp_send("10.88.0.2",53) && (errno==EACCES || errno==EPERM));
    dns_probe("dns-tcp-private-denied",dns_tcp_denied("172.30.99.1",53));
    dns_probe("dns-tcp-wrong-port-denied",dns_tcp_denied("1.1.1.1",80));
}
