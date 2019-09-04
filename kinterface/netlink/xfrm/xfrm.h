//
// Created by liuhao on 2019/9/2.
//

#ifndef FUZZER_XFRM_H
#define FUZZER_XFRM_H


#include "../base/base_nl.h"
#include <cstdio>
#include <cstring>
#include <ctime>
#include <cerrno>
#include <cstdlib>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <linux/xfrm.h>
#include <linux/netlink.h>
#include <sys/resource.h>

#include <iostream>
#include <netlink/types.h>
#include <netlink/xfrm/sa.h>
/*
#include <netlink/types.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/xfrm/sa.h>
*/



class xfrmNl : baseNl {
public:
    xfrmNl();
    virtual ~xfrmNl() = default;
    virtual int sa_add();
private:
    int fd_xfrm_state;
};

#endif //FUZZER_XFRM_H
