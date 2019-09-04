//
// Created by liuhao on 2019/9/2.
//

#include "xfrm.h"
#include <log.h>
#include <check.h>

void xfrmNl::bindSendRecv(){

}

xfrmNl::xfrmNl() {
    struct sockaddr_nl snl={
        .nl_family=PF_NETLINK,
    };
    snl.nl_pid=getpid();
    fd_xfrm_state = socket(PF_NETLINK, SOCK_RAW, NETLINK_XFRM);
    CHECK_UNEXPECT_EQUAL(fd_xfrm_state,-1);
    CHECK_UNEXPECT_EQUAL(bind(fd_xfrm_state, (struct sockaddr *)&snl, sizeof(snl)),-1);
}