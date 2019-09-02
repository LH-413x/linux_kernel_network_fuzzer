//
// Created by liuhao on 2019/9/2.
//

#include "xfrm.h"
void xfrmNl::bindSendRecv(){

}

xfrmNl::xfrmNl() {
    auto network_error=[](const char* kind){
        char buffer[0x100];
        snprintf(buffer,sizeof(buffer),"xfrmNl %s fail",kind);
        perror(buffer);
    };
    auto CHECK_UNEXPECT_EQUAL = [&network_error](int result,int unexpect,const char* kind){
        if(result==unexpect){
            network_error(kind);
        }
    };
    struct sockaddr_nl snl={
        .nl_family=PF_NETLINK,
    };
    snl.nl_pid=getpid();
    fd_xfrm_state = socket(PF_NETLINK, SOCK_RAW, NETLINK_XFRM);
    CHECK_UNEXPECT_EQUAL(fd_xfrm_state,
            -1,"socket(PF_NETLINK, SOCK_RAW, NETLINK_XFRM)");
    CHECK_UNEXPECT_EQUAL(bind(fd_xfrm_state, (struct sockaddr *)&snl, sizeof(snl)),
            -1,"bind(fd_xfrm_state, (struct sockaddr *)&snl");
}