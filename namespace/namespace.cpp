//
// Created by liuhao on 2019/9/2.
//

#include "namespace.h"

void enableNamespace(){
    using namespace std;
    auto namespaceError=[](const char* kind){
        char buffer[0x100];
        snprintf(buffer,sizeof(buffer),"enable %s fail",kind);
        perror(buffer);
    };
    auto CHECK_EQUAL=[&namespaceError](int ret,int expect,const char* kind){
        if(ret!=expect){
            namespaceError(kind);
            exit(1);
        }
    };
    CHECK_EQUAL(unshare(CLONE_NEWUSER),0,"unshare(CLONE_NEWUSER)");
    CHECK_EQUAL(unshare(CLONE_NEWNET),0,"unshare(CLONE_NEWNET)");
    CHECK_EQUAL(unshare(CLONE_NEWCGROUP),0,"unshare(CLONE_NEWCGROUP)");
}
