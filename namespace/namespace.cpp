//
// Created by liuhao on 2019/9/2.
//

#include "namespace.h"
#include <check.h>
#include <log.h>
void enableNamespace(){
    CHECK_EXPECT_EQUAL(unshare(CLONE_NEWUSER),0);
    CHECK_EXPECT_EQUAL(unshare(CLONE_NEWNET),0);
    CHECK_EXPECT_EQUAL(unshare(CLONE_NEWCGROUP),0);
}
