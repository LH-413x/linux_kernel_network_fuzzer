//
// Created by liuhao on 2019/9/3.
//

#ifndef FUZZER_CHECK_H
#define FUZZER_CHECK_H

#define CHECK_EXPECT_EQUAL(expr,expect)  \
    { \
        uint64_t result=expr; \
        if((result)!=(expect)){ \
            char buffer[0x100]; \
            snprintf(buffer,sizeof(buffer), \
                "CHECK_EXPECT_EQUAL %s not equal %s",#expr,#expect); \
            LOGE("%s",buffer); \
            exit(0); \
        } \
    }

#define CHECK_UNEXPECT_EQUAL(expr,expect) \
    { \
        uint64_t result=expr; \
        if((result)==(expect)){ \
            char buffer[0x100]; \
            snprintf(buffer,sizeof(buffer), \
                "CHECK_EXPECT_EQUAL %s not equal %s",#expr,#expect); \
            LOGE("%s",buffer); \
            exit(0); \
        } \
    }

#endif //FUZZER_CHECK_H
