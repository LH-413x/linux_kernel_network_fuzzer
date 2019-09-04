//
// Created by liuhao on 2019/9/3.
//

#ifndef FUZZER_LOG_H
#define FUZZER_LOG_H

#include <cstdio>

#define RED   "\x1B[31m"
#define GRN   "\x1B[32m"
#define YEL   "\x1B[33m"
#define BLU   "\x1B[34m"
#define MAG   "\x1B[35m"
#define CYN   "\x1B[36m"
#define WHT   "\x1B[37m"
#define RESET "\x1B[0m"

#define LOGI(fmt, args...) fprintf(stdout, "\n%sTRACE%s %s: " fmt, \
    BLU,RESET,__func__, ##args)

#define LOGD(fmt, args...) fprintf(stdout, "\n%sDEBUG%s %s: " fmt, \
    GRN,RESET,__func__, ##args)

#define LOGE(fmt, args...) fprintf(stdout, "\n%sFATAL%s %s: " fmt, \
     RED,RESET,__func__, ##args)
#endif //FUZZER_LOG_H
