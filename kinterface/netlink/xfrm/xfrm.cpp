//
// Created by liuhao on 2019/9/2.
//

#include "xfrm.h"
#include <log.h>
#include <check.h>

int flags[]={
        NLM_F_REQUEST,	/* It is request message. 	*/
        NLM_F_MULTI,	/* Multipart message, terminated by NLMSG_DONE */
        NLM_F_ACK,	/* Reply with ack, with zero or error code */
        NLM_F_ECHO,	/* Echo this request 		*/
        NLM_F_DUMP_INTR,	/* Dump was inconsistent due to sequence change */
        NLM_F_DUMP_FILTERED,	/* Dump was filtered as requested */
        NLM_F_ROOT,	/* specify tree	root	*/
        NLM_F_MATCH,	/* return all matching	*/
        NLM_F_ATOMIC,	/* atomic GET		*/
        //NLM_F_DUMP,
        //(NLM_F_ROOT|NLM_F_MATCH),
        NLM_F_REPLACE,	/* Override existing		*/
        NLM_F_EXCL,	/* Do not touch, if it exists	*/
        NLM_F_CREATE,	/* Create, if it does not exist	*/
        NLM_F_APPEND,	/* Add to end of list		*/
        NLM_F_NONREC,	/* Do not delete recursively	*/
        NLM_F_CAPPED,	/* request was capped */
        NLM_F_ACK_TLVS,	/* extended ACK TVLs were included */
};

int xfrmNl::sa_add(){
    struct nl_sock *socket;
    socket = nl_socket_alloc();  // Allocate new netlink socket in memory.
    if (0 != nl_connect(socket, NETLINK_XFRM)) {
        LOGE("ERROR on nl_connect\n");
    }

    int err = 0;
    struct xfrmnl_sa *sa;
    sa = xfrmnl_sa_alloc();
    if (!sa) {
        printf("ERROR in xfrmnl_sa_alloc\n");
        return -1;
    }

    const char* auth_alg_name = "helloworld";
    const char* auth_key = "12345678901234567890123456789012";
    unsigned int auth_key_len = strlen(auth_key);
    unsigned int auth_trunc_len = 96;
    if (0 != xfrmnl_sa_set_auth_params(sa, auth_alg_name, auth_key_len, auth_trunc_len, auth_key)) {
        LOGE("ERROR in xfrmnl_sa_set_auth_params\n");
        goto clean;
    }

    err = xfrmnl_sa_add(socket, sa, 0);
    if (err < 0) {
        LOGE("ERROR in xfrm_sa_add, error code %d\n",err);
        goto clean;
    }
clean:
    xfrmnl_sa_put(sa);
    nl_close(socket);
    return 0;
}

xfrmNl::xfrmNl() {
    /*
    struct sockaddr_nl snl={
        .nl_family=PF_NETLINK,
    };
    snl.nl_pid=getpid();
    fd_xfrm_state = socket(PF_NETLINK, SOCK_RAW, NETLINK_XFRM);
    CHECK_UNEXPECT_EQUAL(fd_xfrm_state,-1);
    CHECK_UNEXPECT_EQUAL(bind(fd_xfrm_state, (struct sockaddr *)&snl, sizeof(snl)),-1);
*/
}