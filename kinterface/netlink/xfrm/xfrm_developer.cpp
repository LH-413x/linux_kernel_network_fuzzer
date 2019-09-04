//
// Created by liuhao on 2019/9/4.
//

#include <netlink/netlink.h>
#include <netlink/cache.h>
#include <netlink/addr.h>
#include <netlink/xfrm/sa.h>
#include <netlink/xfrm/sp.h>
#include <netlink/xfrm/ae.h>
#include <netlink/genl/genl.h>
#include <netlink/cache.h>
#include <netlink/object.h>
#include <netlink/xfrm/selector.h>
#include <netlink/xfrm/lifetime.h>
#include <ctime>
#include <linux/socket.h>
#include <linux/xfrm.h>
#include <namespace.h>
#include <check.h>
#include <log.h>
struct auth_params {
    char *auth_alg_name;
    char *auth_key;
    unsigned int auth_key_len;
    unsigned int auth_trunc_len;
};
struct crypto_params {
    char *crypto_alg_name;
    char *crypto_key;
    unsigned int crypto_key_len;
};
typedef struct{
    int parent_pid;
    int socket;
    //sr_session_ctx_t *session;
} xfrm_register_thread;

struct xfrmnl_ltime_cfg* create_ltime_cfg(unsigned long long soft_bytelimit, unsigned long long hard_bytelimit, unsigned long long soft_packetlimit, unsigned long long hard_packetlimit, unsigned long long soft_addexpires, unsigned long long hard_addexpires, unsigned long long soft_useexpires, unsigned long long hard_useexpires){
    struct xfrmnl_ltime_cfg* ltime_cfg = xfrmnl_ltime_cfg_alloc();
    if (ltime_cfg != NULL) {
        xfrmnl_ltime_cfg_set_soft_bytelimit (ltime_cfg, soft_bytelimit);
        xfrmnl_ltime_cfg_set_hard_bytelimit (ltime_cfg, hard_bytelimit);
        xfrmnl_ltime_cfg_set_soft_packetlimit (ltime_cfg, soft_packetlimit);
        xfrmnl_ltime_cfg_set_hard_packetlimit (ltime_cfg, hard_packetlimit);
        xfrmnl_ltime_cfg_set_soft_addexpires (ltime_cfg, soft_addexpires);
        xfrmnl_ltime_cfg_set_hard_addexpires (ltime_cfg, hard_addexpires);
        xfrmnl_ltime_cfg_set_soft_useexpires (ltime_cfg, soft_useexpires);
        xfrmnl_ltime_cfg_set_hard_useexpires (ltime_cfg, hard_useexpires);
    }
    return ltime_cfg;
}
#define SADB_SATYPE_ESP 1
#define SADB_SATYPE_AH 2
#define IPSEC_MODE_TRANSPORT 3
#define IPSEC_MODE_TUNNEL 4
#define SADB_AALG_MD5HMAC 5
#define SADB_AALG_SHA1HMAC 6
#define SADB_EALG_DESCBC 7
#define SADB_EALG_3DESCBC 8

struct nl_addr* create_nl_addr(char *addr){
    int err=0;
    struct nl_addr *nl_address;
    if ((err = nl_addr_parse(addr, AF_INET, &nl_address)) < 0) {
        fprintf(stderr,"Unable to parse IP address %s\n",addr);
        return nullptr;
    }
    return nl_address;
}

int add_sa(struct nl_addr * src_addr,struct nl_addr * dst_addr, int spi,int mode,int protocol,int replay_window,struct xfrmnl_ltime_cfg* ltime_cfg, struct auth_params *auth, struct crypto_params *crypto){
    int err=0;
    int family = AF_INET;
    int flags = 0;
    struct nl_sock *socket;
    socket = nl_socket_alloc();
    if (0 != nl_connect(socket, NETLINK_XFRM)) {
        fprintf(stderr,"ERROR on nl_connect");
        return -1;
    }
    struct xfrmnl_sa *sa;
    CHECK_UNEXPECT_EQUAL((uint64_t)(sa = xfrmnl_sa_alloc()),(uint64_t)nullptr);
    CHECK_EXPECT_EQUAL((uint64_t)(xfrmnl_sa_set_spi(sa, spi)),0);
    CHECK_EXPECT_EQUAL((uint64_t)(xfrmnl_sa_set_proto (sa, protocol)),0)
    CHECK_EXPECT_EQUAL((uint64_t)(xfrmnl_sa_set_mode(sa, mode)),0);
    CHECK_EXPECT_EQUAL((uint64_t)(xfrmnl_sa_set_daddr (sa, dst_addr)),0);
    CHECK_EXPECT_EQUAL((uint64_t)(xfrmnl_sa_set_saddr (sa, src_addr)),0);
    CHECK_EXPECT_EQUAL((uint64_t)(xfrmnl_sa_set_lifetime_cfg(sa, ltime_cfg)),0);
    CHECK_EXPECT_EQUAL((uint64_t)(xfrmnl_sa_set_family(sa, family)),0);
    CHECK_EXPECT_EQUAL((uint64_t)(xfrmnl_sa_set_replay_window(sa, replay_window)),0);
    CHECK_EXPECT_EQUAL((uint64_t)(xfrmnl_sa_set_flags(sa, flags)),0)

    if (0 != xfrmnl_sa_set_auth_params(sa, auth->auth_alg_name, auth->auth_key_len, auth->auth_trunc_len, auth->auth_key)) {
        fprintf(stderr,"ERROR in  xfrmnl_sa_set_auth_params\n");
        return -1;
    }
    if (protocol != IPPROTO_AH){
        if (0 != xfrmnl_sa_set_crypto_params(sa, crypto->crypto_alg_name, crypto->crypto_key_len,  crypto->crypto_key)) {
            fprintf(stderr,"ERROR in  xfrmnl_sa_set_crypto_params\n");
            return -1;
        }
    }
    err = xfrmnl_sa_add(socket, sa, NLM_F_CREATE);
    if (err < 0) {
        fprintf(stderr,"ERROR in xfrm_sad_add\n");
        return -1;
    }
    xfrmnl_sa_put(sa);
    nl_close(socket);
    return 0;
}

int xfrm_addsad(
        int satype=SADB_SATYPE_ESP,
        int spi=10,
        int sad_node_mode=IPSEC_MODE_TRANSPORT,
        int auth_alg=SADB_AALG_MD5HMAC,
        char encrypt_key[]="01234567",
        int replay=10,
        int encrypt_alg=SADB_EALG_DESCBC
){
    int protocol = 0;
    if (satype == SADB_SATYPE_ESP)
        protocol = IPPROTO_ESP;
    else if (satype == SADB_SATYPE_AH)
        protocol = IPPROTO_AH;
    int mode = -1;
    if (sad_node_mode == IPSEC_MODE_TRANSPORT)
        mode = XFRM_MODE_TRANSPORT;
    else if (sad_node_mode == IPSEC_MODE_TUNNEL)
        mode = XFRM_MODE_TUNNEL;
    else {
        fprintf(stderr,"Error in sad_node->mode");
        return -1;
    }
    int lft_byte_soft=10;
    int lft_byte_hard=10;
    int lft_packet_soft=10;
    int lft_packet_hard=10;
    int lft_soft_add_expires_seconds=10;
    int lft_hard_add_expires_seconds=10;
    int lft_soft_use_expires_seconds=10;
    int lft_hard_use_expires_seconds=10;
    struct xfrmnl_ltime_cfg* ltime_cfg = create_ltime_cfg(
         lft_byte_soft,
         lft_byte_hard,
         lft_packet_soft,
         lft_packet_hard,
         lft_soft_add_expires_seconds,
         lft_hard_add_expires_seconds,
         lft_soft_use_expires_seconds,
         lft_hard_use_expires_seconds
            );
    if (ltime_cfg == NULL) {
        return -1;
    }
    //auth

    struct auth_params *auth = static_cast<auth_params*>(malloc(sizeof(struct auth_params))) ;
    if (auth_alg == SADB_AALG_MD5HMAC)
        auth->auth_alg_name="hmac(md5)";
    else if (auth_alg == SADB_AALG_SHA1HMAC)
        auth->auth_alg_name="hmac(sha1)";
    else {
        fprintf(stderr,"Error in sad_node->auth_alg");
        return -1;
    }
    char auth_key[]="0123456789abc";
    auth->auth_key = auth_key;
    auth->auth_key_len = strlen(auth_key)*8;
    auth->auth_trunc_len = strlen(auth_key)*8;

    //encryption

    auto *crypto = static_cast<crypto_params*>(malloc(sizeof(struct crypto_params)));
    memset(crypto,0,sizeof(crypto_params));
    if(satype == SADB_SATYPE_ESP){
        if (encrypt_alg == SADB_EALG_DESCBC){
            crypto->crypto_alg_name="cbc(des)";
            if (strlen(encrypt_key) != 8){
                fprintf(stderr,"Error el tamaño de clave de encriptacion no es el correcto para el algoritmo 'des' \n El tamaño de la clave tiene que ser de 8 caracteres o 64 bits\n Clave: %s\n",encrypt_key);
                return -1;
            }
            crypto->crypto_key_len = 64;
            crypto->crypto_key = encrypt_key;
        }
        else if (encrypt_alg == SADB_EALG_3DESCBC){
            crypto->crypto_alg_name="cbc(des3_ede)";
            if (strlen(encrypt_key) != 24){
                fprintf(stderr,"Error el tamaño de clave de encriptacion no es el correcto para el algoritmo '3des' \n El tamaño de la clave tiene que ser de 24 caracteres o 192 bits\n Clave: %s\n",encrypt_key);
                return -1;
            }
            crypto->crypto_key_len = 192;
            crypto->crypto_key = encrypt_key;
        }
        else {
            fprintf(stderr,"Error in encrypt_alg");
            //crypto->crypto_alg_name="cbc(aes)";
            return -1;
        }
    }

    char src_tunnel[]="127.0.0.1";
    char dst_tunnel[]="127.0.0.1";
    char src[]="127.0.0.1";
    char dst[]="127.0.0.1";

    if (sad_node_mode == IPSEC_MODE_TUNNEL){
        struct nl_addr * srcaddr = create_nl_addr(src_tunnel);
        if(srcaddr == nullptr){
            return -1;
        }
        struct nl_addr * dstaddr = create_nl_addr(dst_tunnel);
        if(dstaddr == nullptr){
            return -1;
        }
        return add_sa(srcaddr,dstaddr,spi,mode,protocol,replay,ltime_cfg,auth,crypto);
    }
    else if (sad_node_mode == IPSEC_MODE_TRANSPORT){
        struct nl_addr * srcaddr = create_nl_addr(src);
        if(srcaddr == nullptr){
            return -1;
        }
        struct nl_addr * dstaddr = create_nl_addr(dst);
        if(dstaddr == nullptr){
            return -1;
        }
        return add_sa(srcaddr,dstaddr,spi,mode,protocol,replay,ltime_cfg,auth,crypto);
    }
}

int main(){
    enableNamespace();
    xfrm_addsad();
}