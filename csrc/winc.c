
#include "winc.h"

#include "inc/m2m_wifi.h"
#include "src/nmasic.h"
#include "inc/socket.h"
#include "inc/conf_winc.h"

#include "zerynth_sockets.h"

#if defined(ZERYNTH_SSL)
#include "zerynth_ssl.h"
#include "mbedtls/ssl.h"
#endif

// #define printf(...) vbl_printf_stdout(__VA_ARGS__)
#define printf(...)

// volatile int32_t driver_locked = 0;

#define LOCK_DRIVER() do {              \
    /*printf("LOCK@ %i\n",__LINE__);*/      \
    vosSemWait(driver_access_mutex);    \
    /*driver_locked++; */                  \
    /*printf("LOCKED@ %i %i\n",__LINE__,driver_locked);*/      \
} while (0)

#define UNLOCK_DRIVER() do {              \
    /*printf("UNLOCK@ %i\n",__LINE__);*/      \
    vosSemSignal(driver_access_mutex);    \
    /*driver_locked--;     */               \
    /*printf("UNLOCKED@ %i %i\n",__LINE__,driver_locked);*/      \
} while (0)


PObject *drvinfo;
VSemaphore callback_handler_sem;
VSemaphore driver_access_mutex;

#define CB_TYPE_WIFI 0
#define CB_TYPE_SOCK 1
#define CB_TYPE_DNS  2


typedef struct _socket_data {
    uint16_t sock;
    uint8_t taken;
    uint16_t size;
    uint8_t *buffer;
    uint8_t *head;
} SockData;

typedef struct _callback_data {
    VSemaphore sem;
    uint32_t res;
    uint8_t info[4];
    uint8_t type;
    uint8_t available;
} CbData;

#define CB_DATA_LEN 5
#define MAX_SOCKS 4
#define MAX_SOCK_BUF 1596

CbData cb_data[CB_DATA_LEN];
SockData sock_data[MAX_SOCKS];
VSemaphore cb_data_lock;

static inline void cb_data_assign(uint8_t slot, uint8_t cb_type,
                    uint8_t info0, uint8_t info1, uint8_t info2) {
    vosSemWait(cb_data_lock);
    vosSemReset(cb_data[slot].sem);
    cb_data[slot].type = cb_type;
    cb_data[slot].info[0] = info0;
    cb_data[slot].info[1] = info1;
    cb_data[slot].info[2] = info2;
    vosSemSignal(cb_data_lock);
}

static inline uint32_t cb_data_get_res(uint8_t slot) {
    //printf("ENTER GET RES\n");
    vosSemWait(cb_data[slot].sem);

    uint32_t res;
    vosSemWait(cb_data_lock);
    res = cb_data[slot].res;
    cb_data[slot].available = 1;
    vosSemSignal(cb_data_lock);
    //printf("EXIT GET RES\n");
    return res;
}

static inline void cb_data_set_res(uint8_t slot, uint32_t res) {
    //printf("ENTER SET RES\n");
    vosSemWait(cb_data_lock);
    cb_data[slot].res = res;
    vosSemSignal(cb_data_lock);

    vosSemSignal(cb_data[slot].sem);
    //printf("EXIT SET RES\n");
}

void cb_data_init() {
    cb_data_lock = vosSemCreate(1);

    vosSemWait(cb_data_lock);
    uint8_t i;
    for (i = 0; i < CB_DATA_LEN; i++) {
        cb_data[i].available = 1;
        cb_data[i].sem = vosSemCreate(0);
    }
    vosSemSignal(cb_data_lock);
}

void sock_data_init() {

    uint8_t i;
    for (i = 0; i < MAX_SOCKS; i++) {
        sock_data[i].taken = 0;
        sock_data[i].buffer = NULL;
        sock_data[i].size = 0;
        //sock_data[i].sem = vosSemCreate(1);
    }
}

SockData *take_sock_data(int sock){
    int i;
    for(i=0;i<MAX_SOCKS;i++){
        if (!sock_data[i].taken) {
            sock_data[i].taken = 1;
            sock_data[i].sock = sock;
            if(!sock_data[i].buffer) {
                sock_data[i].buffer = gc_malloc(MAX_SOCK_BUF);
                sock_data[i].size = 0;
            }
            return &sock_data[i];
        }
    }
    return NULL;
}

void give_sock_data(SockData *sd){
    sd->taken = 0;
}



SockData *get_sock_data(int sock){
    int i;
    for(i=0;i<MAX_SOCKS;i++){
        if (sock_data[i].taken && sock_data[i].sock == sock) {
            return &sock_data[i];
        }
    }
    return NULL;
}

uint8_t cb_data_get_slot() {
    uint8_t i;
    uint8_t res = CB_DATA_LEN;

    vosSemWait(cb_data_lock);

    for (i = 0; i < CB_DATA_LEN; i++) {
        if (cb_data[i].available) {
            cb_data[i].available = 0;
            res = i;
            break;
        }
    }
    vosSemSignal(cb_data_lock);

    return res;
}

uint8_t cb_data_find_slot(uint8_t type, uint8_t info_len, uint8_t *info) {
    uint8_t i, j;
    uint8_t res = CB_DATA_LEN;

    //printf("WAIT DATA SLOT\n");
    vosSemWait(cb_data_lock);

    for (i = 0; i < CB_DATA_LEN; i++) {
        if (!cb_data[i].available) {
            if (type != cb_data[i].type) {
                continue;
            }

            uint8_t ok_info = 1;
            for (j = 0; j < info_len; j++) {
                    if (cb_data[i].info[j] != info[j]) {
                        ok_info = 0;
                        break;
                    }
            }
            if (!ok_info) {
                continue;
            }

            res = i;
            break;
        }
    }

    vosSemSignal(cb_data_lock);
    //printf("EXIT WAIT DATA SLOT %i\n",res);

    return res;
}

void cb_data_force_free(uint8_t cb_type, uint8_t info0, uint8_t info1) {

    uint8_t info[] = { info0, info1 };
    uint8_t slot = cb_data_find_slot(cb_type, 2, info);
    if (slot != CB_DATA_LEN) {
        // unlock suspended call
        cb_data_set_res(slot, -123);
    }

}


// wifi

static uint8_t wifi_connected;

static void wifi_cb(uint8_t u8MsgType, void *pvMsg) {
	switch (u8MsgType) {

    case M2M_WIFI_RESP_SCAN_DONE:
	{
		tstrM2mScanDone *pstrInfo = (tstrM2mScanDone *)pvMsg;

        uint8_t info[] = { M2M_WIFI_RESP_SCAN_DONE };
        uint8_t slot = cb_data_find_slot(CB_TYPE_WIFI, 1, info);

        if (slot != CB_DATA_LEN) {
            cb_data_set_res(slot, pstrInfo->u8NumofCh);
        }
		break;
	}

	case M2M_WIFI_RESP_SCAN_RESULT:
	{

        uint8_t info[] = { M2M_WIFI_RESP_SCAN_RESULT };
        uint8_t slot = cb_data_find_slot(CB_TYPE_WIFI, 1, info);

        if (slot != CB_DATA_LEN) {
            tstrM2mWifiscanResult *pstrScanResult = (tstrM2mWifiscanResult *)pvMsg;
            vosSemWait(cb_data_lock);
            PObject *sr = (PObject* ) cb_data[slot].res;
            vosSemSignal(cb_data_lock);

            PTUPLE_SET_ITEM(sr, 0, (PObject* ) pstring_new(strlen(pstrScanResult->au8SSID), pstrScanResult->au8SSID));
            PTUPLE_SET_ITEM(sr, 1, (PObject* ) PSMALLINT_NEW(pstrScanResult->u8AuthType - 1));
            PTUPLE_SET_ITEM(sr, 2, (PObject* ) PSMALLINT_NEW(pstrScanResult->s8rssi));
            PTUPLE_SET_ITEM(sr, 3, (PObject* ) pbytes_new(6, pstrScanResult->au8BSSID));

            vosSemSignal(cb_data[slot].sem);
        }
		break;
	}

	case M2M_WIFI_RESP_CON_STATE_CHANGED:
	{
        tstrM2mWifiStateChanged *pstrWifiState = (tstrM2mWifiStateChanged *)pvMsg;
        uint8_t info[] = { M2M_WIFI_RESP_CON_STATE_CHANGED };
        uint8_t slot = cb_data_find_slot(CB_TYPE_WIFI, 1, info);

        if (slot != CB_DATA_LEN) {

            if (pstrWifiState->u8CurrState == M2M_WIFI_CONNECTED) {
                printf("wifi_cb: M2M_WIFI_RESP_CON_STATE_CHANGED: CONNECTED\r\n");

                vosSemWait(cb_data_lock);
                cb_data[slot].info[0] = M2M_WIFI_REQ_DHCP_CONF;
                vosSemSignal(cb_data_lock);

                // legacy, automatically executed
                // m2m_wifi_request_dhcp_client();

            } else if (pstrWifiState->u8CurrState == M2M_WIFI_DISCONNECTED) {
                cb_data_set_res(slot, 0);
            }

        }
        else {
            if (pstrWifiState->u8CurrState == M2M_WIFI_DISCONNECTED) {
                wifi_connected = 0;
            }
        }

		break;
	}

	case M2M_WIFI_REQ_DHCP_CONF:
	{

		uint8_t *pu8IPAddress = (uint8_t *)pvMsg;

		printf("wifi_cb: M2M_WIFI_REQ_DHCP_CONF: IP is %u.%u.%u.%u\r\n",
				pu8IPAddress[0], pu8IPAddress[1], pu8IPAddress[2], pu8IPAddress[3]);

        uint8_t info[] = { M2M_WIFI_REQ_DHCP_CONF };
        uint8_t slot = cb_data_find_slot(CB_TYPE_WIFI, 1, info);
        if (slot != CB_DATA_LEN) {
            cb_data_set_res(slot, 1);
        }
		break;
	}

    case M2M_WIFI_RESP_CONN_INFO:
	{

        uint8_t info[] = { M2M_WIFI_RESP_CONN_INFO };
        uint8_t slot = cb_data_find_slot(CB_TYPE_WIFI, 1, info);

        if (slot != CB_DATA_LEN) {
            tstrM2MConnInfo *pstrConnInfo = (tstrM2MConnInfo *)pvMsg;
            vosSemWait(cb_data_lock);
            PObject *ir = (PObject* ) cb_data[slot].res;
            vosSemSignal(cb_data_lock);

            PTUPLE_SET_ITEM(ir, 0, (PObject* ) pbytes_new(4, pstrConnInfo->au8IPAddr));
            PTUPLE_SET_ITEM(ir, 1, (PObject* ) pstring_new(1,"."));
            PTUPLE_SET_ITEM(ir, 2, (PObject* ) pstring_new(1,"."));
            PTUPLE_SET_ITEM(ir, 3, (PObject* ) pstring_new(1,"."));
            PTUPLE_SET_ITEM(ir, 4, (PObject* ) pbytes_new(6, pstrConnInfo->au8MACAddress));

            vosSemSignal(cb_data[slot].sem);
        }
		break;
	}

	default:
	{
		break;
	}
	}
}

C_NATIVE(winc_wifi_link) {
    NATIVE_UNWARN();

    uint8_t slot = cb_data_get_slot();
    if (slot == CB_DATA_LEN) {
        // no more slots available
        return ERR_VALUE_EXC;
    }

    uint8_t *ssid = PSEQUENCE_BYTES(args[0]);
    uint8_t sec;
    switch (PSMALLINT_VALUE(args[1])) {
        case 1:
            sec = M2M_WIFI_SEC_WEP;
            break;
        case 2:
        case 3:
            sec = M2M_WIFI_SEC_WPA_PSK;
            break;
        default:
            sec = M2M_WIFI_SEC_OPEN;
            break;
    }
    uint8_t *psw = PSEQUENCE_BYTES(args[2]);

    wifi_connected = 0;

    pdict_put(drvinfo, pstring_new(4, (uint8_t *)"ssid"), args[0]);
    pdict_put(drvinfo, pstring_new(3, (uint8_t *)"psw"), args[2]);
    pdict_put(drvinfo, pstring_new(3, (uint8_t *)"sec"), PSMALLINT_NEW(sec));

    cb_data_assign(slot, CB_TYPE_WIFI, M2M_WIFI_RESP_CON_STATE_CHANGED, 0, 0);

    RELEASE_GIL();
    LOCK_DRIVER();
    m2m_wifi_connect(ssid, PSEQUENCE_ELEMENTS(args[0]), sec, psw, M2M_WIFI_CH_ALL);
    UNLOCK_DRIVER();

    wifi_connected = cb_data_get_res(slot);
    ACQUIRE_GIL();

    if (!wifi_connected) {
        return ERR_CONNECTION_REF_EXC;
    }

    return ERR_OK;
}

C_NATIVE(winc_wifi_unlink) {
    NATIVE_UNWARN();

    uint8_t slot = cb_data_get_slot();
    if (slot == CB_DATA_LEN) {
        // no more slots available
        return ERR_VALUE_EXC;
    }

    cb_data_assign(slot, CB_TYPE_WIFI, M2M_WIFI_RESP_CON_STATE_CHANGED, 0, 0);

    RELEASE_GIL();
    LOCK_DRIVER();
    m2m_wifi_disconnect();
    UNLOCK_DRIVER();

    wifi_connected = cb_data_get_res(slot);
    ACQUIRE_GIL();

    return ERR_OK;
}

C_NATIVE(winc_wifi_is_linked) {
    NATIVE_UNWARN();

    *res = (wifi_connected ? PBOOL_TRUE() : PBOOL_FALSE());

    return ERR_OK;
}

void dns_resolve_callback(uint8* pu8HostName, uint32 hostIp) {
    // not multithreaded...
    uint8_t slot = cb_data_find_slot(CB_TYPE_DNS, 0, NULL);
    cb_data_set_res(slot, hostIp);

}

C_NATIVE(winc_wifi_gethostbyname) {
    NATIVE_UNWARN();
    NetAddress addr;
    uint32_t ip_addr;

    socketInit();

    uint8_t slot = cb_data_get_slot();
    if (slot == CB_DATA_LEN) {
        // no more slots available
        return ERR_VALUE_EXC;
    }

    cb_data_assign(slot, CB_TYPE_DNS, 0, 0, 0);

    RELEASE_GIL();
    uint8_t *hostname = PSEQUENCE_BYTES(args[0]);

    LOCK_DRIVER();
    gethostbyname(hostname);
    UNLOCK_DRIVER();


    ip_addr = cb_data_get_res(slot);
    ACQUIRE_GIL();

    addr.port= 0;
    addr.ip = ip_addr;


    *res = netaddress_to_object(&addr);

    return ERR_OK;
}

C_NATIVE(winc_wifi_scan) {
    NATIVE_UNWARN();

    uint8_t slot = cb_data_get_slot();
    if (slot == CB_DATA_LEN) {
        // no more slots available
        return ERR_VALUE_EXC;
    }

    uint32_t num_ap;

    cb_data_assign(slot, CB_TYPE_WIFI, M2M_WIFI_RESP_SCAN_DONE, 0, 0);

    RELEASE_GIL();

    LOCK_DRIVER();
    m2m_wifi_request_scan(M2M_WIFI_CH_ALL);
    UNLOCK_DRIVER();


    num_ap = cb_data_get_res(slot);
    ACQUIRE_GIL();

    *res = ptuple_new(num_ap, NULL);

    uint32 i;
    for (i = 0; i < num_ap; i++) {
        uint8_t slot = cb_data_get_slot();
        if (slot == CB_DATA_LEN) {
            // no more slots available
            return ERR_VALUE_EXC;
        }

        PObject *scan_res = ptuple_new(4, NULL);

        cb_data_assign(slot, CB_TYPE_WIFI, M2M_WIFI_RESP_SCAN_RESULT, 0, 0);

        vosSemWait(cb_data_lock);
        cb_data[slot].res = (uint32_t) scan_res;
        vosSemSignal(cb_data_lock);

        RELEASE_GIL();

        LOCK_DRIVER();
        m2m_wifi_req_scan_result(i);
        UNLOCK_DRIVER();

        cb_data_get_res(slot);

        ACQUIRE_GIL();

        PTUPLE_SET_ITEM(*res, i, scan_res);
    }

    return ERR_OK;
}

C_NATIVE(winc_wifi_link_info) {
    NATIVE_UNWARN();

    uint8_t slot = cb_data_get_slot();
    if (slot == CB_DATA_LEN) {
        // no more slots available
        return ERR_VALUE_EXC;
    }

    uint32_t num_ap;

    cb_data_assign(slot, CB_TYPE_WIFI, M2M_WIFI_RESP_CONN_INFO, 0, 0);

    *res = ptuple_new(5, NULL);

    vosSemWait(cb_data_lock);
    cb_data[slot].res = (uint32_t) *res;
    vosSemSignal(cb_data_lock);

    RELEASE_GIL();

    LOCK_DRIVER();
    m2m_wifi_get_connection_info();
    UNLOCK_DRIVER();

    cb_data_get_res(slot);
    ACQUIRE_GIL();

    return ERR_OK;
}

// socket

typedef struct _sock_accepted {
    NetAddress netaddr;
    uint8_t sock_id;
    uint8_t error;
} SockAccepted;

uint32_t sock_timeout[MAX_SOCKET];

/*
 *  pvMsg is a pointer to message structure. Existing types are:
 */
static void socket_cb(SOCKET sock, uint8_t u8Msg, void *pvMsg)
{
    printf("SOCKET CB %i %i %x\n",sock,u8Msg,pvMsg);
	switch (u8Msg) {
	/* Socket connected */
	case SOCKET_MSG_CONNECT:
	{
        uint8_t info[] = { SOCKET_MSG_CONNECT, sock };
        uint8_t slot = cb_data_find_slot(CB_TYPE_SOCK, 2, info);
        if (slot != CB_DATA_LEN) {
    		tstrSocketConnectMsg *pstrConnect = (tstrSocketConnectMsg *)pvMsg;
    		if (pstrConnect && pstrConnect->s8Error >= 0) {

                cb_data_set_res(slot, 1);
                printf("socket_cb: connect success!\r\n");

            } else {
                printf("socket_cb: connect error! %i\r\n", pstrConnect->s8Error);
                cb_data_set_res(slot, 0);
            }
        }
    }
    break;

	/* Message send */
    case SOCKET_MSG_SEND:
    {
        uint8_t info[] = { SOCKET_MSG_SEND, sock };
        uint8_t slot = cb_data_find_slot(CB_TYPE_SOCK, 2, info);
        if (slot != CB_DATA_LEN) {
            sint16 *sent = (sint16 *)pvMsg;
            // if (*sent > 0) {
            cb_data_set_res(slot, *sent);
            // }
            // else {
            //     cb_data_set_res(slot, 0);
            // }
            printf("socket_cb: send result %i\r\n", *sent);
        }
	}
	break;

	/* Message receive */
	case SOCKET_MSG_RECV:
	{
        //printf("SOCK!\n");
        tstrSocketRecvMsg *pstrRecv = (tstrSocketRecvMsg *)pvMsg;
        printf("RR %i/%i\n",pstrRecv->s16BufferSize,pstrRecv->u16RemainingSize);

        //printf("SOCK_RECV %i\n",pstrRecv->s16BufferSize);
        uint8_t info[] = { SOCKET_MSG_RECV, sock };
        uint8_t slot = cb_data_find_slot(CB_TYPE_SOCK, 2, info);
        if (slot != CB_DATA_LEN) {
            SockData *sd = get_sock_data(cb_data[slot].info[3]);
            printf("SD RECV %x %i",sd,cb_data[slot].info[3]);
            if (sd) {
                if (pstrRecv->s16BufferSize > 0) {
                    sd->size = pstrRecv->s16BufferSize;
                }
                else {
                    // timeout or error occurred
                    sd->size = 0;
                }
            }
            cb_data_set_res(slot, pstrRecv->s16BufferSize);
        }
    }
    break;

    case SOCKET_MSG_BIND:
    {
        uint8_t info[] = { SOCKET_MSG_BIND, sock };
        uint8_t slot = cb_data_find_slot(CB_TYPE_SOCK, 2, info);
        if (slot != CB_DATA_LEN) {
    		tstrSocketBindMsg *pstrBind = (tstrSocketBindMsg *)pvMsg;
    		if (pstrBind && pstrBind->status >= 0) {

                cb_data_set_res(slot, 1);
                printf("socket_cb: bind success!\r\n");

            } else {
                printf("socket_cb: bind error!\r\n");
                cb_data_set_res(slot, 0);
            }
        }
    }
    break;

    case SOCKET_MSG_LISTEN:
    {
        uint8_t info[] = { SOCKET_MSG_LISTEN, sock };
        uint8_t slot = cb_data_find_slot(CB_TYPE_SOCK, 2, info);
        if (slot != CB_DATA_LEN) {
    		tstrSocketListenMsg *pstrListen = (tstrSocketListenMsg *)pvMsg;
    		if (pstrListen && pstrListen->status >= 0) {

                cb_data_set_res(slot, 1);
                printf("socket_cb: listen success!\r\n");

            } else {
                printf("socket_cb: listen error!\r\n");
                cb_data_set_res(slot, 0);
            }
        }
    }
    break;

    case SOCKET_MSG_ACCEPT:
    {
        uint8_t info[] = { SOCKET_MSG_ACCEPT, sock };
        uint8_t slot = cb_data_find_slot(CB_TYPE_SOCK, 2, info);
        if (slot != CB_DATA_LEN) {
            vosSemWait(cb_data_lock);
            PObject *sock_addr = (PObject* ) cb_data[slot].res;
            vosSemSignal(cb_data_lock);

    		tstrSocketAcceptMsg *pstrAccept = (tstrSocketAcceptMsg *)pvMsg;
    		if (pstrAccept->sock >= 0) {

                PTUPLE_SET_ITEM(sock_addr, 0, (PObject* ) PSMALLINT_NEW(pstrAccept->sock));
                NetAddress netaddr;
                netaddr.port = _ntohs(pstrAccept->strAddr.sin_port);
                netaddr.ip   = _ntohl(pstrAccept->strAddr.sin_addr.s_addr);
                PTUPLE_SET_ITEM(sock_addr, 1, (PObject* ) netaddress_to_object(&netaddr));

                printf("socket_cb: accept success!\r\n");

            } else {
                printf("socket_cb: accept error!\r\n");
                // sock_acc->error = 1;
                PTUPLE_SET_ITEM(sock_addr, 0, (PObject* ) PSMALLINT_NEW(-1));
            }
            vosSemSignal(cb_data[slot].sem);
        }
    }
    break;


    case SOCKET_MSG_RECVFROM:
	{
        uint8_t info[] = { SOCKET_MSG_RECVFROM, sock };
        uint8_t slot = cb_data_find_slot(CB_TYPE_SOCK, 2, info);
        if (slot != CB_DATA_LEN) {
            vosSemWait(cb_data_lock);
            PObject *rd_addr = (PObject* ) cb_data[slot].res;
            vosSemSignal(cb_data_lock);
    		tstrSocketRecvMsg *pstrRecv = (tstrSocketRecvMsg *)pvMsg;
            PTUPLE_SET_ITEM(rd_addr, 0, (PObject* ) PSMALLINT_NEW(pstrRecv->s16BufferSize));
    		if (pstrRecv && pstrRecv->s16BufferSize > 0) {
                NetAddress netaddr;
                netaddr.port = _ntohs(pstrRecv->strRemoteAddr.sin_port);
                netaddr.ip   = _ntohl(pstrRecv->strRemoteAddr.sin_addr.s_addr);
                PTUPLE_SET_ITEM(rd_addr, 1, (PObject* ) netaddress_to_object(&netaddr));

    			printf("socket_cb: recvfrom success!\r\n");
    		} else {
    			printf("socket_cb: recvfrom error!\r\n");
    		}
            vosSemSignal(cb_data[slot].sem);
        }
	}
	break;

    case SOCKET_MSG_SENDTO:
    {
        uint8_t info[] = { SOCKET_MSG_SENDTO, sock };
        uint8_t slot = cb_data_find_slot(CB_TYPE_SOCK, 2, info);
        if (slot != CB_DATA_LEN) {
            sint16 *sent = (sint16 *)pvMsg;
            if (*sent > 0) {
                cb_data_set_res(slot, (uint16_t) *sent);
            }
            else {
                cb_data_set_res(slot, 0);
            }
            printf("socket_cb: sendto success!\r\n");
        }
	}
	break;

	default:
		break;
	}
    //printf("EXIT SOCK!\n");
}

C_NATIVE(winc_socket_socket) {
    NATIVE_UNWARN();

    uint32_t family = PSMALLINT_VALUE(args[0]);
    uint32_t type = PSMALLINT_VALUE(args[1]);

    if (family != 0 || type > 3) {
        return ERR_UNSUPPORTED_EXC;
    }

    RELEASE_GIL();
    int32_t sock_id = gzsock_socket(
          AF_INET,
          type + 1,
          IPPROTO_TCP,
          NULL);
    ACQUIRE_GIL();

    if (sock_id < 0) {
        return ERR_IOERROR_EXC;
    }

    *res = PSMALLINT_NEW(sock_id);

    return ERR_OK;
}

#define DRV_SOCK_DGRAM 1
#define DRV_SOCK_STREAM 0
#define DRV_AF_INET 0

C_NATIVE(winc_secure_socket) {
    C_NATIVE_UNWARN();

#if defined(ZERYNTH_SSL)
    int32_t err = ERR_OK;
    int32_t sock;
    int32_t i;
    SSLInfo nfo;

    int32_t ssocknum = 0;
    int32_t ctxlen;
    uint8_t* certbuf = NULL;
    uint16_t certlen = 0;
    uint8_t* clibuf = NULL;
    uint16_t clilen = 0;
    uint8_t* pkeybuf = NULL;
    uint16_t pkeylen = 0;
    uint32_t options = _CLIENT_AUTH | _CERT_NONE;
    uint8_t* hostbuf = NULL;
    uint16_t hostlen = 0;

    PTuple* ctx;
    memset(&nfo,0,sizeof(nfo));
    ctx = (PTuple*)args[nargs - 1];
    nargs--;
    // if (parse_py_args("III", nargs, args, DRV_AF_INET, &family, DRV_SOCK_STREAM, &type, IPPROTO_TCP, &proto) != 3){
    //     printf("G\n");
    //     return ERR_TYPE_EXC;
    // }

    uint32_t family = PSMALLINT_VALUE(args[0]);
    uint32_t type = PSMALLINT_VALUE(args[1]);

    if (family != 0 || type > 3) {
        return ERR_UNSUPPORTED_EXC;
    }

    // if (type != DRV_SOCK_DGRAM && type != DRV_SOCK_STREAM){
    //     printf("GG\n");
    //     return ERR_TYPE_EXC;
    // }
    // if (family != DRV_AF_INET)
    //     return ERR_UNSUPPORTED_EXC;

    ctxlen = PSEQUENCE_ELEMENTS(ctx);
    if (ctxlen && ctxlen != 5)
        return ERR_TYPE_EXC;

    if (ctxlen) {
        //ssl context passed
        PObject* cacert = PTUPLE_ITEM(ctx, 0);
        PObject* clicert = PTUPLE_ITEM(ctx, 1);
        PObject* ppkey = PTUPLE_ITEM(ctx, 2);
        PObject* host = PTUPLE_ITEM(ctx, 3);
        PObject* iopts = PTUPLE_ITEM(ctx, 4);

        nfo.cacert = PSEQUENCE_BYTES(cacert);
        nfo.cacert_len = PSEQUENCE_ELEMENTS(cacert);
        nfo.clicert = PSEQUENCE_BYTES(clicert);
        nfo.clicert_len = PSEQUENCE_ELEMENTS(clicert);
        nfo.hostname = PSEQUENCE_BYTES(host);
        nfo.hostname_len = PSEQUENCE_ELEMENTS(host);
        nfo.pvkey = PSEQUENCE_BYTES(ppkey);
        nfo.pvkey_len = PSEQUENCE_ELEMENTS(ppkey);
        nfo.options = PSMALLINT_VALUE(iopts);
    }

    RELEASE_GIL();
    printf("%x\n",gzsock_socket);
    sock = gzsock_socket(
          AF_INET,
          type + 1, // zerynth sockets type differ from winc sockets type by one
          IPPROTO_TCP,
          (ctxlen) ? &nfo:NULL);
  ACQUIRE_GIL();
  printf("CMD_SOCKET: %i %i\n", sock, errno);
  if (sock < 0)
    return ERR_IOERROR_EXC;
  *res = PSMALLINT_NEW(sock);
  return ERR_OK;

#else 

    NATIVE_UNWARN();

    socketInit();

    // m2m_ssl_set_active_ciphersuites(SSL_NON_ECC_CIPHERS_AES_128 | SSL_NON_ECC_CIPHERS_AES_256);
    // m2m_ssl_set_active_ciphersuites(SSL_ECC_ALL_CIPHERS);

    LOCK_DRIVER();
    int sock_id = socket(AF_INET, SOCK_STREAM, SOCKET_FLAGS_SSL);
    UNLOCK_DRIVER();

    if (sock_id < 0) {
        return ERR_IOERROR_EXC;
    }

    SockData *sd = take_sock_data(sock_id);
    if(!sd) {
        return ERR_VALUE_EXC;
    }

    sock_timeout[(uint32_t) sock_id] = 0;

    *res = PSMALLINT_NEW(sock_id);

    return ERR_OK;

#endif
}

C_NATIVE(winc_socket_connect) {
    NATIVE_UNWARN();
    int32_t sock_id;
    NetAddress netaddr;

    if (parse_py_args("in", nargs, args, &sock_id, &netaddr) != 2)
        return ERR_TYPE_EXC;

    struct sockaddr_in addr;
    int ret;

    addr.sin_family = AF_INET;
	addr.sin_port = netaddr.port;
    addr.sin_addr.s_addr = netaddr.ip;

    printf("CONNECT TO %x %x\n",addr.sin_port,addr.sin_addr.s_addr);
    printf("WITH %i\n",sock_id);

    RELEASE_GIL();
    ret = gzsock_connect(sock_id, &addr, sizeof(addr));
    ACQUIRE_GIL();

    if (ret < 0) {
        return ERR_CONNECTION_REF_EXC;
    }

    return ERR_OK;
}

C_NATIVE(winc_socket_send) {
    NATIVE_UNWARN();

    socketInit();

    uint32_t sock_id = PSMALLINT_VALUE(args[0]);
    int ret;

    uint8_t *to_send = PSEQUENCE_BYTES(args[1]);
    uint16_t len = PSEQUENCE_ELEMENTS(args[1]);

    RELEASE_GIL();
    ret = gzsock_send(sock_id, to_send, len, 0);
    ACQUIRE_GIL();

    if (ret == SOCK_ERR_CONN_ABORTED || ret == SOCK_ERR_INVALID || ret == -123) {
        return ERR_CONNECTION_ABR_EXC;
    }

    *res = PSMALLINT_NEW((uint32_t) (ret > 0) ? ret : 0);

    return ERR_OK;
}

C_NATIVE(winc_socket_sendall) {
    NATIVE_UNWARN();

    socketInit();

    uint32_t sock_id = PSMALLINT_VALUE(args[0]);
    int ret;

    uint8_t *to_send = PSEQUENCE_BYTES(args[1]);
    uint16_t len = PSEQUENCE_ELEMENTS(args[1]);

    RELEASE_GIL();
    ret = gzsock_send(sock_id, to_send, len, 0);
    ACQUIRE_GIL();

    if (ret == SOCK_ERR_CONN_ABORTED || ret == SOCK_ERR_INVALID || ret == -123) {
        return ERR_CONNECTION_ABR_EXC;
    }
    if (ret != len) {
        return ERR_IOERROR_EXC;
    }

    return ERR_OK;
}

C_NATIVE(winc_socket_recv_into) {
    NATIVE_UNWARN();

    uint8_t *buf;
    int32_t len;
    int32_t sz;
    int32_t flags;
    int32_t ofs;
    int32_t sock_id;
    if (parse_py_args("isiiI", nargs, args,
                    &sock_id,
                    &buf, &len,
                    &sz,
                    &flags,
                    0,
                    &ofs
                   ) != 5) return ERR_TYPE_EXC;

    buf += ofs;
    len -= ofs;
    len = (sz < len) ? sz : len;
    sz = len;

    printf("RECV %i %i %x %i\n",sock_id,len,buf,ofs);

    sint16 ret=0;
    RELEASE_GIL();
    ret = gzsock_recv(sock_id, buf, len, flags);
    ACQUIRE_GIL();

    if (ret < 0) {
        if (ret == SOCK_ERR_TIMEOUT) {
            return ERR_TIMEOUT_EXC;
        }
#if defined(ZERYNTH_SSL)
        else if (ret == MBEDTLS_ERR_SSL_TIMEOUT) {
            return ERR_TIMEOUT_EXC;
        }
#endif
        else if (ret==-1234) {
            return ERR_VALUE_EXC;
        }
        else if (ret != SOCK_ERR_CONN_ABORTED) {
            return ERR_IOERROR_EXC;
        }
    }

    *res = PSMALLINT_NEW((uint32_t) sz);

    return ERR_OK;
}




C_NATIVE(winc_socket_bind) {
    NATIVE_UNWARN();

    socketInit();

    NetAddress netaddr;
    uint32_t sock_id;

    if (parse_py_args("in", nargs, args, &sock_id, &netaddr) != 2)
        return ERR_TYPE_EXC;

    uint8_t slot = cb_data_get_slot();
    if (slot == CB_DATA_LEN) {
        // no more slots available
        return ERR_VALUE_EXC;
    }


    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = netaddr.port;
    addr.sin_addr.s_addr = netaddr.ip;

    cb_data_assign(slot, CB_TYPE_SOCK, SOCKET_MSG_BIND, sock_id, 0);

    RELEASE_GIL();

    LOCK_DRIVER();
    bind(sock_id, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
    UNLOCK_DRIVER();

    uint32_t ret = cb_data_get_res(slot);
    ACQUIRE_GIL();
    if (!ret) {
        return ERR_IOERROR_EXC;
    }

    return ERR_OK;
}

C_NATIVE(winc_socket_listen) {
    NATIVE_UNWARN();

    socketInit();

    uint8_t slot = cb_data_get_slot();
    if (slot == CB_DATA_LEN) {
        // no more slots available
        return ERR_VALUE_EXC;
    }

    uint32_t sock_id = PSMALLINT_VALUE(args[0]);

    cb_data_assign(slot, CB_TYPE_SOCK, SOCKET_MSG_LISTEN, sock_id, 0);

    RELEASE_GIL();

    LOCK_DRIVER();
    listen(sock_id, 0);
    UNLOCK_DRIVER();

    uint32_t ret = cb_data_get_res(slot);
    ACQUIRE_GIL();
    if (!ret) {
        return ERR_IOERROR_EXC;
    }

    return ERR_OK;
}

C_NATIVE(winc_socket_accept) {
    NATIVE_UNWARN();

    socketInit();

    uint8_t slot = cb_data_get_slot();
    if (slot == CB_DATA_LEN) {
        // no more slots available
        return ERR_VALUE_EXC;
    }

    uint32_t sock_id = PSMALLINT_VALUE(args[0]);

    cb_data_assign(slot, CB_TYPE_SOCK, SOCKET_MSG_ACCEPT, sock_id, 0);

    // rd_addr
    *res = ptuple_new(2, NULL);

    vosSemWait(cb_data_lock);
    cb_data[slot].res = (uint32_t) *res;
    vosSemSignal(cb_data_lock);

    RELEASE_GIL();

    cb_data_get_res(slot);
    ACQUIRE_GIL();

    int acc_sock_id = PSMALLINT_VALUE(PTUPLE_ITEM(*res, 0));
    if (acc_sock_id < 0) {
        return ERR_IOERROR_EXC;
    }

    SockData *sd = take_sock_data(acc_sock_id);
    if(!sd) {
        return ERR_VALUE_EXC;
    }
    sock_timeout[acc_sock_id] = 0;

    return ERR_OK;
}

C_NATIVE(winc_socket_sendto) {
    NATIVE_UNWARN();

    socketInit();

    uint8_t slot = cb_data_get_slot();
    if (slot == CB_DATA_LEN) {
        // no more slots available
        return ERR_VALUE_EXC;
    }

    uint32_t sock_id;
    uint8_t *to_send = NULL;
    uint32_t len;
    NetAddress netaddr;

    // ignore flags
    nargs--;

    if (parse_py_args("isn", nargs, args, &sock_id, &to_send, &len, &netaddr) != 3)
        return ERR_TYPE_EXC;

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
	// addr.sin_port = _htons(PSMALLINT_VALUE(args[3]));
    // addr.sin_addr.s_addr = _htonl((uint32_t) PSMALLINT_VALUE(args[2]));
    addr.sin_port = netaddr.port;
    addr.sin_addr.s_addr = netaddr.ip;

    cb_data_assign(slot, CB_TYPE_SOCK, SOCKET_MSG_SENDTO, sock_id, 0);

    RELEASE_GIL();

    LOCK_DRIVER();
    sendto(sock_id, to_send, len, 0, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
    UNLOCK_DRIVER();

    uint32_t ret = cb_data_get_res(slot);
    ACQUIRE_GIL();

    *res = PSMALLINT_NEW(ret);

    return ERR_OK;
}

C_NATIVE(winc_socket_close) {
    NATIVE_UNWARN();

    uint32_t sock_id = PSMALLINT_VALUE(args[0]);

    LOCK_DRIVER();
    wincsock_close(sock_id);
    UNLOCK_DRIVER();

    SockData *sd = get_sock_data(sock_id);
    if(sd) give_sock_data(sd);

    return ERR_OK;
}

C_NATIVE(winc_socket_recvfrom_into) {
    NATIVE_UNWARN();

    socketInit();

    uint8_t slot = cb_data_get_slot();
    if (slot == CB_DATA_LEN) {
        // no more slots available
        return ERR_VALUE_EXC;
    }

    uint32_t sock_id = PSMALLINT_VALUE(args[0]);
    uint8_t *buf = PSEQUENCE_BYTES(args[1]);
    uint16_t len = PSEQUENCE_ELEMENTS(args[1]);

    cb_data_assign(slot, CB_TYPE_SOCK, SOCKET_MSG_RECVFROM, sock_id, 0);

    // rd_addr
    *res = ptuple_new(2, NULL);

    vosSemWait(cb_data_lock);
    cb_data[slot].res = (uint32_t) *res;
    vosSemSignal(cb_data_lock);

    RELEASE_GIL();

    LOCK_DRIVER();
    recvfrom(sock_id, buf, len, sock_timeout[sock_id]);
    UNLOCK_DRIVER();

    cb_data_get_res(slot);
    ACQUIRE_GIL();

    int buf_size = PSMALLINT_VALUE(PTUPLE_ITEM(*res, 0));
    if (buf_size < 0) {
        if (buf_size == SOCK_ERR_TIMEOUT) {
            return ERR_TIMEOUT_EXC;
        }
        return ERR_IOERROR_EXC;
    }

    return ERR_OK;
}

#define ZER_SO_RCVTIMEO 1

C_NATIVE(winc_socket_setsockopt) {
    NATIVE_UNWARN();

    socketInit();

    uint32_t sock_id = PSMALLINT_VALUE(args[0]);
    uint32_t opt = PSMALLINT_VALUE(args[2]);

    // SO_RCVTIMEO
    if (opt != ZER_SO_RCVTIMEO) {
        return ERR_UNSUPPORTED_EXC;
    }

    if (PTYPE(args[3]) != PNONE) {
        uint32_t val = PSMALLINT_VALUE(args[3]);

        if (val == 0) {
            return ERR_UNSUPPORTED_EXC;
        }

        struct timeval tms;
        tms.tv_sec = val / 1000;
        tms.tv_usec = (val % 1000) * 1000;

        RELEASE_GIL();
        gzsock_setsockopt(sock_id, SOL_SOCKET, SO_RCVTIMEO, &tms, sizeof(struct timeval));
        ACQUIRE_GIL();
    }

    return ERR_OK;
}

// misc

void winc_callback_handler(void *data) {
    while (1) {
        vosSemWait(callback_handler_sem);

        LOCK_DRIVER();
        printf("M2M\n");
        m2m_wifi_handle_events(NULL);
        printf("M2M RET\n");
        UNLOCK_DRIVER();
    }
}

C_NATIVE(__get_chipid) {
    NATIVE_UNWARN();

	/* Display WINC1500 chip information. */
	printf("Chip ID : \r\t\t\t%x\r\n", (unsigned int)nmi_get_chipid());
	printf("RF Revision ID : \r\t\t\t%x\r\n", (unsigned int)nmi_get_rfrevid());
	printf("Done.\r\n\r\n");

	return ERR_OK;
}

int winc_gzsock_socket(int family, int type, int protocol) {
    socketInit();

    LOCK_DRIVER();
    int sock_id = socket(AF_INET, type, 0);
    UNLOCK_DRIVER();

    if (sock_id < 0) {
        return -1;
    }

    SockData *sd = take_sock_data(sock_id);
    if(!sd) {
        return -1;
    }

    sock_timeout[sock_id] = 0;

    return sock_id;
}

int winc_gzsock_connect(int sock_id, const struct sockaddr *addr, socklen_t addrlen) {
    int ret;

    socketInit();

    uint8_t slot = cb_data_get_slot();
    if (slot == CB_DATA_LEN) {
        // no more slots available
        return -1;
    }

    printf("CONNECT SLOT %i TO %i\n", slot, sock_id);

    cb_data_assign(slot, CB_TYPE_SOCK, SOCKET_MSG_CONNECT, sock_id, 0);

    LOCK_DRIVER();
    connect(sock_id, addr, addrlen);
    UNLOCK_DRIVER();

    printf("WAIT FOR RES...\n");
    ret = cb_data_get_res(slot);
    printf("GOT RES %i\n", ret);

    if (ret) return 0;
    return -1;
}

int winc_gzsock_send(int sock_id, const void *dataptr, size_t size, int flags) {
    socketInit();

    printf("gzsock_send %i %i\n", sock_id, size);

    // workaround for undetected connection closed by peer (not completely working)
    cb_data_force_free(CB_TYPE_SOCK, SOCKET_MSG_SEND, sock_id);

    uint8_t slot = cb_data_get_slot();
    if (slot == CB_DATA_LEN) {
        // no more slots available
        return -1;
    }

    uint8_t *to_send = (uint8_t*) dataptr;
    uint16_t len = size;

    cb_data_assign(slot, CB_TYPE_SOCK, SOCKET_MSG_SEND, sock_id, 0);

    LOCK_DRIVER();
    send(sock_id, to_send, len, 0);
    UNLOCK_DRIVER();

    sint16 ret = cb_data_get_res(slot);

    if (ret < 0) {
        errno = ECONNABORTED;
    }

    return ret;
}

int winc_gzsock_write(int sock_id, const void *dataptr, size_t size) {
    return winc_gzsock_send(sock_id, dataptr, size, 0);
}

int winc_gzsock_recv(int sock_id, void *mem, size_t len, int flags) {
    socketInit();

    uint8_t *buf = (uint8_t*) mem;
    size_t size = len;

    SockData *sd = get_sock_data(sock_id);
    if (!sd) {
        // no more sockets available
        return -1;
    }

    printf("RECV %i %i %x\n",sock_id,len,buf);

    sint16 ret=0;

    do {
        printf("SD SIZE %i vs %i\n",sd->size,len);
        if (sd->size){
            //get data from socket
            if (sd->size>=len) {
                memcpy(buf,sd->head,len);
                sd->size-=len;
                sd->head+=len;
                len=0;
            } else {
                memcpy(buf,sd->head,sd->size);
                buf+=sd->size;
                len-=sd->size;
                sd->size=0;
            }
        } else {
            uint8_t slot = cb_data_get_slot();
            if (slot == CB_DATA_LEN) {
                // no more slots available
                ret = -1234;
                break;
            }
            cb_data_assign(slot, CB_TYPE_SOCK, SOCKET_MSG_RECV, sock_id, 0);
            cb_data[slot].info[3] = sock_id;
            //do read
            LOCK_DRIVER();
            sd->head = sd->buffer;
            recv(sock_id,sd->buffer,MAX_SOCK_BUF,sock_timeout[sock_id]);
            //recv(sock_id, buf, len, sock_timeout[sock_id]);
            UNLOCK_DRIVER();
            ret = cb_data_get_res(slot);
            printf("EXITRECV WITH SD %i\n",sd->size);
        }
    } while(len>0 && ret>=0);

    if (ret < 0) {
        return ret;
    }
    return size - len; // want to read - left to read
}

int winc_gzsock_read(int sock_id, void *mem, size_t len) {
    return winc_gzsock_recv(sock_id, mem, len, 0);
}

int winc_gzsock_setsockopt(int sock_id, int level, int optname, const void *optval, socklen_t optlen) {
    socketInit();

    if (optname != SO_RCVTIMEO) {
        return -1;
    }

    struct timeval *tms = (struct timeval*) optval;
    sock_timeout[sock_id] = tms->tv_sec * 1000 + ((uint32_t) (tms->tv_usec/1000));

    return 0;
}

int winc_gzsock_getsockopt(int sock_id, int level, int optname, void *optval, socklen_t *optlen) {

    if (optname == SO_RCVTIMEO) {
        struct timeval *tms = (struct timeval*) optval;
        tms->tv_sec = sock_timeout[sock_id] / 1000;
        tms->tv_usec = (sock_timeout[sock_id] % 1000)*1000;

        return 0;
    }

    if (optname == SO_ERROR) {
        int* opterrno = (int*) optval;
        *opterrno = errno;
    }
    return -1;
}

int winc_gzsock_close(int sock_id) {

    LOCK_DRIVER();
    wincsock_close(sock_id);
    UNLOCK_DRIVER();

    SockData *sd = get_sock_data(sock_id);
    if(sd) give_sock_data(sd);

    return 0;
}

int winc_gzsock_select(int maxfdp1, void *readset, void *writeset, void *exceptset, struct timeval *tv) {
    socketInit();
    fd_set *read_fds = (fd_set*) readset;

    int i, ret;
    int sock_id = -1;

    for (i=0; i < FD_SETSIZE; i++) {
        if (FD_ISSET(i, read_fds)) {
            // only one read source supported
            sock_id = i;
            break;
        }
    }

    if (sock_id < 0) {
        return -1;
    }

    SockData *sd = get_sock_data(sock_id);
    if (!sd) {
        // no more sockets available
        return -1;
    }

    if (sd->size) {
        // have data to read
        return 1;
    }

    uint8_t slot = cb_data_get_slot();
    if (slot == CB_DATA_LEN) {
        // no more slots available
        return -1;
    }
    cb_data_assign(slot, CB_TYPE_SOCK, SOCKET_MSG_RECV, sock_id, 0);
    cb_data[slot].info[3] = sock_id;

    uint32_t timeout = tv->tv_sec * 1000 + ((uint32_t) (tv->tv_usec/1000));

    //do read
    LOCK_DRIVER();
    sd->head = sd->buffer;
    recv(sock_id, sd->buffer, MAX_SOCK_BUF, timeout);
    // recv(sock_id, sd->buffer, MAX_SOCK_BUF, 100);
    UNLOCK_DRIVER();
    ret = cb_data_get_res(slot);

    if (ret < 0) {
        if (ret == SOCK_ERR_TIMEOUT) {
            return 0;
        }
        return -1;
    }
    // have data to read
    return 1;
}

int winc_gzsock_fcntl(int s, int cmd, int val) {
    if (cmd != F_GETFL) {
        return -1;
    }
    return O_NONBLOCK;
}


int winc_gzsock_shutdown(int s, int how) {
    return 0;
}

int errno;

SocketAPIPointers winc_api;

WINC_INFO winc_info;
C_NATIVE(__chip_init) {
    NATIVE_UNWARN();

	tstrWifiInitParam param;
	int8_t ret;

    //remove drvinfo from parsing
    nargs--;
    //parse
    if (parse_py_args("iiiiiii", nargs, args, &winc_info.winc_spidrv, &winc_info.winc_cs,&winc_info.winc_int_pin,&winc_info.winc_rst,&winc_info.winc_enable,&winc_info.winc_wake,&winc_info.winc_clock) != 7)
        return ERR_TYPE_EXC;

    printf("spidrv %x\n",winc_info.winc_spidrv);
    printf("cs %x\n",winc_info.winc_cs);
    printf("int_pin %x\n",winc_info.winc_int_pin);
    printf("rst %x\n",winc_info.winc_rst);
    printf("enable %x\n",winc_info.winc_enable);
    printf("wake %x\n",winc_info.winc_wake);
    printf("clock %x\n",winc_info.winc_clock);

    drvinfo = args[7];

    driver_access_mutex = vosSemCreate(1);
    callback_handler_sem = vosSemCreate(0);

    VThread cbt = vosThCreate(640, VOS_PRIO_NORMAL, winc_callback_handler, NULL, NULL);
    vosThResume(cbt);

	/* Initialize the BSP. */
	nm_bsp_init();

	/* Initialize Wi-Fi parameters structure. */
	memset((uint8_t *)&param, 0, sizeof(tstrWifiInitParam));

	/* Initialize Wi-Fi driver with data and status callbacks. */
    param.pfAppWifiCb = wifi_cb;
	ret = m2m_wifi_init(&param);

	if (M2M_SUCCESS != ret) {
		printf("__chip_init: m2m_wifi_init call error!(%d)\r\n", ret);
        return ERR_VALUE_EXC;
	}

    cb_data_init();
    sock_data_init();

    registerSocketCallback(socket_cb, dns_resolve_callback);

    // m2m_ssl_init(NULL);
    // m2m_ssl_set_active_ciphersuites(SSL_NON_ECC_CIPHERS_AES_128 | SSL_NON_ECC_CIPHERS_AES_256);

    winc_api.socket = winc_gzsock_socket;
    winc_api.connect = winc_gzsock_connect;
    winc_api.setsockopt = winc_gzsock_setsockopt;
    winc_api.getsockopt = winc_gzsock_getsockopt;
    winc_api.send = winc_gzsock_send;
    winc_api.sendto = NULL;
    winc_api.write = winc_gzsock_write;
    winc_api.recv = winc_gzsock_recv;
    winc_api.recvfrom = NULL;
    winc_api.read = winc_gzsock_read;
    winc_api.close = winc_gzsock_close;
    winc_api.shutdown = winc_gzsock_shutdown;
    winc_api.bind = NULL;
    winc_api.accept = NULL;
    winc_api.listen = NULL;
    winc_api.select = winc_gzsock_select;
    winc_api.fcntl = winc_gzsock_fcntl;
    winc_api.ioctl = NULL;
    winc_api.getaddrinfo = NULL;
    winc_api.freeaddrinfo = NULL;
    winc_api.inet_addr = NULL;
    winc_api.inet_ntoa = NULL;

    gzsock_init(&winc_api);

    return ERR_OK;
}
