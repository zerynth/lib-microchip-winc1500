#ifndef WINC_FAKE_LWIP_SOCKS_
#define WINC_FAKE_LWIP_SOCKS_

#include "inc/socket.h"

typedef uint32_t socklen_t;

#define  SO_DEBUG       0x0001 /* Unimplemented: turn on debugging info recording */
#define  SO_ACCEPTCONN  0x0002 /* socket has had listen() */
#define  SO_REUSEADDR   0x0004 /* Allow local address reuse */
#define  SO_KEEPALIVE   0x0008 /* keep connections alive */
#define  SO_DONTROUTE   0x0010 /* Unimplemented: just use interface addresses */
#define  SO_BROADCAST   0x0020 /* permit to send and to receive broadcast messages (see IP_SOF_BROADCAST option) */
#define  SO_USELOOPBACK 0x0040 /* Unimplemented: bypass hardware when possible */
#define  SO_LINGER      0x0080 /* linger on close if data present */
#define  SO_OOBINLINE   0x0100 /* Unimplemented: leave received OOB data in line */
#define  SO_REUSEPORT   0x0200 /* Unimplemented: allow local address & port reuse */

/*
 * Additional options, not kept in so_options.
 */
#ifndef SO_SNDBUF
    #define SO_SNDBUF    0x1001    /* Unimplemented: send buffer size */
#endif
#ifndef SO_RCVBUF
    #define SO_RCVBUF    0x1002    /* receive buffer size */
#endif
#define SO_SNDLOWAT  0x1003    /* Unimplemented: send low-water mark */
#define SO_RCVLOWAT  0x1004    /* Unimplemented: receive low-water mark */
#define SO_SNDTIMEO  0x1005    /* Unimplemented: send timeout */
#define SO_RCVTIMEO  0x1006    /* receive timeout */
#define SO_ERROR     0x1007    /* get error status and clear */
#define SO_TYPE      0x1008    /* get socket type */
#define SO_CONTIMEO  0x1009    /* Unimplemented: connect timeout */
#define SO_NO_CHECK  0x100a    /* don't create UDP checksum */

struct timeval {
  long    tv_sec;         /* seconds */
  long    tv_usec;        /* and microseconds */
};

#define AF_UNSPEC       0
#define PF_UNSPEC       AF_UNSPEC

#define IPPROTO_IP      0
#define IPPROTO_TCP     6
#define IPPROTO_UDP     17
#define IPPROTO_UDPLITE 136

/* Flags we can use with send and recv. */
#define MSG_PEEK       0x01    /* Peeks at an incoming message */
#define MSG_WAITALL    0x02    /* Unimplemented: Requests that the function block until the full amount of data requested can be returned */
#define MSG_OOB        0x04    /* Unimplemented: Requests out-of-band data. The significance and semantics of out-of-band data are protocol-specific */
#define MSG_DONTWAIT   0x08    /* Nonblocking i/o for this operation only */
#define MSG_MORE       0x10    /* Sender will send more */

/* commands for fnctl */
#ifndef F_GETFL
#define F_GETFL 3
#endif
#ifndef F_SETFL
#define F_SETFL 4
#endif

/* File status flags and file access modes for fnctl,
   these are bits in an int. */
#ifndef O_NONBLOCK
#define O_NONBLOCK  1 /* nonblocking I/O */
#endif
#ifndef O_NDELAY
#define O_NDELAY    1 /* same as O_NONBLOCK, for compatibility */
#endif



#define IPADDR_ANY          ((uint32_t)0x00000000UL)
#define INADDR_ANY          IPADDR_ANY


#ifndef FD_SET
  #undef  FD_SETSIZE
  /* Make FD_SETSIZE match NUM_SOCKETS in socket.c */
  #define FD_SETSIZE    MAX_SOCKET
  #define FD_SET(n, p)  ((p)->fd_bits[(n)/8] |=  (1 << ((n) & 7)))
  #define FD_CLR(n, p)  ((p)->fd_bits[(n)/8] &= ~(1 << ((n) & 7)))
  #define FD_ISSET(n,p) ((p)->fd_bits[(n)/8] &   (1 << ((n) & 7)))
  #define FD_ZERO(p)    memset((void*)(p),0,sizeof(*(p)))

  typedef struct fd_set {
          unsigned char fd_bits [(FD_SETSIZE+7)/8];
        } fd_set;

#endif /* FD_SET */


#define  EPERM         1  /* Operation not permitted */
#define  ENOENT        2  /* No such file or directory */
#define  ESRCH         3  /* No such process */
#define  EINTR         4  /* Interrupted system call */
#define  EIO           5  /* I/O error */
#define  ENXIO         6  /* No such device or address */
#define  E2BIG         7  /* Arg list too long */
#define  ENOEXEC       8  /* Exec format error */
#define  EBADF         9  /* Bad file number */
#define  ECHILD       10  /* No child processes */
#define  EAGAIN       11  /* Try again */
#define  ENOMEM       12  /* Out of memory */
#define  EACCES       13  /* Permission denied */
#define  EFAULT       14  /* Bad address */
#define  ENOTBLK      15  /* Block device required */
#define  EBUSY        16  /* Device or resource busy */
#define  EEXIST       17  /* File exists */
#define  EXDEV        18  /* Cross-device link */
#define  ENODEV       19  /* No such device */
#define  ENOTDIR      20  /* Not a directory */
#define  EISDIR       21  /* Is a directory */
#define  EINVAL       22  /* Invalid argument */
#define  ENFILE       23  /* File table overflow */
#define  EMFILE       24  /* Too many open files */
#define  ENOTTY       25  /* Not a typewriter */
#define  ETXTBSY      26  /* Text file busy */
#define  EFBIG        27  /* File too large */
#define  ENOSPC       28  /* No space left on device */
#define  ESPIPE       29  /* Illegal seek */
#define  EROFS        30  /* Read-only file system */
#define  EMLINK       31  /* Too many links */
#define  EPIPE        32  /* Broken pipe */
#define  EDOM         33  /* Math argument out of domain of func */
#define  ERANGE       34  /* Math result not representable */
#define  EDEADLK      35  /* Resource deadlock would occur */
#define  ENAMETOOLONG 36  /* File name too long */
#define  ENOLCK       37  /* No record locks available */
#define  ENOSYS       38  /* Function not implemented */
#define  ENOTEMPTY    39  /* Directory not empty */
#define  ELOOP        40  /* Too many symbolic links encountered */
#define  EWOULDBLOCK  EAGAIN  /* Operation would block */
#define  ENOMSG       42  /* No message of desired type */
#define  EIDRM        43  /* Identifier removed */
#define  ECHRNG       44  /* Channel number out of range */
#define  EL2NSYNC     45  /* Level 2 not synchronized */
#define  EL3HLT       46  /* Level 3 halted */
#define  EL3RST       47  /* Level 3 reset */
#define  ELNRNG       48  /* Link number out of range */
#define  EUNATCH      49  /* Protocol driver not attached */
#define  ENOCSI       50  /* No CSI structure available */
#define  EL2HLT       51  /* Level 2 halted */
#define  EBADE        52  /* Invalid exchange */
#define  EBADR        53  /* Invalid request descriptor */
#define  EXFULL       54  /* Exchange full */
#define  ENOANO       55  /* No anode */
#define  EBADRQC      56  /* Invalid request code */
#define  EBADSLT      57  /* Invalid slot */

#define  EDEADLOCK    EDEADLK

#define  EBFONT       59  /* Bad font file format */
#define  ENOSTR       60  /* Device not a stream */
#define  ENODATA      61  /* No data available */
#define  ETIME        62  /* Timer expired */
#define  ENOSR        63  /* Out of streams resources */
#define  ENONET       64  /* Machine is not on the network */
#define  ENOPKG       65  /* Package not installed */
#define  EREMOTE      66  /* Object is remote */
#define  ENOLINK      67  /* Link has been severed */
#define  EADV         68  /* Advertise error */
#define  ESRMNT       69  /* Srmount error */
#define  ECOMM        70  /* Communication error on send */
#define  EPROTO       71  /* Protocol error */
#define  EMULTIHOP    72  /* Multihop attempted */
#define  EDOTDOT      73  /* RFS specific error */
#define  EBADMSG      74  /* Not a data message */
#define  EOVERFLOW    75  /* Value too large for defined data type */
#define  ENOTUNIQ     76  /* Name not unique on network */
#define  EBADFD       77  /* File descriptor in bad state */
#define  EREMCHG      78  /* Remote address changed */
#define  ELIBACC      79  /* Can not access a needed shared library */
#define  ELIBBAD      80  /* Accessing a corrupted shared library */
#define  ELIBSCN      81  /* .lib section in a.out corrupted */
#define  ELIBMAX      82  /* Attempting to link in too many shared libraries */
#define  ELIBEXEC     83  /* Cannot exec a shared library directly */
#define  EILSEQ       84  /* Illegal byte sequence */
#define  ERESTART     85  /* Interrupted system call should be restarted */
#define  ESTRPIPE     86  /* Streams pipe error */
#define  EUSERS       87  /* Too many users */
#define  ENOTSOCK     88  /* Socket operation on non-socket */
#define  EDESTADDRREQ 89  /* Destination address required */
#define  EMSGSIZE     90  /* Message too long */
#define  EPROTOTYPE   91  /* Protocol wrong type for socket */
#define  ENOPROTOOPT  92  /* Protocol not available */
#define  EPROTONOSUPPORT 93  /* Protocol not supported */
#define  ESOCKTNOSUPPORT 94  /* Socket type not supported */
#define  EOPNOTSUPP      95  /* Operation not supported on transport endpoint */
#define  EPFNOSUPPORT    96  /* Protocol family not supported */
#define  EAFNOSUPPORT    97  /* Address family not supported by protocol */
#define  EADDRINUSE      98  /* Address already in use */
#define  EADDRNOTAVAIL   99  /* Cannot assign requested address */
#define  ENETDOWN       100  /* Network is down */
#define  ENETUNREACH    101  /* Network is unreachable */
#define  ENETRESET      102  /* Network dropped connection because of reset */
#define  ECONNABORTED   103  /* Software caused connection abort */
#define  ECONNRESET     104  /* Connection reset by peer */
#define  ENOBUFS        105  /* No buffer space available */
#define  EISCONN        106  /* Transport endpoint is already connected */
#define  ENOTCONN       107  /* Transport endpoint is not connected */
#define  ESHUTDOWN      108  /* Cannot send after transport endpoint shutdown */
#define  ETOOMANYREFS   109  /* Too many references: cannot splice */
#define  ETIMEDOUT      110  /* Connection timed out */
#define  ECONNREFUSED   111  /* Connection refused */
#define  EHOSTDOWN      112  /* Host is down */
#define  EHOSTUNREACH   113  /* No route to host */
#define  EALREADY       114  /* Operation already in progress */
#define  EINPROGRESS    115  /* Operation now in progress */
#define  ESTALE         116  /* Stale NFS file handle */
#define  EUCLEAN        117  /* Structure needs cleaning */
#define  ENOTNAM        118  /* Not a XENIX named type file */
#define  ENAVAIL        119  /* No XENIX semaphores available */
#define  EISNAM         120  /* Is a named type file */
#define  EREMOTEIO      121  /* Remote I/O error */
#define  EDQUOT         122  /* Quota exceeded */

#define  ENOMEDIUM      123  /* No medium found */
#define  EMEDIUMTYPE    124  /* Wrong medium type */

#ifndef errno
extern int errno;
#endif

#define htonl(x) _htonl(x)

#endif
