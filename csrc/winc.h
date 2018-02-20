
#ifndef WINC_H_INCLUDED
#define WINC_H_INCLUDED

#include "zerynth.h"
#include "vbl.h"

extern PObject *drvinfo;
// extern PSysObject *drvinfo_lock;

extern VSemaphore callback_handler_sem;

typedef struct _winc_info {
    uint32_t winc_spidrv;
    uint32_t winc_cs;
    uint32_t winc_int_pin;
    uint32_t winc_rst;
    uint32_t winc_enable;
    uint32_t winc_wake;
    uint32_t winc_clock;
} WINC_INFO;

extern WINC_INFO winc_info;

#define get_drv_int_info(x) (winc_info.winc_ ## x)
//(PSMALLINT_VALUE(pdict_get(drvinfo, (PObject*) pstring_new(sizeof(info)-1, (uint8_t *)info))))

#endif
