#ifndef _LINUX_DELAY_H
#define _LINUX_DELAY_H

/* Copyright (C) 1993 Linus Torvalds */

#include <asm/delay.h>

static inline void mdelay(unsigned long msec)
{
    while ( msec-- )
        udelay(1000);
}

#endif /* defined(_LINUX_DELAY_H) */
