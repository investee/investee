/* SPDX-License-Identifier: GPL-2.0 */
/*
 * printk() for use before the final page tables are setup.
 *
 * Copyright (C) 2012 Citrix Systems, Inc.
 */

#include <xen/init.h>
#include <xen/lib.h>
#include <xen/stdarg.h>
#include <xen/string.h>
#include <xen/early_printk.h>

void early_putch(char c);
void early_flush(void);

void early_puts(const char *s, size_t nr)
{
    while ( nr-- > 0 )
    {
        if (*s == '\n')
            early_putch('\r');
        early_putch(*s);
        s++;
    }

    /*
     * Wait the UART has finished to transfer all characters before
     * to continue. This will avoid lost characters if Xen abort.
     */
    early_flush();
}
