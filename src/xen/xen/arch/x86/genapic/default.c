/* 
 * Default generic APIC driver. This handles upto 8 CPUs.
 */
#include <xen/cpumask.h>
#include <asm/current.h>
#include <asm/mpspec.h>
#include <asm/genapic.h>
#include <asm/fixmap.h>
#include <asm/apicdef.h>
#include <xen/kernel.h>
#include <xen/string.h>
#include <xen/smp.h>
#include <xen/init.h>
#include <asm/io_apic.h>

/* should be called last. */
const struct genapic __initconstrel apic_default = {
	APIC_INIT("default", NULL),
	GENAPIC_FLAT
};
