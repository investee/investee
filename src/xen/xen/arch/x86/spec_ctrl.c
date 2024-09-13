/* SPDX-License-Identifier: GPL-2.0-or-later */
/******************************************************************************
 * arch/x86/spec_ctrl.c
 *
 * Copyright (c) 2017-2018 Citrix Systems Ltd.
 */
#include <xen/errno.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/param.h>
#include <xen/warning.h>

#include <asm/amd.h>
#include <asm/hvm/svm/svm.h>
#include <asm/microcode.h>
#include <asm/msr.h>
#include <asm/pv/domain.h>
#include <asm/pv/shim.h>
#include <asm/setup.h>
#include <asm/spec_ctrl.h>
#include <asm/spec_ctrl_asm.h>

/* Cmdline controls for Xen's alternative blocks. */
static bool __initdata opt_msr_sc_pv = true;
static bool __initdata opt_msr_sc_hvm = true;
static int8_t __initdata opt_rsb_pv = -1;
static bool __initdata opt_rsb_hvm = true;
static int8_t __ro_after_init opt_md_clear_pv = -1;
static int8_t __ro_after_init opt_md_clear_hvm = -1;

static int8_t __ro_after_init opt_ibpb_entry_pv = -1;
static int8_t __ro_after_init opt_ibpb_entry_hvm = -1;
static bool __ro_after_init opt_ibpb_entry_dom0;

/* Cmdline controls for Xen's speculative settings. */
static enum ind_thunk {
    THUNK_DEFAULT, /* Decide which thunk to use at boot time. */
    THUNK_NONE,    /* Missing compiler support for thunks. */

    THUNK_RETPOLINE,
    THUNK_LFENCE,
    THUNK_JMP,
} opt_thunk __initdata = THUNK_DEFAULT;

static int8_t __initdata opt_ibrs = -1;
static int8_t __initdata opt_stibp = -1;
bool __ro_after_init opt_ssbd;
static int8_t __initdata opt_psfd = -1;

int8_t __ro_after_init opt_ibpb_ctxt_switch = -1;
int8_t __read_mostly opt_eager_fpu = -1;
int8_t __read_mostly opt_l1d_flush = -1;
static bool __initdata opt_branch_harden = true;

bool __initdata bsp_delay_spec_ctrl;
uint8_t __read_mostly default_xen_spec_ctrl;
uint8_t __read_mostly default_spec_ctrl_flags;

paddr_t __read_mostly l1tf_addr_mask, __read_mostly l1tf_safe_maddr;
bool __read_mostly cpu_has_bug_l1tf;
static unsigned int __initdata l1d_maxphysaddr;

static bool __initdata cpu_has_bug_msbds_only; /* => minimal HT impact. */
static bool __initdata cpu_has_bug_mds; /* Any other M{LP,SB,FB}DS combination. */

static int8_t __initdata opt_srb_lock = -1;
static bool __initdata opt_unpriv_mmio;
static bool __ro_after_init opt_fb_clear_mmio;
static int8_t __initdata opt_gds_mit = -1;
static int8_t __initdata opt_div_scrub = -1;

static int __init cf_check parse_spec_ctrl(const char *s)
{
    const char *ss;
    int val, rc = 0;

    do {
        ss = strchr(s, ',');
        if ( !ss )
            ss = strchr(s, '\0');

        /* Global and Xen-wide disable. */
        val = parse_bool(s, ss);
        if ( !val )
        {
            opt_msr_sc_pv = false;
            opt_msr_sc_hvm = false;

            opt_eager_fpu = 0;

            if ( opt_xpti_hwdom < 0 )
                opt_xpti_hwdom = 0;
            if ( opt_xpti_domu < 0 )
                opt_xpti_domu = 0;

            if ( opt_smt < 0 )
                opt_smt = 1;

            if ( opt_pv_l1tf_hwdom < 0 )
                opt_pv_l1tf_hwdom = 0;
            if ( opt_pv_l1tf_domu < 0 )
                opt_pv_l1tf_domu = 0;

            if ( opt_tsx == -1 )
                opt_tsx = -3;

        disable_common:
            opt_rsb_pv = false;
            opt_rsb_hvm = false;
            opt_md_clear_pv = 0;
            opt_md_clear_hvm = 0;
            opt_ibpb_entry_pv = 0;
            opt_ibpb_entry_hvm = 0;
            opt_ibpb_entry_dom0 = false;

            opt_thunk = THUNK_JMP;
            opt_ibrs = 0;
            opt_ibpb_ctxt_switch = false;
            opt_ssbd = false;
            opt_l1d_flush = 0;
            opt_branch_harden = false;
            opt_srb_lock = 0;
            opt_unpriv_mmio = false;
            opt_gds_mit = 0;
            opt_div_scrub = 0;
        }
        else if ( val > 0 )
            rc = -EINVAL;
        else if ( (val = parse_boolean("xen", s, ss)) >= 0 )
        {
            if ( !val )
                goto disable_common;

            rc = -EINVAL;
        }

        /* Xen's alternative blocks. */
        else if ( (val = parse_boolean("pv", s, ss)) >= 0 )
        {
            opt_msr_sc_pv = val;
            opt_rsb_pv = val;
            opt_md_clear_pv = val;
            opt_ibpb_entry_pv = val;
        }
        else if ( (val = parse_boolean("hvm", s, ss)) >= 0 )
        {
            opt_msr_sc_hvm = val;
            opt_rsb_hvm = val;
            opt_md_clear_hvm = val;
            opt_ibpb_entry_hvm = val;
        }
        else if ( (val = parse_boolean("msr-sc", s, ss)) != -1 )
        {
            switch ( val )
            {
            case 0:
            case 1:
                opt_msr_sc_pv = opt_msr_sc_hvm = val;
                break;

            case -2:
                s += strlen("msr-sc=");
                if ( (val = parse_boolean("pv", s, ss)) >= 0 )
                    opt_msr_sc_pv = val;
                else if ( (val = parse_boolean("hvm", s, ss)) >= 0 )
                    opt_msr_sc_hvm = val;
                else
            default:
                    rc = -EINVAL;
                break;
            }
        }
        else if ( (val = parse_boolean("rsb", s, ss)) != -1 )
        {
            switch ( val )
            {
            case 0:
            case 1:
                opt_rsb_pv = opt_rsb_hvm = val;
                break;

            case -2:
                s += strlen("rsb=");
                if ( (val = parse_boolean("pv", s, ss)) >= 0 )
                    opt_rsb_pv = val;
                else if ( (val = parse_boolean("hvm", s, ss)) >= 0 )
                    opt_rsb_hvm = val;
                else
            default:
                    rc = -EINVAL;
                break;
            }
        }
        else if ( (val = parse_boolean("md-clear", s, ss)) != -1 )
        {
            switch ( val )
            {
            case 0:
            case 1:
                opt_md_clear_pv = opt_md_clear_hvm = val;
                break;

            case -2:
                s += strlen("md-clear=");
                if ( (val = parse_boolean("pv", s, ss)) >= 0 )
                    opt_md_clear_pv = val;
                else if ( (val = parse_boolean("hvm", s, ss)) >= 0 )
                    opt_md_clear_hvm = val;
                else
            default:
                    rc = -EINVAL;
                break;
            }
        }
        else if ( (val = parse_boolean("ibpb-entry", s, ss)) != -1 )
        {
            switch ( val )
            {
            case 0:
            case 1:
                opt_ibpb_entry_pv = opt_ibpb_entry_hvm =
                    opt_ibpb_entry_dom0 = val;
                break;

            case -2:
                s += strlen("ibpb-entry=");
                if ( (val = parse_boolean("pv", s, ss)) >= 0 )
                    opt_ibpb_entry_pv = val;
                else if ( (val = parse_boolean("hvm", s, ss)) >= 0 )
                    opt_ibpb_entry_hvm = val;
                else
            default:
                    rc = -EINVAL;
                break;
            }
        }

        /* Xen's speculative sidechannel mitigation settings. */
        else if ( !strncmp(s, "bti-thunk=", 10) )
        {
            s += 10;

            if ( !cmdline_strcmp(s, "retpoline") )
                opt_thunk = THUNK_RETPOLINE;
            else if ( !cmdline_strcmp(s, "lfence") )
                opt_thunk = THUNK_LFENCE;
            else if ( !cmdline_strcmp(s, "jmp") )
                opt_thunk = THUNK_JMP;
            else
                rc = -EINVAL;
        }

        /* Bits in MSR_SPEC_CTRL. */
        else if ( (val = parse_boolean("ibrs", s, ss)) >= 0 )
            opt_ibrs = val;
        else if ( (val = parse_boolean("stibp", s, ss)) >= 0 )
            opt_stibp = val;
        else if ( (val = parse_boolean("ssbd", s, ss)) >= 0 )
            opt_ssbd = val;
        else if ( (val = parse_boolean("psfd", s, ss)) >= 0 )
            opt_psfd = val;

        /* Misc settings. */
        else if ( (val = parse_boolean("ibpb", s, ss)) >= 0 )
            opt_ibpb_ctxt_switch = val;
        else if ( (val = parse_boolean("eager-fpu", s, ss)) >= 0 )
            opt_eager_fpu = val;
        else if ( (val = parse_boolean("l1d-flush", s, ss)) >= 0 )
            opt_l1d_flush = val;
        else if ( (val = parse_boolean("branch-harden", s, ss)) >= 0 )
            opt_branch_harden = val;
        else if ( (val = parse_boolean("srb-lock", s, ss)) >= 0 )
            opt_srb_lock = val;
        else if ( (val = parse_boolean("unpriv-mmio", s, ss)) >= 0 )
            opt_unpriv_mmio = val;
        else if ( (val = parse_boolean("gds-mit", s, ss)) >= 0 )
            opt_gds_mit = val;
        else if ( (val = parse_boolean("div-scrub", s, ss)) >= 0 )
            opt_div_scrub = val;
        else
            rc = -EINVAL;

        s = ss + 1;
    } while ( *ss );

    return rc;
}
custom_param("spec-ctrl", parse_spec_ctrl);

int8_t __read_mostly opt_xpti_hwdom = -1;
int8_t __read_mostly opt_xpti_domu = -1;

static __init void xpti_init_default(void)
{
    if ( (boot_cpu_data.x86_vendor & (X86_VENDOR_AMD | X86_VENDOR_HYGON)) ||
         cpu_has_rdcl_no )
    {
        if ( opt_xpti_hwdom < 0 )
            opt_xpti_hwdom = 0;
        if ( opt_xpti_domu < 0 )
            opt_xpti_domu = 0;
    }
    else
    {
        if ( opt_xpti_hwdom < 0 )
            opt_xpti_hwdom = 1;
        if ( opt_xpti_domu < 0 )
            opt_xpti_domu = 1;
    }
}

static int __init cf_check parse_xpti(const char *s)
{
    const char *ss;
    int val, rc = 0;

    /* Interpret 'xpti' alone in its positive boolean form. */
    if ( *s == '\0' )
        opt_xpti_hwdom = opt_xpti_domu = 1;

    do {
        ss = strchr(s, ',');
        if ( !ss )
            ss = strchr(s, '\0');

        switch ( parse_bool(s, ss) )
        {
        case 0:
            opt_xpti_hwdom = opt_xpti_domu = 0;
            break;

        case 1:
            opt_xpti_hwdom = opt_xpti_domu = 1;
            break;

        default:
            if ( !strcmp(s, "default") )
                opt_xpti_hwdom = opt_xpti_domu = -1;
            else if ( (val = parse_boolean("dom0", s, ss)) >= 0 )
                opt_xpti_hwdom = val;
            else if ( (val = parse_boolean("domu", s, ss)) >= 0 )
                opt_xpti_domu = val;
            else if ( *s )
                rc = -EINVAL;
            break;
        }

        s = ss + 1;
    } while ( *ss );

    return rc;
}
custom_param("xpti", parse_xpti);

int8_t __read_mostly opt_pv_l1tf_hwdom = -1;
int8_t __read_mostly opt_pv_l1tf_domu = -1;

static int __init cf_check parse_pv_l1tf(const char *s)
{
    const char *ss;
    int val, rc = 0;

    /* Interpret 'pv-l1tf' alone in its positive boolean form. */
    if ( *s == '\0' )
        opt_pv_l1tf_hwdom = opt_pv_l1tf_domu = 1;

    do {
        ss = strchr(s, ',');
        if ( !ss )
            ss = strchr(s, '\0');

        switch ( parse_bool(s, ss) )
        {
        case 0:
            opt_pv_l1tf_hwdom = opt_pv_l1tf_domu = 0;
            break;

        case 1:
            opt_pv_l1tf_hwdom = opt_pv_l1tf_domu = 1;
            break;

        default:
            if ( (val = parse_boolean("dom0", s, ss)) >= 0 )
                opt_pv_l1tf_hwdom = val;
            else if ( (val = parse_boolean("domu", s, ss)) >= 0 )
                opt_pv_l1tf_domu = val;
            else if ( *s )
                rc = -EINVAL;
            break;
        }

        s = ss + 1;
    } while ( *ss );

    return rc;
}
custom_param("pv-l1tf", parse_pv_l1tf);

static void __init print_details(enum ind_thunk thunk)
{
    unsigned int _7d0 = 0, _7d2 = 0, e8b = 0, e21a = 0, max = 0, tmp;
    uint64_t caps = 0;

    /* Collect diagnostics about available mitigations. */
    if ( boot_cpu_data.cpuid_level >= 7 )
        cpuid_count(7, 0, &max, &tmp, &tmp, &_7d0);
    if ( max >= 2 )
        cpuid_count(7, 2, &tmp, &tmp, &tmp, &_7d2);
    if ( boot_cpu_data.extended_cpuid_level >= 0x80000008 )
        cpuid(0x80000008, &tmp, &e8b, &tmp, &tmp);
    if ( boot_cpu_data.extended_cpuid_level >= 0x80000021 )
        cpuid(0x80000021, &e21a, &tmp, &tmp, &tmp);
    if ( cpu_has_arch_caps )
        rdmsrl(MSR_ARCH_CAPABILITIES, caps);

    printk("Speculative mitigation facilities:\n");

    /*
     * Hardware read-only information, stating immunity to certain issues, or
     * suggestions of which mitigation to use.
     */
    printk("  Hardware hints:%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s\n",
           (caps & ARCH_CAPS_RDCL_NO)                        ? " RDCL_NO"        : "",
           (caps & ARCH_CAPS_EIBRS)                          ? " EIBRS"          : "",
           (caps & ARCH_CAPS_RSBA)                           ? " RSBA"           : "",
           (caps & ARCH_CAPS_RRSBA)                          ? " RRSBA"          : "",
           (caps & ARCH_CAPS_SKIP_L1DFL)                     ? " SKIP_L1DFL"     : "",
           (e8b  & cpufeat_mask(X86_FEATURE_SSB_NO)) ||
           (caps & ARCH_CAPS_SSB_NO)                         ? " SSB_NO"         : "",
           (caps & ARCH_CAPS_MDS_NO)                         ? " MDS_NO"         : "",
           (caps & ARCH_CAPS_TAA_NO)                         ? " TAA_NO"         : "",
           (caps & ARCH_CAPS_SBDR_SSDP_NO)                   ? " SBDR_SSDP_NO"   : "",
           (caps & ARCH_CAPS_FBSDP_NO)                       ? " FBSDP_NO"       : "",
           (caps & ARCH_CAPS_PSDP_NO)                        ? " PSDP_NO"        : "",
           (caps & ARCH_CAPS_FB_CLEAR)                       ? " FB_CLEAR"       : "",
           (caps & ARCH_CAPS_PBRSB_NO)                       ? " PBRSB_NO"       : "",
           (caps & ARCH_CAPS_GDS_NO)                         ? " GDS_NO"         : "",
           (e8b  & cpufeat_mask(X86_FEATURE_IBRS_ALWAYS))    ? " IBRS_ALWAYS"    : "",
           (e8b  & cpufeat_mask(X86_FEATURE_STIBP_ALWAYS))   ? " STIBP_ALWAYS"   : "",
           (e8b  & cpufeat_mask(X86_FEATURE_IBRS_FAST))      ? " IBRS_FAST"      : "",
           (e8b  & cpufeat_mask(X86_FEATURE_IBRS_SAME_MODE)) ? " IBRS_SAME_MODE" : "",
           (e8b  & cpufeat_mask(X86_FEATURE_BTC_NO))         ? " BTC_NO"         : "",
           (e8b  & cpufeat_mask(X86_FEATURE_IBPB_RET))       ? " IBPB_RET"       : "",
           (e21a & cpufeat_mask(X86_FEATURE_IBPB_BRTYPE))    ? " IBPB_BRTYPE"    : "",
           (e21a & cpufeat_mask(X86_FEATURE_SRSO_NO))        ? " SRSO_NO"        : "");

    /* Hardware features which need driving to mitigate issues. */
    printk("  Hardware features:%s%s%s%s%s%s%s%s%s%s%s%s%s\n",
           (e8b  & cpufeat_mask(X86_FEATURE_IBPB)) ||
           (_7d0 & cpufeat_mask(X86_FEATURE_IBRSB))          ? " IBPB"           : "",
           (e8b  & cpufeat_mask(X86_FEATURE_IBRS)) ||
           (_7d0 & cpufeat_mask(X86_FEATURE_IBRSB))          ? " IBRS"           : "",
           (e8b  & cpufeat_mask(X86_FEATURE_AMD_STIBP)) ||
           (_7d0 & cpufeat_mask(X86_FEATURE_STIBP))          ? " STIBP"          : "",
           (e8b  & cpufeat_mask(X86_FEATURE_AMD_SSBD)) ||
           (_7d0 & cpufeat_mask(X86_FEATURE_SSBD))           ? " SSBD"           : "",
           (_7d2 & cpufeat_mask(X86_FEATURE_INTEL_PSFD)) ||
           (e8b  & cpufeat_mask(X86_FEATURE_PSFD))           ? " PSFD"           : "",
           (_7d0 & cpufeat_mask(X86_FEATURE_L1D_FLUSH))      ? " L1D_FLUSH"      : "",
           (_7d0 & cpufeat_mask(X86_FEATURE_MD_CLEAR))       ? " MD_CLEAR"       : "",
           (_7d0 & cpufeat_mask(X86_FEATURE_SRBDS_CTRL))     ? " SRBDS_CTRL"     : "",
           (e8b  & cpufeat_mask(X86_FEATURE_VIRT_SSBD))      ? " VIRT_SSBD"      : "",
           (caps & ARCH_CAPS_TSX_CTRL)                       ? " TSX_CTRL"       : "",
           (caps & ARCH_CAPS_FB_CLEAR_CTRL)                  ? " FB_CLEAR_CTRL"  : "",
           (caps & ARCH_CAPS_GDS_CTRL)                       ? " GDS_CTRL"       : "",
           (e21a & cpufeat_mask(X86_FEATURE_SBPB))           ? " SBPB"           : "");

    /* Compiled-in support which pertains to mitigations. */
    if ( IS_ENABLED(CONFIG_INDIRECT_THUNK) || IS_ENABLED(CONFIG_SHADOW_PAGING) )
        printk("  Compiled-in support:"
#ifdef CONFIG_INDIRECT_THUNK
               " INDIRECT_THUNK"
#endif
#ifdef CONFIG_SHADOW_PAGING
               " SHADOW_PAGING"
#endif
               "\n");

    /* Settings for Xen's protection, irrespective of guests. */
    printk("  Xen settings: BTI-Thunk %s, SPEC_CTRL: %s%s%s%s%s, Other:%s%s%s%s%s%s\n",
           thunk == THUNK_NONE      ? "N/A" :
           thunk == THUNK_RETPOLINE ? "RETPOLINE" :
           thunk == THUNK_LFENCE    ? "LFENCE" :
           thunk == THUNK_JMP       ? "JMP" : "?",
           (!boot_cpu_has(X86_FEATURE_IBRSB) &&
            !boot_cpu_has(X86_FEATURE_IBRS))         ? "No" :
           (default_xen_spec_ctrl & SPEC_CTRL_IBRS)  ? "IBRS+" :  "IBRS-",
           (!boot_cpu_has(X86_FEATURE_STIBP) &&
            !boot_cpu_has(X86_FEATURE_AMD_STIBP))    ? "" :
           (default_xen_spec_ctrl & SPEC_CTRL_STIBP) ? " STIBP+" : " STIBP-",
           (!boot_cpu_has(X86_FEATURE_SSBD) &&
            !boot_cpu_has(X86_FEATURE_AMD_SSBD))     ? "" :
           (default_xen_spec_ctrl & SPEC_CTRL_SSBD)  ? " SSBD+" : " SSBD-",
           (!boot_cpu_has(X86_FEATURE_PSFD) &&
            !boot_cpu_has(X86_FEATURE_INTEL_PSFD))   ? "" :
           (default_xen_spec_ctrl & SPEC_CTRL_PSFD)  ? " PSFD+" : " PSFD-",
           !(caps & ARCH_CAPS_TSX_CTRL)              ? "" :
           (opt_tsx & 1)                             ? " TSX+" : " TSX-",
           !cpu_has_srbds_ctrl                       ? "" :
           opt_srb_lock                              ? " SRB_LOCK+" : " SRB_LOCK-",
           opt_ibpb_ctxt_switch                      ? " IBPB-ctxt" : "",
           opt_l1d_flush                             ? " L1D_FLUSH" : "",
           opt_md_clear_pv || opt_md_clear_hvm ||
           opt_fb_clear_mmio                         ? " VERW"  : "",
           opt_div_scrub                             ? " DIV" : "",
           opt_branch_harden                         ? " BRANCH_HARDEN" : "");

    /* L1TF diagnostics, printed if vulnerable or PV shadowing is in use. */
    if ( cpu_has_bug_l1tf || opt_pv_l1tf_hwdom || opt_pv_l1tf_domu )
        printk("  L1TF: believed%s vulnerable, maxphysaddr L1D %u, CPUID %u"
               ", Safe address %"PRIx64"\n",
               cpu_has_bug_l1tf ? "" : " not",
               l1d_maxphysaddr, paddr_bits, l1tf_safe_maddr);

    /*
     * Alternatives blocks for protecting against and/or virtualising
     * mitigation support for guests.
     */
#ifdef CONFIG_HVM
    printk("  Support for HVM VMs:%s%s%s%s%s%s%s\n",
           (boot_cpu_has(X86_FEATURE_SC_MSR_HVM) ||
            boot_cpu_has(X86_FEATURE_SC_RSB_HVM) ||
            boot_cpu_has(X86_FEATURE_IBPB_ENTRY_HVM) ||
            amd_virt_spec_ctrl ||
            opt_eager_fpu || opt_md_clear_hvm)       ? ""               : " None",
           boot_cpu_has(X86_FEATURE_SC_MSR_HVM)      ? " MSR_SPEC_CTRL" : "",
           (boot_cpu_has(X86_FEATURE_SC_MSR_HVM) ||
            amd_virt_spec_ctrl)                      ? " MSR_VIRT_SPEC_CTRL" : "",
           boot_cpu_has(X86_FEATURE_SC_RSB_HVM)      ? " RSB"           : "",
           opt_eager_fpu                             ? " EAGER_FPU"     : "",
           opt_md_clear_hvm                          ? " MD_CLEAR"      : "",
           boot_cpu_has(X86_FEATURE_IBPB_ENTRY_HVM)  ? " IBPB-entry"    : "");

#endif
#ifdef CONFIG_PV
    printk("  Support for PV VMs:%s%s%s%s%s%s\n",
           (boot_cpu_has(X86_FEATURE_SC_MSR_PV) ||
            boot_cpu_has(X86_FEATURE_SC_RSB_PV) ||
            boot_cpu_has(X86_FEATURE_IBPB_ENTRY_PV) ||
            opt_eager_fpu || opt_md_clear_pv)        ? ""               : " None",
           boot_cpu_has(X86_FEATURE_SC_MSR_PV)       ? " MSR_SPEC_CTRL" : "",
           boot_cpu_has(X86_FEATURE_SC_RSB_PV)       ? " RSB"           : "",
           opt_eager_fpu                             ? " EAGER_FPU"     : "",
           opt_md_clear_pv                           ? " MD_CLEAR"      : "",
           boot_cpu_has(X86_FEATURE_IBPB_ENTRY_PV)   ? " IBPB-entry"    : "");

    printk("  XPTI (64-bit PV only): Dom0 %s, DomU %s (with%s PCID)\n",
           opt_xpti_hwdom ? "enabled" : "disabled",
           opt_xpti_domu  ? "enabled" : "disabled",
           xpti_pcid_enabled() ? "" : "out");

    printk("  PV L1TF shadowing: Dom0 %s, DomU %s\n",
           opt_pv_l1tf_hwdom ? "enabled"  : "disabled",
           opt_pv_l1tf_domu  ? "enabled"  : "disabled");
#endif
}

static bool __init check_smt_enabled(void)
{
    uint64_t val;
    unsigned int cpu;

    /*
     * x86_num_siblings defaults to 1 in the absence of other information, and
     * is adjusted based on other topology information found in CPUID leaves.
     *
     * On AMD hardware, it will be the current SMT configuration.  On Intel
     * hardware, it will represent the maximum capability, rather than the
     * current configuration.
     */
    if ( boot_cpu_data.x86_num_siblings < 2 )
        return false;

    /*
     * Intel Nehalem and later hardware does have an MSR which reports the
     * current count of cores/threads in the package.
     *
     * At the time of writing, it is almost completely undocumented, so isn't
     * virtualised reliably.
     */
    if ( boot_cpu_data.x86_vendor == X86_VENDOR_INTEL &&
         boot_cpu_data.x86 != 0xf && !cpu_has_hypervisor &&
         !rdmsr_safe(MSR_INTEL_CORE_THREAD_COUNT, val) )
        return (MASK_EXTR(val, MSR_CTC_CORE_MASK) !=
                MASK_EXTR(val, MSR_CTC_THREAD_MASK));

    /*
     * Search over the CPUs reported in the ACPI tables.  Any whose APIC ID
     * has a non-zero thread id component indicates that SMT is active.
     */
    for_each_present_cpu ( cpu )
        if ( x86_cpu_to_apicid[cpu] & (boot_cpu_data.x86_num_siblings - 1) )
            return true;

    return false;
}

/*
 * Calculate whether Retpoline is known-safe on this CPU.  Fix up the
 * RSBA/RRSBA bits as necessary.
 */
static bool __init retpoline_calculations(void)
{
    unsigned int ucode_rev = this_cpu(cpu_sig).rev;
    bool safe = false;

    if ( boot_cpu_data.x86_vendor & (X86_VENDOR_AMD | X86_VENDOR_HYGON) )
        return true;

    if ( boot_cpu_data.x86_vendor != X86_VENDOR_INTEL ||
         boot_cpu_data.x86 != 6 )
        return false;

    /*
     * The meaning of the RSBA and RRSBA bits have evolved over time.  The
     * agreed upon meaning at the time of writing (May 2023) is thus:
     *
     * - RSBA (RSB Alternative) means that an RSB may fall back to an
     *   alternative predictor on underflow.  Skylake uarch and later all have
     *   this property.  Broadwell too, when running microcode versions prior
     *   to Jan 2018.
     *
     * - All eIBRS-capable processors suffer RSBA, but eIBRS also introduces
     *   tagging of predictions with the mode in which they were learned.  So
     *   when eIBRS is active, RSBA becomes RRSBA (Restricted RSBA).
     *
     * - CPUs are not expected to enumerate both RSBA and RRSBA.
     *
     * Some parts (Broadwell) are not expected to ever enumerate this
     * behaviour directly.  Other parts have differing enumeration with
     * microcode version.  Fix up Xen's idea, so we can advertise them safely
     * to guests, and so toolstacks can level a VM safety for migration.
     *
     * The following states exist:
     *
     * |   | RSBA | EIBRS | RRSBA | Notes              | Action (in principle) |
     * |---+------+-------+-------+--------------------+-----------------------|
     * | 1 |    0 |     0 |     0 | OK (older parts)   | Maybe +RSBA           |
     * | 2 |    0 |     0 |     1 | Broken             | (+RSBA, -RRSBA)       |
     * | 3 |    0 |     1 |     0 | OK (pre-Aug ucode) | +RRSBA                |
     * | 4 |    0 |     1 |     1 | OK                 |                       |
     * | 5 |    1 |     0 |     0 | OK                 |                       |
     * | 6 |    1 |     0 |     1 | Broken             | (-RRSBA)              |
     * | 7 |    1 |     1 |     0 | Broken             | (-RSBA, +RRSBA)       |
     * | 8 |    1 |     1 |     1 | Broken             | (-RSBA)               |
     *
     * However, we don't need perfect adherence to the spec.  We only need
     * RSBA || RRSBA to indicate "alternative predictors potentially in use".
     * Rows 1 & 3 are fixed up by later logic, as they're known configurations
     * which exist in the world.
     *
     * Complain loudly at the broken cases. They're safe for Xen to use (so we
     * don't attempt to correct), and may or may not exist in reality, but if
     * we ever encounter them in practice, something is wrong and needs
     * further investigation.
     */
    if ( cpu_has_eibrs ? cpu_has_rsba  /* Rows 7, 8 */
                       : cpu_has_rrsba /* Rows 2, 6 */ )
    {
        printk(XENLOG_ERR
               "FIRMWARE BUG: CPU %02x-%02x-%02x, ucode 0x%08x: RSBA %u, EIBRS %u, RRSBA %u\n",
               boot_cpu_data.x86, boot_cpu_data.x86_model,
               boot_cpu_data.x86_mask, ucode_rev,
               cpu_has_rsba, cpu_has_eibrs, cpu_has_rrsba);
        add_taint(TAINT_CPU_OUT_OF_SPEC);
    }

    /*
     * Processors offering Enhanced IBRS are not guarenteed to be
     * repoline-safe.
     */
    if ( cpu_has_eibrs )
    {
        /*
         * Prior to the August 2023 microcode, many eIBRS-capable parts did
         * not enumerate RRSBA.
         */
        if ( !cpu_has_rrsba )
            setup_force_cpu_cap(X86_FEATURE_RRSBA);

        return false;
    }

    /*
     * RSBA is explicitly enumerated in some cases, but may also be set by a
     * hypervisor to indicate that we may move to a processor which isn't
     * retpoline-safe.
     */
    if ( cpu_has_rsba )
        return false;

    /*
     * At this point, we've filtered all the legal RSBA || RRSBA cases (or the
     * known non-ideal cases).  If ARCH_CAPS is visible, trust the absence of
     * RSBA || RRSBA.  There's no known microcode which advertises ARCH_CAPS
     * without RSBA or EIBRS, and if we're virtualised we can't rely the model
     * check anyway.
     */
    if ( cpu_has_arch_caps )
        return true;

    switch ( boot_cpu_data.x86_model )
    {
    case 0x17: /* Penryn */
    case 0x1d: /* Dunnington */
    case 0x1e: /* Nehalem */
    case 0x1f: /* Auburndale / Havendale */
    case 0x1a: /* Nehalem EP */
    case 0x2e: /* Nehalem EX */
    case 0x25: /* Westmere */
    case 0x2c: /* Westmere EP */
    case 0x2f: /* Westmere EX */
    case 0x2a: /* SandyBridge */
    case 0x2d: /* SandyBridge EP/EX */
    case 0x3a: /* IvyBridge */
    case 0x3e: /* IvyBridge EP/EX */
    case 0x3c: /* Haswell */
    case 0x3f: /* Haswell EX/EP */
    case 0x45: /* Haswell D */
    case 0x46: /* Haswell H */
        safe = true;
        break;

        /*
         * Broadwell processors are retpoline-safe after specific microcode
         * versions.
         */
    case 0x3d: /* Broadwell */
        safe = ucode_rev >= 0x2a;      break;
    case 0x47: /* Broadwell H */
        safe = ucode_rev >= 0x1d;      break;
    case 0x4f: /* Broadwell EP/EX */
        safe = ucode_rev >= 0xb000021; break;
    case 0x56: /* Broadwell D */
        switch ( boot_cpu_data.x86_mask )
        {
        case 2:  safe = ucode_rev >= 0x15;      break;
        case 3:  safe = ucode_rev >= 0x7000012; break;
        case 4:  safe = ucode_rev >= 0xf000011; break;
        case 5:  safe = ucode_rev >= 0xe000009; break;
        default:
            printk("Unrecognised CPU stepping %#x - assuming not reptpoline safe\n",
                   boot_cpu_data.x86_mask);
            safe = false;
            break;
        }
        break;

        /*
         * Skylake, Kabylake and Cannonlake processors are not retpoline-safe.
         */
    case 0x4e: /* Skylake M */
    case 0x55: /* Skylake X */
    case 0x5e: /* Skylake D */
    case 0x66: /* Cannonlake */
    case 0x67: /* Cannonlake? */
    case 0x8e: /* Kabylake M */
    case 0x9e: /* Kabylake D */
        safe = false;
        break;

        /*
         * Atom processors before Goldmont Plus/Gemini Lake are retpoline-safe.
         */
    case 0x1c: /* Pineview */
    case 0x26: /* Lincroft */
    case 0x27: /* Penwell */
    case 0x35: /* Cloverview */
    case 0x36: /* Cedarview */
    case 0x37: /* Baytrail / Valleyview (Silvermont) */
    case 0x4d: /* Avaton / Rangely (Silvermont) */
    case 0x4c: /* Cherrytrail / Brasswell */
    case 0x4a: /* Merrifield */
    case 0x57: /* Knights Landing */
    case 0x5a: /* Moorefield */
    case 0x5c: /* Goldmont */
    case 0x5f: /* Denverton */
    case 0x85: /* Knights Mill */
        safe = true;
        break;

    default:
        printk("Unrecognised CPU model %#x - assuming not reptpoline safe\n",
               boot_cpu_data.x86_model);
        safe = false;
        break;
    }

    if ( !safe )
    {
        /*
         * Note: the eIBRS-capable parts are filtered out earlier, so the
         * remainder here are the ones which suffer RSBA behaviour.
         */
        setup_force_cpu_cap(X86_FEATURE_RSBA);
    }

    return safe;
}

/*
 * https://software.intel.com/content/www/us/en/develop/articles/software-security-guidance/technical-documentation/retpoline-branch-target-injection-mitigation.html
 *
 * Silvermont and Airmont based cores are 64bit but only have a 32bit wide
 * RSB, which impacts the safety of using SMEP to avoid RSB-overwriting.
 */
static bool __init rsb_is_full_width(void)
{
    if ( boot_cpu_data.x86_vendor != X86_VENDOR_INTEL ||
         boot_cpu_data.x86 != 6 )
        return true;

    switch ( boot_cpu_data.x86_model )
    {
    case 0x37: /* Baytrail / Valleyview (Silvermont) */
    case 0x4a: /* Merrifield */
    case 0x4c: /* Cherrytrail / Brasswell */
    case 0x4d: /* Avaton / Rangely (Silvermont) */
    case 0x5a: /* Moorefield */
    case 0x5d: /* SoFIA 3G Granite/ES2.1 */
    case 0x65: /* SoFIA LTE AOSP */
    case 0x6e: /* Cougar Mountain */
    case 0x75: /* Lightning Mountain */
        return false;
    }

    return true;
}

/* Calculate whether this CPU speculates past #NM */
static bool __init should_use_eager_fpu(void)
{
    /*
     * Assume all unrecognised processors are ok.  This is only known to
     * affect Intel Family 6 processors.
     */
    if ( boot_cpu_data.x86_vendor != X86_VENDOR_INTEL ||
         boot_cpu_data.x86 != 6 )
        return false;

    switch ( boot_cpu_data.x86_model )
    {
        /*
         * Core processors since at least Nehalem are vulnerable.
         */
    case 0x1e: /* Nehalem */
    case 0x1f: /* Auburndale / Havendale */
    case 0x1a: /* Nehalem EP */
    case 0x2e: /* Nehalem EX */
    case 0x25: /* Westmere */
    case 0x2c: /* Westmere EP */
    case 0x2f: /* Westmere EX */
    case 0x2a: /* SandyBridge */
    case 0x2d: /* SandyBridge EP/EX */
    case 0x3a: /* IvyBridge */
    case 0x3e: /* IvyBridge EP/EX */
    case 0x3c: /* Haswell */
    case 0x3f: /* Haswell EX/EP */
    case 0x45: /* Haswell D */
    case 0x46: /* Haswell H */
    case 0x3d: /* Broadwell */
    case 0x47: /* Broadwell H */
    case 0x4f: /* Broadwell EP/EX */
    case 0x56: /* Broadwell D */
    case 0x4e: /* Skylake M */
    case 0x55: /* Skylake X */
    case 0x5e: /* Skylake D */
    case 0x66: /* Cannonlake */
    case 0x67: /* Cannonlake? */
    case 0x8e: /* Kabylake M */
    case 0x9e: /* Kabylake D */
        return true;

        /*
         * Atom processors are not vulnerable.
         */
    case 0x1c: /* Pineview */
    case 0x26: /* Lincroft */
    case 0x27: /* Penwell */
    case 0x35: /* Cloverview */
    case 0x36: /* Cedarview */
    case 0x37: /* Baytrail / Valleyview (Silvermont) */
    case 0x4d: /* Avaton / Rangely (Silvermont) */
    case 0x4c: /* Cherrytrail / Brasswell */
    case 0x4a: /* Merrifield */
    case 0x5a: /* Moorefield */
    case 0x5c: /* Goldmont */
    case 0x5f: /* Denverton */
    case 0x7a: /* Gemini Lake */
        return false;

        /*
         * Knights processors are not vulnerable.
         */
    case 0x57: /* Knights Landing */
    case 0x85: /* Knights Mill */
        return false;

    default:
        printk("Unrecognised CPU model %#x - assuming vulnerable to LazyFPU\n",
               boot_cpu_data.x86_model);
        return true;
    }
}

static void __init srso_calculations(bool hw_smt_enabled)
{
    if ( !(boot_cpu_data.x86_vendor &
           (X86_VENDOR_AMD | X86_VENDOR_HYGON)) )
        return;

    /*
     * If virtualised, none of these heuristics are safe.  Trust the
     * hypervisor completely.
     */
    if ( cpu_has_hypervisor )
        return;

    if ( boot_cpu_data.x86 == 0x19 )
    {
        /*
         * We could have a table of models/microcode revisions.  ...or we
         * could just look for the new feature added.
         */
        if ( wrmsr_safe(MSR_PRED_CMD, PRED_CMD_SBPB) == 0 )
        {
            setup_force_cpu_cap(X86_FEATURE_IBPB_BRTYPE);
            setup_force_cpu_cap(X86_FEATURE_SBPB);
        }
        else
            printk(XENLOG_WARNING
                   "Vulnerable to SRSO, without suitable microcode to mitigate\n");
    }
    else if ( boot_cpu_data.x86 < 0x19 )
    {
        /*
         * Zen1/2 (which have the IBPB microcode) have IBPB_BRTYPE behaviour
         * already.
         *
         * Older CPUs are unknown, but their IBPB likely does flush branch
         * types too.  As we're synthesising for the benefit of guests, go
         * with the likely option - this avoids VMs running on e.g. a Zen3
         * thinking there's no SRSO mitigation available because it may
         * migrate to e.g. a Bulldozer.
         */
        if ( boot_cpu_has(X86_FEATURE_IBPB) )
            setup_force_cpu_cap(X86_FEATURE_IBPB_BRTYPE);
    }

    /*
     * In single-thread mode on Zen1/2, microarchitectural limits prevent SRSO
     * attacks from being effective.  Synthesise SRSO_NO if SMT is disabled in
     * hardware.
     *
     * Booting with smt=0, or using xen-hptool should be effective too, but
     * they can be altered at runtime so it's not safe to presume SRSO_NO.
     */
    if ( !hw_smt_enabled &&
         (boot_cpu_data.x86 == 0x17 || boot_cpu_data.x86 == 0x18) )
        setup_force_cpu_cap(X86_FEATURE_SRSO_NO);
}

/*
 * The Div leakage issue is specific to the AMD Zen1 microarchitecure.
 *
 * However, there's no $FOO_NO bit defined, so if we're virtualised we have no
 * hope of spotting the case where we might move to vulnerable hardware.  We
 * also can't make any useful conclusion about SMT-ness.
 *
 * Don't check the hypervisor bit, so at least we do the safe thing when
 * booting on something that looks like a Zen1 CPU.
 */
static bool __init has_div_vuln(void)
{
    if ( !(boot_cpu_data.x86_vendor &
           (X86_VENDOR_AMD | X86_VENDOR_HYGON)) )
        return false;

    if ( boot_cpu_data.x86 != 0x17 && boot_cpu_data.x86 != 0x18 )
        return false;

    return is_zen1_uarch();
}

static void __init div_calculations(bool hw_smt_enabled)
{
    bool cpu_bug_div = has_div_vuln();

    if ( opt_div_scrub == -1 )
        opt_div_scrub = cpu_bug_div;

    if ( opt_div_scrub )
        setup_force_cpu_cap(X86_FEATURE_SC_DIV);

    if ( opt_smt == -1 && !cpu_has_hypervisor && cpu_bug_div && hw_smt_enabled )
        warning_add(
            "Booted on leaky-DIV hardware with SMT/Hyperthreading\n"
            "enabled.  Please assess your configuration and choose an\n"
            "explicit 'smt=<bool>' setting.  See XSA-439.\n");
}

static void __init ibpb_calculations(void)
{
    bool def_ibpb_entry = false;

    /* Check we have hardware IBPB support before using it... */
    if ( !boot_cpu_has(X86_FEATURE_IBRSB) && !boot_cpu_has(X86_FEATURE_IBPB) )
    {
        opt_ibpb_entry_hvm = opt_ibpb_entry_pv = opt_ibpb_ctxt_switch = 0;
        opt_ibpb_entry_dom0 = false;
        return;
    }

    if ( boot_cpu_data.x86_vendor & (X86_VENDOR_AMD | X86_VENDOR_HYGON) )
    {
        /*
         * AMD/Hygon CPUs to date (June 2022) don't flush the RAS.  Future
         * CPUs are expected to enumerate IBPB_RET when this has been fixed.
         * Until then, cover the difference with the software sequence.
         */
        if ( !boot_cpu_has(X86_FEATURE_IBPB_RET) )
            setup_force_cpu_cap(X86_BUG_IBPB_NO_RET);

        /*
         * AMD/Hygon CPUs up to and including Zen2 suffer from Branch Type
         * Confusion.  Mitigate with IBPB-on-entry.
         */
        if ( !boot_cpu_has(X86_FEATURE_BTC_NO) )
            def_ibpb_entry = true;

        /*
         * Further to BTC, Zen3/4 CPUs suffer from Speculative Return Stack
         * Overflow in most configurations.  Mitigate with IBPB-on-entry if we
         * have the microcode that makes this an effective option.
         */
        if ( !boot_cpu_has(X86_FEATURE_SRSO_NO) &&
             boot_cpu_has(X86_FEATURE_IBPB_BRTYPE) )
            def_ibpb_entry = true;
    }

    if ( opt_ibpb_entry_pv == -1 )
        opt_ibpb_entry_pv = IS_ENABLED(CONFIG_PV) && def_ibpb_entry;
    if ( opt_ibpb_entry_hvm == -1 )
        opt_ibpb_entry_hvm = IS_ENABLED(CONFIG_HVM) && def_ibpb_entry;

    if ( opt_ibpb_entry_pv )
    {
        setup_force_cpu_cap(X86_FEATURE_IBPB_ENTRY_PV);

        /*
         * We only need to flush in IST context if we're protecting against PV
         * guests.  HVM IBPB-on-entry protections are both atomic with
         * NMI/#MC, so can't interrupt Xen ahead of having already flushed the
         * BTB.
         */
        default_spec_ctrl_flags |= SCF_ist_ibpb;
    }
    if ( opt_ibpb_entry_hvm )
        setup_force_cpu_cap(X86_FEATURE_IBPB_ENTRY_HVM);

    /*
     * If we're using IBPB-on-entry to protect against PV and HVM guests
     * (ignoring dom0 if trusted), then there's no need to also issue IBPB on
     * context switch too.
     */
    if ( opt_ibpb_ctxt_switch == -1 )
        opt_ibpb_ctxt_switch = !(opt_ibpb_entry_hvm && opt_ibpb_entry_pv);
}

/* Calculate whether this CPU is vulnerable to L1TF. */
static __init void l1tf_calculations(void)
{
    bool hit_default = false;

    l1d_maxphysaddr = paddr_bits;

    /* L1TF is only known to affect Intel Family 6 processors at this time. */
    if ( boot_cpu_data.x86_vendor == X86_VENDOR_INTEL &&
         boot_cpu_data.x86 == 6 )
    {
        switch ( boot_cpu_data.x86_model )
        {
            /*
             * Core processors since at least Penryn are vulnerable.
             */
        case 0x17: /* Penryn */
        case 0x1d: /* Dunnington */
            cpu_has_bug_l1tf = true;
            break;

        case 0x1f: /* Auburndale / Havendale */
        case 0x1e: /* Nehalem */
        case 0x1a: /* Nehalem EP */
        case 0x2e: /* Nehalem EX */
        case 0x25: /* Westmere */
        case 0x2c: /* Westmere EP */
        case 0x2f: /* Westmere EX */
            cpu_has_bug_l1tf = true;
            l1d_maxphysaddr = 44;
            break;

        case 0x2a: /* SandyBridge */
        case 0x2d: /* SandyBridge EP/EX */
        case 0x3a: /* IvyBridge */
        case 0x3e: /* IvyBridge EP/EX */
        case 0x3c: /* Haswell */
        case 0x3f: /* Haswell EX/EP */
        case 0x45: /* Haswell D */
        case 0x46: /* Haswell H */
        case 0x3d: /* Broadwell */
        case 0x47: /* Broadwell H */
        case 0x4f: /* Broadwell EP/EX */
        case 0x56: /* Broadwell D */
        case 0x4e: /* Skylake M */
        case 0x55: /* Skylake X */
        case 0x5e: /* Skylake D */
        case 0x66: /* Cannonlake */
        case 0x67: /* Cannonlake? */
        case 0x8e: /* Kabylake M */
        case 0x9e: /* Kabylake D */
            cpu_has_bug_l1tf = true;
            l1d_maxphysaddr = 46;
            break;

            /*
             * Atom processors are not vulnerable.
             */
        case 0x1c: /* Pineview */
        case 0x26: /* Lincroft */
        case 0x27: /* Penwell */
        case 0x35: /* Cloverview */
        case 0x36: /* Cedarview */
        case 0x37: /* Baytrail / Valleyview (Silvermont) */
        case 0x4d: /* Avaton / Rangely (Silvermont) */
        case 0x4c: /* Cherrytrail / Brasswell */
        case 0x4a: /* Merrifield */
        case 0x5a: /* Moorefield */
        case 0x5c: /* Goldmont */
        case 0x5f: /* Denverton */
        case 0x7a: /* Gemini Lake */
            break;

            /*
             * Knights processors are not vulnerable.
             */
        case 0x57: /* Knights Landing */
        case 0x85: /* Knights Mill */
            break;

        default:
            /* Defer printk() until we've accounted for RDCL_NO. */
            hit_default = true;
            cpu_has_bug_l1tf = true;
            break;
        }
    }

    /* Any processor advertising RDCL_NO should be not vulnerable to L1TF. */
    if ( cpu_has_rdcl_no )
        cpu_has_bug_l1tf = false;

    if ( cpu_has_bug_l1tf && hit_default )
        printk("Unrecognised CPU model %#x - assuming vulnerable to L1TF\n",
               boot_cpu_data.x86_model);

    /*
     * L1TF safe address heuristics.  These apply to the real hardware we are
     * running on, and are best-effort-only if Xen is virtualised.
     *
     * The address mask which the L1D cache uses, which might be wider than
     * the CPUID-reported maxphysaddr.
     */
    l1tf_addr_mask = ((1UL << l1d_maxphysaddr) - 1) & PAGE_MASK;

    /*
     * To be safe, l1tf_safe_maddr must be above the highest cacheable entity
     * in system physical address space.  However, to preserve space for
     * paged-out metadata, it should be as low as possible above the highest
     * cacheable address, so as to require fewer high-order bits being set.
     *
     * These heuristics are based on some guesswork to improve the likelihood
     * of safety in the common case, including Linux's L1TF mitigation of
     * inverting all address bits in a non-present PTE.
     *
     * - If L1D is wider than CPUID (Nehalem and later mobile/desktop/low end
     *   server), setting any address bit beyond CPUID maxphysaddr guarantees
     *   to make the PTE safe.  This case doesn't require all the high-order
     *   bits being set, and doesn't require any other source of information
     *   for safety.
     *
     * - If L1D is the same as CPUID (Pre-Nehalem, or high end server), we
     *   must sacrifice high order bits from the real address space for
     *   safety.  Therefore, make a blind guess that there is nothing
     *   cacheable in the top quarter of physical address space.
     *
     *   It is exceedingly unlikely for machines to be populated with this
     *   much RAM (likely 512G on pre-Nehalem, 16T on Nehalem/Westmere, 64T on
     *   Sandybridge and later) due to the sheer volume of DIMMs this would
     *   actually take.
     *
     *   However, it is possible to find machines this large, so the "top
     *   quarter" guess is supplemented to push the limit higher if references
     *   to cacheable mappings (E820/SRAT/EFI/etc) are found above the top
     *   quarter boundary.
     *
     *   Finally, this top quarter guess gives us a good chance of being safe
     *   when running virtualised (and the CPUID maxphysaddr hasn't been
     *   levelled for heterogeneous migration safety), where the safety
     *   consideration is still in terms of host details, but all E820/etc
     *   information is in terms of guest physical layout.
     */
    l1tf_safe_maddr = max(l1tf_safe_maddr, ((l1d_maxphysaddr > paddr_bits)
                                            ? (1UL << paddr_bits)
                                            : (3UL << (paddr_bits - 2))));
}

/* Calculate whether this CPU is vulnerable to MDS. */
static __init void mds_calculations(void)
{
    /* MDS is only known to affect Intel Family 6 processors at this time. */
    if ( boot_cpu_data.x86_vendor != X86_VENDOR_INTEL ||
         boot_cpu_data.x86 != 6 )
        return;

    /* Any processor advertising MDS_NO should be not vulnerable to MDS. */
    if ( cpu_has_mds_no )
        return;

    switch ( boot_cpu_data.x86_model )
    {
        /*
         * Core processors since at least Nehalem are vulnerable.
         */
    case 0x1f: /* Auburndale / Havendale */
    case 0x1e: /* Nehalem */
    case 0x1a: /* Nehalem EP */
    case 0x2e: /* Nehalem EX */
    case 0x25: /* Westmere */
    case 0x2c: /* Westmere EP */
    case 0x2f: /* Westmere EX */
    case 0x2a: /* SandyBridge */
    case 0x2d: /* SandyBridge EP/EX */
    case 0x3a: /* IvyBridge */
    case 0x3e: /* IvyBridge EP/EX */
    case 0x3c: /* Haswell */
    case 0x3f: /* Haswell EX/EP */
    case 0x45: /* Haswell D */
    case 0x46: /* Haswell H */
    case 0x3d: /* Broadwell */
    case 0x47: /* Broadwell H */
    case 0x4f: /* Broadwell EP/EX */
    case 0x56: /* Broadwell D */
    case 0x4e: /* Skylake M */
    case 0x5e: /* Skylake D */
        cpu_has_bug_mds = true;
        break;

        /*
         * Some Core processors have per-stepping vulnerability.
         */
    case 0x55: /* Skylake-X / Cascade Lake */
        if ( boot_cpu_data.x86_mask <= 5 )
            cpu_has_bug_mds = true;
        break;

    case 0x8e: /* Kaby / Coffee / Whiskey Lake M */
        if ( boot_cpu_data.x86_mask <= 0xb )
            cpu_has_bug_mds = true;
        break;

    case 0x9e: /* Kaby / Coffee / Whiskey Lake D */
        if ( boot_cpu_data.x86_mask <= 0xc )
            cpu_has_bug_mds = true;
        break;

        /*
         * Very old and very new Atom processors are not vulnerable.
         */
    case 0x1c: /* Pineview */
    case 0x26: /* Lincroft */
    case 0x27: /* Penwell */
    case 0x35: /* Cloverview */
    case 0x36: /* Cedarview */
    case 0x7a: /* Goldmont */
        break;

        /*
         * Middling Atom processors are vulnerable to just the Store Buffer
         * aspect.
         */
    case 0x37: /* Baytrail / Valleyview (Silvermont) */
    case 0x4a: /* Merrifield */
    case 0x4c: /* Cherrytrail / Brasswell */
    case 0x4d: /* Avaton / Rangely (Silvermont) */
    case 0x5a: /* Moorefield */
    case 0x5d: /* SoFIA 3G Granite/ES2.1 */
    case 0x65: /* SoFIA LTE AOSP */
    case 0x6e: /* Cougar Mountain */
    case 0x75: /* Lightning Mountain */
        /*
         * Knights processors (which are based on the Silvermont/Airmont
         * microarchitecture) are similarly only affected by the Store Buffer
         * aspect.
         */
    case 0x57: /* Knights Landing */
    case 0x85: /* Knights Mill */
        cpu_has_bug_msbds_only = true;
        break;

    default:
        printk("Unrecognised CPU model %#x - assuming vulnerable to MDS\n",
               boot_cpu_data.x86_model);
        cpu_has_bug_mds = true;
        break;
    }
}

static bool __init cpu_has_gds(void)
{
    /*
     * Any part advertising GDS_NO should be not vulnerable to GDS.  This
     * includes cases where the hypervisor is mitigating behind our backs, or
     * has synthesized GDS_NO on older parts for levelling purposes.
     */
    if ( cpu_has_gds_no )
        return false;

    /*
     * On real hardware the GDS_CTRL control only exists on parts vulnerable
     * to GDS and with up-to-date microcode.  It might also be virtualised by
     * an aware hypervisor, meaning "somewhere you might migrate to is
     * vulnerable".
     */
    if ( cpu_has_gds_ctrl )
        return true;

    /*
     * An attacker requires the use of the AVX2 GATHER instructions to leak
     * data with GDS.  However, the only way to block those instructions is to
     * prevent XCR0[2] from being set, which is original AVX.  A hypervisor
     * might do this as a stopgap mitigation.
     */
    if ( !cpu_has_avx )
        return false;

    /*
     * GDS affects the Core line from Skylake up to but not including Golden
     * Cove (Alder Lake, Sapphire Rapids).  Broadwell and older, and the Atom
     * line, and all hybrid parts are unaffected.
     */
    switch ( boot_cpu_data.x86_model )
    {
    case 0x55: /* Skylake/Cascade Lake/Cooper Lake SP */
    case 0x6a: /* Ice Lake SP */
    case 0x6c: /* Ice Lake D */
    case 0x7e: /* Ice Lake U/Y */
    case 0x8c: /* Tiger Lake U */
    case 0x8d: /* Tiger Lake H */
    case 0x8e: /* Amber/Kaby/Coffee/Whiskey/Comet lake U/Y */
    case 0x9e: /* Kaby/Coffee lake H/S/Xeon */
    case 0xa5: /* Comet Lake H/S */
    case 0xa6: /* Comet Lake U */
    case 0xa7: /* Rocket Lake */
        return true;

    default:
        /*
         * If we've got here and are virtualised, we're most likely under a
         * hypervisor unaware of GDS at which point we've lost.  Err on the
         * safe side.
         */
        return cpu_has_hypervisor;
    }
}

static void __init gds_calculations(void)
{
    bool cpu_has_bug_gds, mitigated = false;

    /* GDS is only known to affect Intel Family 6 processors at this time. */
    if ( boot_cpu_data.x86_vendor != X86_VENDOR_INTEL ||
         boot_cpu_data.x86 != 6 )
        return;

    cpu_has_bug_gds = cpu_has_gds();

    /*
     * If we've got GDS_CTRL, we're either native with up-to-date microcode on
     * a GDS-vulnerable part, or virtualised under a GDS-aware hypervisor.
     */
    if ( cpu_has_gds_ctrl )
    {
        bool locked;
        uint64_t opt_ctrl;

        if ( cpu_has_gds_no )
        {
            /*
             * We don't expect to ever see GDS_CTL and GDS_NO set together.
             * Complain loudly, and forgo playing with other features.
             */
            printk(XENLOG_ERR
                   "FIRMWARE BUG: CPU %02x-%02x-%02x, ucode 0x%08x: GDS_CTRL && GDS_NO\n",
                   boot_cpu_data.x86, boot_cpu_data.x86_model,
                   boot_cpu_data.x86_mask, this_cpu(cpu_sig).rev);
            return add_taint(TAINT_CPU_OUT_OF_SPEC);
        }

        rdmsrl(MSR_MCU_OPT_CTRL, opt_ctrl);

        mitigated = !(opt_ctrl & MCU_OPT_CTRL_GDS_MIT_DIS);
        locked    =   opt_ctrl & MCU_OPT_CTRL_GDS_MIT_LOCK;

        /*
         * Firmware will lock the GDS mitigation if e.g. SGX is active.
         * Alternatively, a hypervisor might virtualise GDS_CTRL as locked.
         * Warn if the mitigiation is locked and the user requested the
         * opposite configuration.
         */
        if ( locked )
        {
            if ( opt_gds_mit >= 0 && opt_gds_mit != mitigated )
                printk(XENLOG_WARNING
                       "GDS_MIT locked by firwmare - ignoring spec-ctrl=gds-mit setting\n");
            opt_gds_mit = mitigated;
        }
        else if ( opt_gds_mit == -1 )
            opt_gds_mit = cpu_has_bug_gds; /* Mitigate GDS by default */

        /*
         * Latch our choice of GDS_MIT for all CPUs to pick up.  If LOCK is
         * set, we latch the same value as it currently holds.
         */
        set_in_mcu_opt_ctrl(MCU_OPT_CTRL_GDS_MIT_DIS,
                            opt_gds_mit ? 0 : MCU_OPT_CTRL_GDS_MIT_DIS);
        mitigated = opt_gds_mit;
    }
    else if ( opt_gds_mit == -1 )
        opt_gds_mit = cpu_has_bug_gds; /* Mitigate GDS by default */

    /*
     * If we think we're not on vulnerable hardware, or we've mitigated GDS,
     * synthesize GDS_NO.  This is mostly for the benefit of guests, to inform
     * them not to panic.
     */
    if ( !cpu_has_bug_gds || mitigated )
        return setup_force_cpu_cap(X86_FEATURE_GDS_NO);

    /*
     * If all else has failed, mitigate by disabling AVX.  This prevents
     * guests from enabling %xcr0.ymm, thereby blocking the use of VGATHER
     * instructions.
     *
     * There's at least one affected CPU not expected to recieve a microcode
     * update, and this is the only remaining mitigation.
     *
     * If we're virtualised, this prevents our guests attacking each other,
     * but it doesn't stop the outer hypervisor's guests attacking us.  Leave
     * a note to this effect.
     */
    if ( cpu_has_avx && opt_gds_mit )
    {
        setup_clear_cpu_cap(X86_FEATURE_AVX);
        printk(XENLOG_WARNING "Mitigating GDS by disabling AVX%s\n",
               cpu_has_hypervisor ?
               " while virtualised - protections are best-effort" : "");
    }
}

void spec_ctrl_init_domain(struct domain *d)
{
    bool pv = is_pv_domain(d);

    bool verw = ((pv ? opt_md_clear_pv : opt_md_clear_hvm) ||
                 (opt_fb_clear_mmio && is_iommu_enabled(d)));

    bool ibpb = ((pv ? opt_ibpb_entry_pv : opt_ibpb_entry_hvm) &&
                 (d->domain_id != 0 || opt_ibpb_entry_dom0));

    d->arch.spec_ctrl_flags =
        (verw   ? SCF_verw         : 0) |
        (ibpb   ? SCF_entry_ibpb   : 0) |
        0;
}

void __init init_speculation_mitigations(void)
{
    enum ind_thunk thunk = THUNK_DEFAULT;
    bool has_spec_ctrl, ibrs = false, hw_smt_enabled;
    bool cpu_has_bug_taa, retpoline_safe;

    hw_smt_enabled = check_smt_enabled();

    has_spec_ctrl = (boot_cpu_has(X86_FEATURE_IBRSB) ||
                     boot_cpu_has(X86_FEATURE_IBRS));

    /*
     * First, disable the use of retpolines if Xen is using CET.  Retpolines
     * are a ROP gadget so incompatbile with Shadow Stacks, while IBT depends
     * on executing indirect branches for the safety properties to apply.
     *
     * In the absence of retpolines, IBRS needs to be used for speculative
     * safety.  All CET-capable hardware has efficient IBRS.
     */
    if ( read_cr4() & X86_CR4_CET )
    {
        if ( !has_spec_ctrl )
        {
            printk(XENLOG_WARNING "?!? CET active, but no MSR_SPEC_CTRL?\n");
            add_taint(TAINT_CPU_OUT_OF_SPEC);
        }
        else if ( opt_ibrs == -1 )
            opt_ibrs = ibrs = true;

        if ( opt_thunk == THUNK_DEFAULT || opt_thunk == THUNK_RETPOLINE )
            thunk = THUNK_JMP;
    }

    /* Determine if retpoline is safe on this CPU.  Fix up RSBA/RRSBA enumerations. */
    retpoline_safe = retpoline_calculations();

    /*
     * Has the user specified any custom BTI mitigations?  If so, follow their
     * instructions exactly and disable all heuristics.
     */
    if ( opt_thunk != THUNK_DEFAULT || opt_ibrs != -1 )
    {
        thunk = opt_thunk;
        ibrs  = !!opt_ibrs;
    }
    else
    {
        /*
         * Evaluate the safest Branch Target Injection mitigations to use.
         * First, begin with compiler-aided mitigations.
         */
        if ( IS_ENABLED(CONFIG_INDIRECT_THUNK) )
        {
            /*
             * On all hardware, we'd like to use retpoline in preference to
             * IBRS, but only if it is safe on this hardware.
             */
            if ( retpoline_safe )
                thunk = THUNK_RETPOLINE;
            else if ( has_spec_ctrl )
                ibrs = true;
        }
        /* Without compiler thunk support, use IBRS if available. */
        else if ( has_spec_ctrl )
            ibrs = true;
    }

    /*
     * Supplimentary minor adjustments.  Without compiler support, there are
     * no thunks.
     */
    if ( !IS_ENABLED(CONFIG_INDIRECT_THUNK) )
        thunk = THUNK_NONE;

    /*
     * If IBRS is in use and thunks are compiled in, there is no point
     * suffering extra overhead.  Switch to the least-overhead thunk.
     */
    if ( ibrs && thunk == THUNK_DEFAULT )
        thunk = THUNK_JMP;

    /*
     * If there are still no thunk preferences, the compiled default is
     * actually retpoline, and it is better than nothing.
     */
    if ( thunk == THUNK_DEFAULT )
        thunk = THUNK_RETPOLINE;

    /* Apply the chosen settings. */
    if ( thunk == THUNK_LFENCE )
        setup_force_cpu_cap(X86_FEATURE_IND_THUNK_LFENCE);
    else if ( thunk == THUNK_JMP )
        setup_force_cpu_cap(X86_FEATURE_IND_THUNK_JMP);

    /* Intel hardware: MSR_SPEC_CTRL alternatives setup. */
    if ( boot_cpu_has(X86_FEATURE_IBRSB) )
    {
        if ( opt_msr_sc_pv )
        {
            default_spec_ctrl_flags |= SCF_ist_sc_msr;
            setup_force_cpu_cap(X86_FEATURE_SC_MSR_PV);
        }

        if ( opt_msr_sc_hvm )
        {
            /*
             * While the guest MSR_SPEC_CTRL value is loaded/saved atomically,
             * Xen's value is not restored atomically.  An early NMI hitting
             * the VMExit path needs to restore Xen's value for safety.
             */
            default_spec_ctrl_flags |= SCF_ist_sc_msr;
            setup_force_cpu_cap(X86_FEATURE_SC_MSR_HVM);
        }
    }

    /* AMD hardware: MSR_SPEC_CTRL alternatives setup. */
    if ( boot_cpu_has(X86_FEATURE_IBRS) )
    {
        /*
         * Virtualising MSR_SPEC_CTRL for guests depends on SVM support, which
         * on real hardware matches the availability of MSR_SPEC_CTRL in the
         * first place.
         *
         * No need for SCF_ist_sc_msr because Xen's value is restored
         * atomically WRT NMIs in the VMExit path.
         *
         * TODO: Adjust cpu_has_svm_spec_ctrl to be usable earlier on boot.
         */
        if ( opt_msr_sc_hvm &&
             (boot_cpu_data.extended_cpuid_level >= 0x8000000a) &&
             (cpuid_edx(0x8000000a) & (1u << SVM_FEATURE_SPEC_CTRL)) )
            setup_force_cpu_cap(X86_FEATURE_SC_MSR_HVM);
    }

    /* Support VIRT_SPEC_CTRL.SSBD if AMD_SSBD is not available. */
    if ( opt_msr_sc_hvm && !cpu_has_amd_ssbd &&
         (cpu_has_virt_ssbd || (amd_legacy_ssbd && amd_setup_legacy_ssbd())) )
        amd_virt_spec_ctrl = true;

    /* Figure out default_xen_spec_ctrl. */
    if ( has_spec_ctrl && ibrs )
    {
        /* IBRS implies STIBP.  */
        if ( opt_stibp == -1 )
            opt_stibp = 1;

        default_xen_spec_ctrl |= SPEC_CTRL_IBRS;
    }

    /*
     * Use STIBP by default on all AMD systems.  Zen3 and later enumerate
     * STIBP_ALWAYS, but STIBP is needed on Zen2 as part of the mitigations
     * for Branch Type Confusion.
     *
     * Leave STIBP off by default on Intel.  Pre-eIBRS systems suffer a
     * substantial perf hit when it was implemented in microcode.
     */
    if ( opt_stibp == -1 )
        opt_stibp = !!boot_cpu_has(X86_FEATURE_AMD_STIBP);

    if ( opt_stibp && (boot_cpu_has(X86_FEATURE_STIBP) ||
                       boot_cpu_has(X86_FEATURE_AMD_STIBP)) )
        default_xen_spec_ctrl |= SPEC_CTRL_STIBP;

    if ( opt_ssbd && (boot_cpu_has(X86_FEATURE_SSBD) ||
                      boot_cpu_has(X86_FEATURE_AMD_SSBD)) )
    {
        /* SSBD implies PSFD */
        if ( opt_psfd == -1 )
            opt_psfd = 1;

        default_xen_spec_ctrl |= SPEC_CTRL_SSBD;
    }

    /*
     * Don't use PSFD by default.  AMD designed the predictor to
     * auto-clear on privilege change.  PSFD is implied by SSBD, which is
     * off by default.
     */
    if ( opt_psfd == -1 )
        opt_psfd = 0;

    if ( opt_psfd && (boot_cpu_has(X86_FEATURE_PSFD) ||
                      boot_cpu_has(X86_FEATURE_INTEL_PSFD)) )
        default_xen_spec_ctrl |= SPEC_CTRL_PSFD;

    /*
     * PV guests can create RSB entries for any linear address they control,
     * which are outside of Xen's mappings.
     *
     * SMEP inhibits speculation to any user mappings, so in principle it is
     * safe to not overwrite the RSB when SMEP is active.
     *
     * However, some caveats apply:
     *
     * 1) CALL instructions push the next sequential linear address into the
     *    RSB, meaning that there is a boundary case at the user=>supervisor
     *    split.  This can be compensated for by having an unmapped or NX
     *    page, or an instruction which halts speculation.
     *
     *    For Xen, the next sequential linear address is the start of M2P
     *    (mapped NX), or a zapped hole (unmapped).
     *
     * 2) 32bit PV kernels execute in Ring 1 and use supervisor mappings.
     *    SMEP offers no protection in this case.
     *
     * 3) Some CPUs have RSBs which are not full width, which allow the
     *    attacker's entries to alias Xen addresses.
     *
     * 4) Some CPUs have RSBs which are re-partitioned based on thread
     *    idleness, which allows an attacker to inject entries into the other
     *    thread.  We still active the optimisation in this case, and mitigate
     *    in the idle path which has lower overhead.
     *
     * It is safe to turn off RSB stuffing when Xen is using SMEP itself, and
     * 32bit PV guests are disabled, and when the RSB is full width.
     */
    BUILD_BUG_ON(RO_MPT_VIRT_START != PML4_ADDR(256));
    if ( opt_rsb_pv == -1 )
    {
        opt_rsb_pv = (opt_pv32 || !boot_cpu_has(X86_FEATURE_XEN_SMEP) ||
                      !rsb_is_full_width());

        /*
         * Cross-Thread Return Address Predictions.
         *
         * Vulnerable systems are Zen1/Zen2 uarch, which is AMD Fam17 / Hygon
         * Fam18, when SMT is active.
         *
         * To mitigate, we must flush the RSB/RAS/RAP once between entering
         * Xen and going idle.
         *
         * Most cases flush on entry to Xen anyway.  The one case where we
         * don't is when using the SMEP optimisation for PV guests.  Flushing
         * before going idle is less overhead than flushing on PV entry.
         */
        if ( !opt_rsb_pv && hw_smt_enabled &&
             (boot_cpu_data.x86_vendor & (X86_VENDOR_AMD|X86_VENDOR_HYGON)) &&
             (boot_cpu_data.x86 == 0x17 || boot_cpu_data.x86 == 0x18) )
            setup_force_cpu_cap(X86_FEATURE_SC_RSB_IDLE);
    }

    if ( opt_rsb_pv )
    {
        setup_force_cpu_cap(X86_FEATURE_SC_RSB_PV);
        default_spec_ctrl_flags |= SCF_ist_rsb;
    }

    /*
     * HVM guests can always poison the RSB to point at Xen supervisor
     * mappings.
     */
    if ( opt_rsb_hvm )
    {
        setup_force_cpu_cap(X86_FEATURE_SC_RSB_HVM);

        /*
         * For SVM, Xen's RSB safety actions are performed before STGI, so
         * behave atomically with respect to IST sources.
         *
         * For VT-x, NMIs are atomic with VMExit (the NMI gets queued but not
         * delivered) whereas other IST sources are not atomic.  Specifically,
         * #MC can hit ahead the RSB safety action in the vmexit path.
         *
         * Therefore, it is necessary for the IST logic to protect Xen against
         * possible rogue RSB speculation.
         */
        if ( !cpu_has_svm )
            default_spec_ctrl_flags |= SCF_ist_rsb;
    }

    srso_calculations(hw_smt_enabled);

    ibpb_calculations();

    div_calculations(hw_smt_enabled);

    /* Check whether Eager FPU should be enabled by default. */
    if ( opt_eager_fpu == -1 )
        opt_eager_fpu = should_use_eager_fpu();

    /* (Re)init BSP state now that default_spec_ctrl_flags has been calculated. */
    init_shadow_spec_ctrl_state();

    /*
     * For microcoded IBRS only (i.e. Intel, pre eIBRS), it is recommended to
     * clear MSR_SPEC_CTRL before going idle, to avoid impacting sibling
     * threads.  Activate this if SMT is enabled, and Xen is using a non-zero
     * MSR_SPEC_CTRL setting.
     */
    if ( boot_cpu_has(X86_FEATURE_IBRSB) && !cpu_has_eibrs &&
         hw_smt_enabled && default_xen_spec_ctrl )
        setup_force_cpu_cap(X86_FEATURE_SC_MSR_IDLE);

    xpti_init_default();

    l1tf_calculations();

    /*
     * By default, enable PV domU L1TF mitigations on all L1TF-vulnerable
     * hardware, except when running in shim mode.
     *
     * In shim mode, SHADOW is expected to be compiled out, and a malicious
     * guest kernel can only attack the shim Xen, not the host Xen.
     */
    if ( opt_pv_l1tf_hwdom == -1 )
        opt_pv_l1tf_hwdom = 0;
    if ( opt_pv_l1tf_domu == -1 )
        opt_pv_l1tf_domu = !pv_shim && cpu_has_bug_l1tf;

    /*
     * By default, enable L1D_FLUSH on L1TF-vulnerable hardware, unless
     * instructed to skip the flush on vmentry by our outer hypervisor.
     */
    if ( !boot_cpu_has(X86_FEATURE_L1D_FLUSH) )
        opt_l1d_flush = 0;
    else if ( opt_l1d_flush == -1 )
        opt_l1d_flush = cpu_has_bug_l1tf && !cpu_has_skip_l1dfl;

    /* We compile lfence's in by default, and nop them out if requested. */
    if ( !opt_branch_harden )
        setup_force_cpu_cap(X86_FEATURE_SC_NO_BRANCH_HARDEN);

    /*
     * We do not disable HT by default on affected hardware.
     *
     * Firstly, if the user intends to use exclusively PV, or HVM shadow
     * guests, HT isn't a concern and should remain fully enabled.  Secondly,
     * safety for HVM HAP guests can be arranged by the toolstack with core
     * parking, pinning or cpupool configurations, including mixed setups.
     *
     * However, if we are on affected hardware, with HT enabled, and the user
     * hasn't explicitly chosen whether to use HT or not, nag them to do so.
     */
    if ( opt_smt == -1 && cpu_has_bug_l1tf && !pv_shim && hw_smt_enabled )
        warning_add(
            "Booted on L1TF-vulnerable hardware with SMT/Hyperthreading\n"
            "enabled.  Please assess your configuration and choose an\n"
            "explicit 'smt=<bool>' setting.  See XSA-273.\n");

    mds_calculations();

    /*
     * Parts which enumerate FB_CLEAR are those which are post-MDS_NO and have
     * reintroduced the VERW fill buffer flushing side effect because of a
     * susceptibility to FBSDP.
     *
     * If unprivileged guests have (or will have) MMIO mappings, we can
     * mitigate cross-domain leakage of fill buffer data by issuing VERW on
     * the return-to-guest path.
     */
    if ( opt_unpriv_mmio )
        opt_fb_clear_mmio = cpu_has_fb_clear;

    /*
     * By default, enable PV and HVM mitigations on MDS-vulnerable hardware.
     * This will only be a token effort for MLPDS/MFBDS when HT is enabled,
     * but it is somewhat better than nothing.
     */
    if ( opt_md_clear_pv == -1 )
        opt_md_clear_pv = ((cpu_has_bug_mds || cpu_has_bug_msbds_only) &&
                           boot_cpu_has(X86_FEATURE_MD_CLEAR));
    if ( opt_md_clear_hvm == -1 )
        opt_md_clear_hvm = ((cpu_has_bug_mds || cpu_has_bug_msbds_only) &&
                            boot_cpu_has(X86_FEATURE_MD_CLEAR));

    /*
     * Enable MDS/MMIO defences as applicable.  The Idle blocks need using if
     * either the PV or HVM MDS defences are used, or if we may give MMIO
     * access to untrusted guests.
     *
     * HVM is more complicated.  The MD_CLEAR microcode extends L1D_FLUSH with
     * equivalent semantics to avoid needing to perform both flushes on the
     * HVM path.  Therefore, we don't need VERW in addition to L1D_FLUSH (for
     * MDS mitigations.  L1D_FLUSH is not safe for MMIO mitigations.)
     *
     * After calculating the appropriate idle setting, simplify
     * opt_md_clear_hvm to mean just "should we VERW on the way into HVM
     * guests", so spec_ctrl_init_domain() can calculate suitable settings.
     */
    if ( opt_md_clear_pv || opt_md_clear_hvm || opt_fb_clear_mmio )
        setup_force_cpu_cap(X86_FEATURE_SC_VERW_IDLE);
    opt_md_clear_hvm &= !cpu_has_skip_l1dfl && !opt_l1d_flush;

    /*
     * Warn the user if they are on MLPDS/MFBDS-vulnerable hardware with HT
     * active and no explicit SMT choice.
     */
    if ( opt_smt == -1 && cpu_has_bug_mds && hw_smt_enabled )
        warning_add(
            "Booted on MLPDS/MFBDS-vulnerable hardware with SMT/Hyperthreading\n"
            "enabled.  Mitigations will not be fully effective.  Please\n"
            "choose an explicit smt=<bool> setting.  See XSA-297.\n");

    /*
     * Vulnerability to TAA is a little complicated to quantify.
     *
     * In the pipeline, it is just another way to get speculative access to
     * stale load port, store buffer or fill buffer data, and therefore can be
     * considered a superset of MDS (on TSX-capable parts).  On parts which
     * predate MDS_NO, the existing VERW flushing will mitigate this
     * sidechannel as well.
     *
     * On parts which contain MDS_NO, the lack of VERW flushing means that an
     * attacker can still use TSX to target microarchitectural buffers to leak
     * secrets.  Therefore, we consider TAA to be the set of TSX-capable parts
     * which have MDS_NO but lack TAA_NO.
     *
     * Note: cpu_has_rtm (== hle) could already be hidden by `tsx=0` on the
     *       cmdline.  MSR_TSX_CTRL will only appear on TSX-capable parts, so
     *       we check both to spot TSX in a microcode/cmdline independent way.
     */
    cpu_has_bug_taa =
        (cpu_has_rtm || cpu_has_tsx_ctrl) && cpu_has_mds_no && !cpu_has_taa_no;

    /*
     * On TAA-affected hardware, disabling TSX is the preferred mitigation, vs
     * the MDS mitigation of disabling HT and using VERW flushing.
     *
     * On CPUs which advertise MDS_NO, VERW has no flushing side effect until
     * the TSX_CTRL microcode (Nov 2019), despite the MD_CLEAR CPUID bit being
     * advertised, and there isn't a MD_CLEAR_2 flag to use...
     *
     * Furthermore, the VERW flushing side effect is removed again on client
     * parts with the Feb 2022 microcode.
     *
     * If we're on affected hardware, able to do something about it (which
     * implies that VERW might work), no explicit TSX choice and traditional
     * MDS mitigations (no-SMT, VERW) not obviosuly in use (someone might
     * plausibly value TSX higher than Hyperthreading...), disable TSX to
     * mitigate TAA.
     */
    if ( opt_tsx == -1 && cpu_has_bug_taa && cpu_has_tsx_ctrl &&
         ((hw_smt_enabled && opt_smt) ||
          !boot_cpu_has(X86_FEATURE_SC_VERW_IDLE)) )
    {
        opt_tsx = 0;
        tsx_init();
    }

    /*
     * On some SRBDS-affected hardware, it may be safe to relax srb-lock by
     * default.
     *
     * All parts with SRBDS_CTRL suffer SSDP, the mechanism by which stale RNG
     * data becomes available to other contexts.  To recover the data, an
     * attacker needs to use:
     *  - SBDS (MDS or TAA to sample the cores fill buffer)
     *  - SBDR (Architecturally retrieve stale transaction buffer contents)
     *  - DRPW (Architecturally latch stale fill buffer data)
     *
     * On MDS_NO parts, and with TAA_NO or TSX unavailable/disabled, and there
     * is no unprivileged MMIO access, the RNG data doesn't need protecting.
     */
    if ( cpu_has_srbds_ctrl )
    {
        if ( opt_srb_lock == -1 && !opt_unpriv_mmio &&
             cpu_has_mds_no && !cpu_has_taa_no &&
             (!cpu_has_hle || (cpu_has_tsx_ctrl && rtm_disabled)) )
            opt_srb_lock = 0;

        set_in_mcu_opt_ctrl(MCU_OPT_CTRL_RNGDS_MITG_DIS,
                            opt_srb_lock ? 0 : MCU_OPT_CTRL_RNGDS_MITG_DIS);
    }

    gds_calculations();

    print_details(thunk);

    /*
     * If MSR_SPEC_CTRL is available, apply Xen's default setting and discard
     * any firmware settings.  For performance reasons, when safe to do so, we
     * delay applying non-zero settings until after dom0 has been constructed.
     *
     * "when safe to do so" is based on whether we are virtualised.  A native
     * boot won't have any other code running in a position to mount an
     * attack.
     */
    if ( has_spec_ctrl )
    {
        struct cpu_info *info = get_cpu_info();
        unsigned int val;

        bsp_delay_spec_ctrl = !cpu_has_hypervisor && default_xen_spec_ctrl;

        /*
         * If delaying MSR_SPEC_CTRL setup, use the same mechanism as
         * spec_ctrl_enter_idle(), by using a shadow value of zero.
         */
        if ( bsp_delay_spec_ctrl )
        {
            info->shadow_spec_ctrl = 0;
            barrier();
            info->spec_ctrl_flags |= SCF_use_shadow;
            barrier();
        }

        val = bsp_delay_spec_ctrl ? 0 : default_xen_spec_ctrl;

        wrmsrl(MSR_SPEC_CTRL, val);
        info->last_spec_ctrl = val;
    }
}

static void __init __maybe_unused build_assertions(void)
{
    /* The optimised assembly relies on this alias. */
    BUILD_BUG_ON(SCF_use_shadow != 1);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
