/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Alternate p2m HVM
 * Copyright (c) 2014, Intel Corporation.
 */

#include <asm/hvm/hvm.h>
#include <asm/p2m.h>
#include <asm/altp2m.h>
#include "mm-locks.h"
#include "p2m.h"

void
altp2m_vcpu_initialise(struct vcpu *v)
{
    if ( v != current )
        vcpu_pause(v);

    vcpu_altp2m(v).p2midx = 0;
    atomic_inc(&p2m_get_altp2m(v)->active_vcpus);

    altp2m_vcpu_update_p2m(v);

    if ( v != current )
        vcpu_unpause(v);
}

void
altp2m_vcpu_destroy(struct vcpu *v)
{
    struct p2m_domain *p2m;

    if ( v != current )
        vcpu_pause(v);

    if ( (p2m = p2m_get_altp2m(v)) )
        atomic_dec(&p2m->active_vcpus);

    altp2m_vcpu_disable_ve(v);

    vcpu_altp2m(v).p2midx = INVALID_ALTP2M;
    altp2m_vcpu_update_p2m(v);

    if ( v != current )
        vcpu_unpause(v);
}

int altp2m_vcpu_enable_ve(struct vcpu *v, gfn_t gfn)
{
    struct domain *d = v->domain;
    struct altp2mvcpu *a = &vcpu_altp2m(v);
    p2m_type_t p2mt;
    struct page_info *pg;
    int rc;

    /* Early exit path if #VE is already configured. */
    if ( a->veinfo_pg )
        return -EEXIST;

    rc = check_get_page_from_gfn(d, gfn, false, &p2mt, &pg);
    if ( rc )
        return rc;

    /*
     * Looking for a plain piece of guest writeable RAM with isn't a magic
     * frame such as a grant/ioreq/shared_info/etc mapping.  We (ab)use the
     * pageable() predicate for this, due to it having the same properties
     * that we want.
     */
    if ( !p2m_is_pageable(p2mt) || is_special_page(pg) )
    {
        rc = -EINVAL;
        goto err;
    }

    /*
     * Update veinfo_pg, making sure to be safe with concurrent hypercalls.
     * The first caller to make veinfo_pg become non-NULL will program its MFN
     * into the VMCS, so must not be clobbered.  Callers which lose the race
     * back off with -EEXIST.
     */
    if ( cmpxchg(&a->veinfo_pg, NULL, pg) != NULL )
    {
        rc = -EEXIST;
        goto err;
    }

    altp2m_vcpu_update_vmfunc_ve(v);

    return 0;

 err:
    put_page(pg);

    return rc;
}

void altp2m_vcpu_disable_ve(struct vcpu *v)
{
    struct altp2mvcpu *a = &vcpu_altp2m(v);
    struct page_info *pg;

    /*
     * Update veinfo_pg, making sure to be safe with concurrent hypercalls.
     * The winner of this race is responsible to update the VMCS to no longer
     * point at the page, then drop the associated ref.
     */
    if ( (pg = xchg(&a->veinfo_pg, NULL)) )
    {
        altp2m_vcpu_update_vmfunc_ve(v);

        put_page(pg);
    }
}

int p2m_init_altp2m(struct domain *d)
{
    unsigned int i;
    struct p2m_domain *p2m;
    struct p2m_domain *hostp2m = p2m_get_hostp2m(d);

    mm_lock_init(&d->arch.altp2m_list_lock);
    for ( i = 0; i < MAX_ALTP2M; i++ )
    {
        d->arch.altp2m_p2m[i] = p2m = p2m_init_one(d);
        if ( p2m == NULL )
        {
            p2m_teardown_altp2m(d);
            return -ENOMEM;
        }
        p2m->p2m_class = p2m_alternate;
        p2m->access_required = hostp2m->access_required;
        _atomic_set(&p2m->active_vcpus, 0);
    }

    return 0;
}

void p2m_teardown_altp2m(struct domain *d)
{
    unsigned int i;
    struct p2m_domain *p2m;

    for ( i = 0; i < MAX_ALTP2M; i++ )
    {
        if ( !d->arch.altp2m_p2m[i] )
            continue;
        p2m = d->arch.altp2m_p2m[i];
        d->arch.altp2m_p2m[i] = NULL;
        p2m_free_one(p2m);
    }
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
