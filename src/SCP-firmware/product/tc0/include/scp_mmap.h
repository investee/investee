/*
 * Arm SCP/MCP Software
 * Copyright (c) 2020-2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef SCP_MMAP_H
#define SCP_MMAP_H

#define SCP_BOOT_ROM_BASE 0x00000000
#define SCP_RAM_BASE 0x10000000

#define SCP_SOC_EXPANSION3_BASE UINT32_C(0x40000000)
#define SCP_PERIPHERAL_BASE UINT32_C(0x44000000)
#define SCP_ELEMENT_MANAGEMENT_PERIPHERAL_BASE UINT32_C(0x50000000)
#define SCP_SYSTEM_ACCESS_PORT0_BASE UINT32_C(0x60000000)
#define SCP_SYSTEM_ACCESS_PORT1_BASE UINT32_C(0xA0000000)

#endif /* SCP_MMAP_H */