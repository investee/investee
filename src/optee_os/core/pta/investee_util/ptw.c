#include "ptw.h"

#include <mm/core_memprot.h> // paddr_t?
#include <mm/mobj.h>
#include <util.h>

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
	// only non-secure memory possible!
	current_mobj = mobj_mapped_shm_alloc(&page, 1, 0, 0);
	if (current_mobj == NULL) {
		current_vaddr = 0;
		// prevent double frees
		current_mobj = NULL;
		//IMSG("shm_alloc failed...");
		return -1;
	}
	current_vaddr = (void *)mobj_get_va(current_mobj, 0, 1);
	if(current_vaddr == NULL)	{
		current_vaddr = 0;
		// free wrong mobj
		mobj_put(current_mobj);
		// prevent double frees
		current_mobj = NULL;
		//IMSG("get_va failed...");
		return -1;
	}

	return 0;
}

// TODO: move read_pa to common file
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


// Maximum size of the translation tables (see D8.2.8)
static const uint32_t max_table_size = 512;

/*
 *	-- VMSAv8-64 Lookup Level (D8.2.8) --
 */
typedef enum {
	PT0 = 0,
	PT1,
	PT2,
	PT3
} long_pt_lookup_level_t;

/*
 *  -- VMSAv8-64 Descriptor Types (D8-45/D8-6623) --
 */
typedef enum {
	// bit[0] = 0 || (bit[0] = 1 && bit[1] = 0 && Lookup Level 3) -> descriptor invalid
	INVALID,

	// bit[0] = 1 -> descriptor is valid
	// Lookup Level is not 3
	BLOCK,	// bit[1] = 0
	TABLE,  // bit[1] = 1
	// Lookup Level is 3
	PAGE	// bit[1] = 1
} long_pt_descriptor_type_t;


/*
 *  -- VMSAv8-64 Table Descriptor (D8.3.1.1) --
 *
 *  The layout of this struct assumes:
 *  - the 4KB translation granule is used
 *  - 48-bit OA
 *  - we only want to translate virt to phys -> unnecessary fields are ignored 
 */
typedef __attribute__((packed)) struct {
	uint64_t valid		: 1;	//  0		Valid-Bit (0 = invalid, 1 = valid, see R_KHVQT/D8-6623)
	uint64_t table_flag	: 1;	//  1		Table Descriptor (for lookup levels < 3)
	uint64_t			: 10;	//  2 - 11	ignored 
	uint64_t nlta		: 36;	// 12 - 47	Base address of the next Table (next level table address)
	uint64_t			: 16;	// 48 - 63	ignored
} long_table_descriptor_t;

/*
 *  -- VMSAv8-64 Page Descriptor (D8.3.1.2) --
 *
 *	The same assumptions as for the table descriptor are made for this descriptor.
 */
typedef __attribute__((packed)) struct {
	uint64_t valid			: 1;	//  0		Valid-Bit
	uint64_t page_flag		: 1;	//  1		= 0 -> Block (lookup level < 3), = 1 -> Page (lookup level = 3)
	uint64_t				: 10;	//  2 - 11	ignored
	uint64_t output_address : 36;	// 12 - 47	output address for the page
	uint64_t				: 16;	// 48 - 63	ignored
} long_page_descriptor_t;

/*
 *  Union all descriptor types into one common type
 */
typedef union {
	uint64_t raw;
	long_table_descriptor_t table;
	long_page_descriptor_t  page;
} long_descriptor_t;

/*
 *	-- VMSAv8-64 Virtual Address (D8.2.8) --
 */
typedef __attribute__((packed)) struct {
	uint64_t page_offset	: 12;	//  0 - 11	page offset of the virtual address 
	uint64_t pt3_offset		: 9;	// 12 - 20	lookup level 3 offset
	uint64_t pt2_offset		: 9;	// 21 -	29	lookup level 2 offset
	uint64_t pt1_offset		: 9;	// 30 - 38	lookup level 1 offset
	uint64_t pt0_offset		: 9;	// 39 -	47	lookup level 0 offset
	uint64_t				: 16;	// 48 - 64	ignored
} long_input_va_t;



/*	-- __get_pt_va_offset --
 *
 *	Helper function to get the offset in the PT from the virtual address depending on the lookup level.
 *
 *	@param virt_addr: Virtual address to get the offset from.
 *	@param level	: Lookup level for which the offset is retrieved.
 *
 *	@return: 9-bit PT offset.
 */
static uint32_t __get_pt_va_offset(uint64_t virt_addr, long_pt_lookup_level_t level) {
	// TODO: assert level
	// Always shift right by 12 to remove the page offset. Then right shift in steps of 9 bits depending on the lookup 
	// level to get the corresponding table offset. Lastly use a binary & to remove any additional data above the offset.
	return (uint32_t)((virt_addr >> (12 + 9 * (3 - level))) & 0x1ff);
}

/*	-- __get_descriptor_at_offset --
 *
 *	Helper to get a translation table descriptor entry at a specific offset.
 *
 *	@param table_base	: Base address of the translation table to get the descriptor from.
 *	@param offset		: Offset (index) of the requested descriptor.
 *
 *	@return: The corresponding descriptor from the translation table.
 */
static long_descriptor_t __get_descriptor_at_offset(uint64_t table_base, uint32_t offset) {
	return (long_descriptor_t)(read_pa(table_base + offset * 8));
}

/*	-- __get_descriptor --
 *
 *	Helper function to get a descriptor from a translation table.
 *
 *	@param virt_addr	: Virtual address to get the offset from.
 *	@param table_base	: Base address of the translation table to get the descriptor from.
 *	@param level		: Lookup level of the translation table to calculate the offset.
 *
 *	@return: The corresponding descriptor from the translation table.
 */
static long_descriptor_t __get_descriptor(uint64_t virt_addr, uint64_t table_base, long_pt_lookup_level_t level) {
	// First convert the table
	uint32_t offset = __get_pt_va_offset(virt_addr, level);
	//IMSG("PT-LOG[%s] base=%lx offset=%i", __func__, table_base, offset);
	return __get_descriptor_at_offset(table_base, offset);
}

/*	-- __print_pt --
 *
 *	Print complete translation table for debugging.
 *
 *	@param table_base: Base of the translation table that should be printed
 */
static void __print_pt(uint64_t table_base) {

	//IMSG("PT-LOG[%s] === TRANSLATION TABLE %lx ===", __func__, table_base);
	for(size_t i = 0; i < max_table_size; i++) {
		long_descriptor_t desc = __get_descriptor_at_offset(table_base, i);
		//IMSG("PT-LOG[%s] descriptor %i: %lx", __func__, i, desc.raw);
	}
}

/*	-- __nw_virt_to_phys --
 *
 *	Recursive helper function to traverse the translation tables.
 */
static uint64_t __nw_virt_to_phys(uint64_t virt_addr, uint64_t pt_base_addr, long_pt_lookup_level_t level) {

	long_descriptor_t desc = __get_descriptor(virt_addr, pt_base_addr, level);
	//IMSG("PT-LOG[%s] PT %i descriptor: %lx", __func__, level, desc.raw);

	if(!desc.table.valid) return 0;		// no valid entry

	// check for lookup level 3 as it only contains page descriptors and thus is handled differently
	if(level == PT3) {
	
		if(!desc.page.page_flag) {	// descriptor is not valid if this bit is not set in the PT3 
			//IMSG("PT-LOG[%s] => Descriptor is not valid", __func__);
			return 0;
		}

		uint64_t pa = (desc.page.output_address << 12) | (virt_addr & 0xfff);

		//IMSG("PT-LOG[%s] Resolved va:%lx -> pa:%lx", __func__, virt_addr, pa);

		return pa;
	}

	// the lookup level is higher than 3 so we are either handling a block or table descriptor
	if(desc.table.table_flag) {
		return __nw_virt_to_phys(virt_addr, desc.table.nlta << 12, level + 1);
	} else {
		//IMSG("PT-LOG[%s] BLOCK DESCRIPTORS are currently not supported! (%lx)", __func__, desc.raw);
	}

	return 0;
}


uint64_t investee_nw_virt_to_phys(uint64_t virt_addr, uint64_t ttbrn_el1) {

	//IMSG("PT-LOG[%s] va=%lx", __func__, virt_addr);

	//__print_pt(ttbrn_el1);

	return __nw_virt_to_phys(virt_addr, ttbrn_el1, PT0);
}
