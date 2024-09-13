#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* For the UUID (found in the TA's h-file(s)) */
#include <pta_investee.h>

int main(int argc, const char *argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = PTA_INVESTEE_UUID;
	uint32_t err_origin;

	if (argc < 2) {
		printf("Usage: %s <cmd>\n", argv[0]);
		return -1;
	}

	uint32_t cmd_id = strtoull(argv[1], NULL, 16);

	/* Initialize a context connecting us to the TEE 
	   We connect to the Control Software
	*/
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	/*
	   Open a session to the "investee" PTA
	   We open a session to the Control Software
	 */
	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);

	/* Everything set up, we can request services now */

	switch (cmd_id)
	{
	// for testing, ability to dump memory
	case PTA_INVESTEE_DUMP_MEM:
		if (argc < 4) {
			printf("Usage PTA_INVESTEE_DUMP_MEM: %s <cmd> <phy_addr> <size>\n", argv[0]);
			TEEC_CloseSession(&sess);
			TEEC_FinalizeContext(&ctx);
			return -1;
		}
		uint64_t pa;
		uint64_t s;
		memset(&op, 0, sizeof(op));
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_VALUE_INOUT, TEEC_NONE, TEEC_NONE);
		pa = strtoull(argv[2], NULL, 16);
		*(uint64_t *)&op.params[0].value.a = pa;
		printf("Got physical addr 0x%016lx\n", pa);
		s = strtoull(argv[3], NULL, 16);
		*(uint64_t *)&op.params[1].value.a = s;
		printf("Got size 0x%016lx\n", s);

		break;
	// for testing, ability find a task_struct of a process specified as comm
	case PTA_INVESTEE_SEARCH_PROCESS:
		if (argc < 3) {
			printf("Usage PTA_INVESTEE_SEARCH_PROCESS: %s <cmd> <comm>\n", argv[0]);
			TEEC_CloseSession(&sess);
			TEEC_FinalizeContext(&ctx);
			return -1;
		}
		char *comm = argv[2];
		memset(&op, 0, sizeof(op));
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
		
		op.params[0].tmpref.buffer = comm;
		op.params[0].tmpref.size = strlen(comm);

		printf("Got comm name %s\n", (char *)op.params[0].tmpref.buffer);
		break;
	// this will request root privileges and let the Control Software install EVT hooking
	case PTA_HOOK_VBAR:
		if (argc < 2) {
			printf("Usage PTA_HOOK_VBAR: %s <cmd> \n", argv[0]);
			TEEC_CloseSession(&sess);
			TEEC_FinalizeContext(&ctx);
			return -1;
		}

		// we do not need any arg here
		memset(&op, 0, sizeof(op));
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);
		
		break;
	
	default:
		printf("Unknown command!\n");
		TEEC_CloseSession(&sess);
		TEEC_FinalizeContext(&ctx);
		return -1;
	}
	
	// invoke the command
	res = TEEC_InvokeCommand(&sess, cmd_id, &op,
				 &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);

	// evaluation, check if we can open a root-protected file
	FILE *file = fopen("/etc/shadow", "r");
	if(file == NULL)	{
		perror("Error opening file!");
		return 1;
	}
	char line[256];
	while(fgets(line, sizeof(line), file) != NULL)	{
		printf("%s", line);
	}
	fclose(file);

	// loop and execute systemcalls, you may comment this out
	while(1)	{
		printf("TEST");
		fflush(stdout);
		sleep(2);
	}

	/*
	* Close session to the "investee" PTA
	*/

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}
