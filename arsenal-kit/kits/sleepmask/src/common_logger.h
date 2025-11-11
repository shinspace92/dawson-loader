

#ifdef DEBUG
#define DLOGT(fmt) OutputDebugStringA(fmt)
#define DLOG(fmt, ...) dlog(fmt, __VA_ARGS__)

void dlog(char* fmt, ...) {
	char buff[512];
	va_list va;

	memset(buff, 0, 512);

	va_start(va, fmt);
	vsprintf_s(buff, 512, fmt, va);
	va_end(va);

	OutputDebugStringA(buff);
}

#else
#define DLOGT(fmt)
#define DLOG(fmt, ...)
#endif
