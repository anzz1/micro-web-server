// w32_crt_stub.h

extern __declspec(dllimport) int __cdecl __getmainargs(long*,char***,char***,long,long*);
void mainCRTStartup() {
	long argc;
	char** argv;
	char** env;
	long l;
	__getmainargs(&argc, &argv, &env, 0, &l);
	exit(main(argc, argv));
}
