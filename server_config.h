
#define REQUEST_MAX_SIZE	2047			// Maximum allowed size for a GET request
#define MAX_PATH_LEN		8191			// Maximum size (in chars) for a path in the filesystem

#define MAXCLIENTS			128				// Maximum number of simultaneous connections allowed (the bigger, the more mem used)
#define WR_BLOCK_SIZE		(1024*1024)		// Chunk size for disk read/write operations, the bigger the more throughput

#ifdef _WIN32
#undef HAVE_SETUID
#define USE_MSVCRT							// Use msvcrt instead of ucrt
#endif

static const char* allowedFileExtensions[] = {
	".bmp",
	".bsp",
	".gz",
	".html",
	".htm",
	".lmp",
	".mdl",
	".mp3",
	".nav",
	".pak",
	".pcx",
	".res",
	".sc",
	".seq",
	".spr",
	".tga",
	".txt",
	".vpk",
	".wad",
	".wav",
	".wpt"
};
