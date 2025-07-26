// server.h

#include "server_config.h"

#define _FILE_OFFSET_BITS 64

#ifdef _WIN32

//#define WINVER 0x600
//#define _WIN32_WINNT 0x600
#define _CRT_NONSTDC_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#ifdef USE_MSVCRT
#define _NO_CRT_STDIO_INLINE
#pragma comment(lib, "msvcrt.lib")
#endif
#include <windows.h>
#include <winsock2.h>
#include <direct.h>
#include <io.h>
#include "win32/inc/w32_dirent.h"
#pragma comment(lib, "ws2_32.lib")
#ifdef _MSC_VER
#pragma warning(disable:4133)
#endif

#define poll				WSAPoll
#define ioctl				ioctlsocket
#define ftello(a)			_telli64(_fileno(a))
#define fseeko				_fseeki64
#define getcwd				_getcwd
#define POLLIN				(POLLRDNORM | POLLRDBAND)
#define POLLOUT				(POLLWRNORM)

#else

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <poll.h>
#include <pwd.h>
#include <unistd.h>
#ifndef O_NONBLOCK
#include <sys/ioctl.h>
#endif

#define closesocket			close
#define send(a,b,c,d)		write(a,b,c)
#define recv(a,b,c,d)		read(a,b,c)

#endif

#include <assert.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#ifndef LLONG_MAX
#define LLONG_MAX 9223372036854775807LL
#endif

#ifndef COUNTOF
#define COUNTOF(x) (sizeof(x)/sizeof(x[0]))
#endif

#define RTYPE_404	0
#define RTYPE_DIR	1
#define RTYPE_FIL	2
#define RTYPE_405	3
#define RTYPE_403	4
#define RTYPE_400	5

#define STATUS_REQ	0
#define STATUS_RESP	1

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

#define RETURN_STRBUF(task, buffer) \
	{ \
		strcpy((char*)task->request_data, (char*)buffer); \
		task->request_size = strlen((char*)buffer); \
	}

char hex2char(const char * i) {
	char c1, c2;
	if      (i[0] >= '0' && i[0] <= '9') c1 = i[0]-'0';
	else if (i[0] >= 'a' && i[0] <= 'f') c1 = i[0]-'a'+10;
	else                                 c1 = i[0]-'A'+10;

	if      (i[1] >= '0' && i[1] <= '9') c2 = i[1]-'0';
	else if (i[1] >= 'a' && i[1] <= 'f') c2 = i[1]-'a'+10;
	else                                 c2 = i[1]-'A'+10;

	return c1*16+c2;
}

int ishexpair(const char *i) {
	if (!((i[0] >= '0' && i[0] <= '9') ||
		(i[0] >= 'a' && i[0] <= 'f') ||
		(i[0] >= 'A' && i[0] <= 'F') ))
		return 0;
	if (!((i[1] >= '0' && i[1] <= '9') ||
		(i[1] >= 'a' && i[1] <= 'f') ||
		(i[1] >= 'A' && i[1] <= 'F') ))
		return 0;
	return 1;
}

// s2 should be in lowercase
char* stristr2(const char* s1, const char* s2) {
	unsigned int i;
	char *p;
	for (p = (char*)s1; *p != 0; p++) {
		i = 0;
		do {
			if (s2[i] == 0) return p;
			if (p[i] == 0) break;
			if (s2[i] != ((p[i]>64 && p[i]<91)?(p[i]+32):p[i])) break;
		} while (++i);
	}
	return 0;
}

// s2 should be in lowercase
static int stricmp2(const char* s1, const char* s2) {
	unsigned int i;
	for (i = 0; s1[i]; i++) {
		char c = (s1[i] > 64 && s1[i] < 91) ? s1[i]+32 : s1[i];
		if (c > s2[i]) return 1;
		else if (c < s2[i]) return -1;
	}
	return (s2[i] ? -1 : 0);
}

// s2 should be in lowercase
static int strncmpi2(const char* s1, const char* s2, unsigned int len) {
  while (*s1 == ((*s1 > 64 && *s1 < 91) ? (*s2)-32 : *s2)) {
    if (*s1 == 0 || --len == 0) return 0;
    s1++; s2++;
  }
  return (*s1 > *s2) ? 1 : -1;
}

char* strlower(char* s) {
	char *p = s;
	while (*p) {
		if (*p > 64 && *p < 91) *p += 32;
		p++;
	}
	return s;
}

// writes to param_str the value of the parameter in the request trimming whitespaces
int header_attr_lookup(char * param_str, const char * request, const char * param, const char * param_end) {
	char tmp[32] = "\r\n";
	if (strncmpi2(request, param, strlen(param))) {
		strcpy(tmp+2, param);
		param = tmp;
	}

	char * ptr = stristr2(request,param);  // ptr to the parameter line
	if (ptr == 0)
		return -1;
	ptr += strlen(param);  // ptr now points to the start of the data
	while (*ptr == ' ') ptr++;  // trim whitespaces

	char * ptr2 = stristr2(ptr,param_end);   // ptr to the end of the line
	if (ptr2 == 0)
		return -1;

	int len = (((size_t)ptr2) - ((size_t)ptr));
	if (len < 0) return -1;
	memcpy(param_str, ptr, len);  // Copy the data to the buffer
	param_str[len] = 0;

	return len;  // Returns the size of the parameter
}

int parse_range_req(const char* req_val, long long* start, long long* end) {
	// Req_val will be something like:
	// bytes=120-   (download from byte 120 to the end)
	// bytes=-120   (download the last 120 bytes)
	// bytes=120-123 (interval)
	// bytes=1-2,5-6 (multiple chunks)
	// We only support %- or %-%

	// By default whole file
	*start = 0;
	*end = LLONG_MAX;

	// Check if there's a comma!
	if (strchr(req_val, ',') != 0)
		return -1;

	// Strip bytes prefix
	const char* ptr = strchr(req_val, '=');
	if (ptr == 0) ptr = req_val;
	else ptr++; //Skip "="

	// Whitespace strip
	while (*ptr == ' ') ptr++;

	if (*ptr == 0) return -1; // Empty!!!

	if (*ptr != '-') {
		// Read the start
		sscanf(ptr, "%lld", start);
		if (*start < 0) return -1;

		// Search for "-"
		ptr = strchr(ptr, '-');
		if (!ptr)
			return 0;  // No "-" present, assuming EOF

		ptr++;
		// More whitespace
		while (*ptr == ' ') ptr++;

		if (*ptr == 0 || *ptr == '-')
			return 0;  // assuming EOF
	}

	// Read the end
	sscanf(ptr, "%lld", end);

	// If end is not negative, should end >= start
	if (*end >= 0 && *start > *end) return -1;

	return 0;
}

void urldecode(char *url) {
	while (*url && *url != '%') url++;
	char *p = url;
	while (*url) {
		if (*url == '%' && ishexpair(url+1)) {
			*p++ = hex2char(++url);
			url++;
		}
		else {
			*p++ = *url;
		}
		url++;
	}
	*p = 0;
}

int is_allowed_extension(const char* url) {
	int url_len = strlen(url);
	for (int i = 0; i < COUNTOF(allowedFileExtensions); i++) {
		int ext_len = strlen(allowedFileExtensions[i]);
		if (url_len < ext_len) continue;
		if (!strncmpi2(url+url_len-ext_len, allowedFileExtensions[i], ext_len))
			return 1;
	}
	return 0;
}

int path_exists(const char* path) {
	// Check whether we have a directory or a file
	void* dirp = opendir(path);
	if (dirp) {
		closedir(dirp);
		return RTYPE_DIR;
	} else {
		// Try as file
		FILE* fd = fopen(path, "rb");
		if (fd) {
			fclose(fd);
			return RTYPE_FIL;
		}
	}
	return RTYPE_404;
}

#define MAX_REQ_PATH_LEN MAX_PATH_LEN
int path_create(const char* base_path, char* req_file, char* out_file) {
	int i, j, k, ret;
	int basepath_len;
	int moddir_len;
	char *p;

	urldecode(req_file);
	for (i = 0, j = 0; req_file[i]; i++, j++) {
		while ((req_file[i] == '/' || req_file[i] == '\\') && (req_file[i + 1] == '/' || req_file[i + 1] == '\\')) i++;
		if  (req_file[i] < 0x20 || (req_file[i] == '.' && req_file[i + 1] == '.' && (req_file[i + 2] == '/' || req_file[i + 2] == '\\'))) {
			return RTYPE_400;
		}
		if (req_file[i] == '\\') {
			req_file[i] = '/';
		} else if (req_file[i] == '?') {
			req_file[j] = 0;
			break;
		}
		if (j != i) req_file[j] = req_file[i];
	}
	req_file[j] = 0;
	if (j > 0 && req_file[j - 1] == '.') {
		return RTYPE_400;
	}
	if (!is_allowed_extension(req_file)) {
		return RTYPE_403;
	}
	if (stristr2(req_file, "/addons/") || stristr2(req_file, "/cfg/") || stristr2(req_file, "/logs/")) { // disallow directory access
		return RTYPE_403;
	}

	k = 0;
	moddir_len = 0;
	p = out_file;
	for (i = 0; base_path[i]; i++) {
		*p++ = base_path[i];
	}
	basepath_len = i;
	j = basepath_len;
	if (req_file[0] != '/') {
		*p++ = '/';
		j++;
		k++;
	}
	for (i = 0; req_file[i] && j < MAX_REQ_PATH_LEN; i++, j++) {
		*p++ = req_file[i];
		if (req_file[i] == '/' && ++k == 2) {
			moddir_len = i;
		}
	}
	if (j == MAX_REQ_PATH_LEN || !moddir_len) {
		return RTYPE_400;
	}
	*p = 0;

	// Check whether we have a directory or a file
	if (ret = path_exists(out_file)) {
		return ret;
	}

	// Try volvo
	p = out_file+basepath_len;
	strcpy(p, "/valve");
	p += 6;
	j = basepath_len + 6;
	for (i = moddir_len; req_file[i] && j < MAX_REQ_PATH_LEN; i++, j++) {
		*p++ = req_file[i];
	}
	if (j == MAX_REQ_PATH_LEN) {
		return RTYPE_400;
	}
	*p = 0;

	// Check whether we have a directory or a file
	if (ret = path_exists(out_file)) {
		return ret;
	}

// Disable lowercasing code on Windows (Windows filesystem API is case-insensitive as-is)
#ifndef _WIN32

	// Try lowercase
	strlower(req_file);
	p = out_file+basepath_len;
	j = basepath_len;
	if (req_file[0] != '/') {
		*p++ = '/';
		j++;
	}
	for (i = 0; req_file[i] && j < MAX_REQ_PATH_LEN; i++, j++) {
		*p++ = req_file[i];
	}
	if (j == MAX_REQ_PATH_LEN) {
		return RTYPE_400;
	}
	*p = 0;

	// Check whether we have a directory or a file
	if (ret = path_exists(out_file)) {
		return ret;
	}

	// Try volvo+lowercase
	p = out_file+basepath_len;
	strcpy(p, "/valve");
	p += 6;
	j = basepath_len + 6;
	for (i = moddir_len; req_file[i] && j < MAX_REQ_PATH_LEN; i++, j++) {
		*p++ = req_file[i];
	}
	if (j == MAX_REQ_PATH_LEN) {
		return RTYPE_400;
	}
	*p = 0;

	// Check whether we have a directory or a file
	if (ret = path_exists(out_file)) {
		return ret;
	}

#endif // #ifndef _WIN32

	return RTYPE_404;
}

const char* mime_lookup(char* file) {
	return "application/octet-stream";
}

long long lof(FILE* fd) {
	long long pos = ftello(fd);
	fseeko(fd,0,SEEK_END);
	long long len = ftello(fd);
	fseeko(fd,pos,SEEK_SET);
	return len;
}

