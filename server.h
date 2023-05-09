
#define _FILE_OFFSET_BITS 64

#ifdef _WIN32
//#define WINVER 0x600
//#define _WIN32_WINNT 0x600
#define _CRT_NONSTDC_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <direct.h>
#include "w32_dirent.h"
#pragma comment (lib, "ws2_32.lib")
#else
#include <dirent.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <poll.h>
#include <pwd.h>
#include <unistd.h>
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

#include "server_config.h"

#ifndef LLONG_MAX
	#define LLONG_MAX 2094967295
#endif

#define RTYPE_404    0
#define RTYPE_DIR    1
#define RTYPE_FIL    2
#define RTYPE_405    3
#define RTYPE_403    4
#define RTYPE_400    5

void urldecode (char * dest, const char *url);
char* stristr2(const char* s1, const char* s2);

#define RETURN_STRBUF(task, buffer) \
	{ \
		strcpy((char*)task->request_data, (char*)buffer); \
		task->request_size = strlen((char*)buffer); \
	}

// writes to param_str the value of the parameter in the request trimming whitespaces
static char param_str[REQUEST_MAX_SIZE*3];
int header_attr_lookup(const char * request, const char * param, const char * param_end) {
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

unsigned int generate_dir_entry(void* out, const struct dirent* ep) {
	const char* slash = ep->d_type == DT_DIR ? "/" : "";
#ifdef HTMLLIST
	sprintf((char*)out, "<a href=\"%s%s\">%s%s</a><br>\n", ep->d_name, slash, ep->d_name, slash);
#else
	sprintf((char*)out, "%s%s\n", ep->d_name, slash);
#endif
	return strlen((char*)out);
}

unsigned int dirlist_size(const char* file_path) {
	char tmp[4 * 1024];
	unsigned r = 0;
	DIR* d = opendir(file_path);
	while (1) {
		struct dirent* ep = readdir(d);
		if (!ep) break;

		r += generate_dir_entry(tmp, ep);
	}
	closedir(d);
	return r;
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

	// Read the start
	sscanf(ptr, "%lld %*s", start);
	if (*start < 0) return -1;

	// Search for "-"
	ptr = strchr(ptr, '-');
	if (ptr == 0)
		return 0;  // No "-" present, assuming EOF
	else
		ptr++;

	// More whitespace
	while (*ptr == ' ') ptr++;

	if (*ptr == 0)
		return 0;  // assuming EOF

	// Read the end
	sscanf(ptr, "%lld %*s", end);

	// Both should be positive values, being start >= end
	if (*end < 0 || *start > *end) return -1;

	return 0;
}

int path_create(const char* base_path, const char* req_file, char* out_file) {
	int i, j;
	char* temp = malloc(strlen(req_file) + 1);

	urldecode(temp, req_file);

	for (i = 0, j = 0; temp[i]; i++, j++) {
		while ((temp[i] == '/' || temp[i] == '\\') && (temp[i + 1] == '/' || temp[i + 1] == '\\')) i++;
		if  (temp[i] < 0x20 || (temp[i] == '.' && temp[i + 1] == '.' && (temp[i + 2] == '/' || temp[i + 2] == '\\'))) {
			free(temp);
			return RTYPE_400;
		}
		if (temp[i] == '\\') {
			temp[i] = '/';
		} else if (temp[i] == '?') {
			temp[j] = 0;
			break;
		}
		if (j != i) temp[j] = temp[i];
	}
	if (j > 0 && temp[j - 1] == '.') {
		free(temp);
		return RTYPE_400;
	}
	temp[j] = 0;

	char* p = out_file;
	for (i = 0; base_path[i]; i++) {
		*p++ = base_path[i];
	}
	if (temp[0] != '/') *p++ = '/';
	for (i = 0; temp[i]; i++) {
		*p++ = temp[i];
	}
	*p = 0;
	free(temp);

	//puts(out_file);

	// Check whether we have a directory or a file
	struct stat path_stat;
	stat(out_file, &path_stat);
	if (S_ISDIR(path_stat.st_mode)) {
		if (*(p-1) != '/') *p++ = '/';
		strcpy(p, DEFAULT_DOC);

		// Try the index first
		FILE * fd = fopen(out_file, "rb");
		if (fd) {
			fclose(fd);
			return RTYPE_FIL;
		}
		*p = 0;

		// Try to open the dir
		void* ptr = opendir(out_file);
		if (ptr) {
			closedir(ptr);
			return RTYPE_DIR;
		}
	} else {
		// Try as file
		FILE* fd = fopen(out_file, "rb");
		if (fd) {
			fclose(fd);
			return RTYPE_FIL;
		}
	}

	return RTYPE_404;
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
int ishexpair(const char * i) {
	if (!(	(i[0] >= '0' && i[0] <= '9') ||
		(i[0] >= 'a' && i[0] <= 'f') ||
		(i[0] >= 'A' && i[0] <= 'F') ))
		return 0;
	if (!(	(i[1] >= '0' && i[1] <= '9') ||
		(i[1] >= 'a' && i[1] <= 'f') ||
		(i[1] >= 'A' && i[1] <= 'F') ))
		return 0;
	return 1;
}

void urldecode (char * dest, const char *url) {
	int s = 0, d = 0;
	int url_len = strlen (url) + 1;

	while (s < url_len) {
		char c = url[s++];

		if (c == '%' && s + 2 < url_len) {
			if (ishexpair(&url[s]))
				dest[d++] = hex2char(&url[s]);
			else {
				dest[d++] = c;
				dest[d++] = url[s+0];
				dest[d++] = url[s+1];
			}
			s += 2;
		}
		else if (c == '+') {
			dest[d++] = ' ';
		}
		else {
			dest[d++] = c;
		}
	}
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
