

#include "server.h"

#ifdef _WIN32
#define poll				WSAPoll
#define ioctl				ioctlsocket
#define ftello				_ftelli64
#define fseeko				_fseeki64
#define POLLIN				(POLLRDNORM | POLLRDBAND)
#define POLLOUT				(POLLWRNORM)
#ifdef _MSC_VER
#pragma warning(disable:4133)
#endif
#else
#include <fcntl.h>
#ifndef O_NONBLOCK
#include <sys/ioctl.h>
#endif
#define closesocket			close
#define send(a,b,c,d)		write(a,b,c)
#define recv(a,b,c,d)		read(a,b,c)
#endif

#define STATUS_REQ         0
#define STATUS_RESP        1

const char *crlf_crlf = "\r\n\r\n";
const char *crlf = "\r\n";

const char ok_200[]  = "HTTP/1.1 200 OK\r\nContent-Length: %lld\r\nContent-Type: %s\r\nConnection: close\r\n\r\n";
const char err_400[] = "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n";
const char err_401[] = "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic\r\nConnection: close\r\n\r\n";
const char err_403[] = "HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n";
const char err_404[] = "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n";
const char err_405[] = "HTTP/1.1 405 Method not allowed\r\nConnection: close\r\n\r\n";
const char partial_206[]  = "HTTP/1.1 206 Partial content\r\nContent-Range: bytes %lld-%lld/%lld\r\nContent-Length: %lld\r\nContent-Type: %s\r\nConnection: close\r\n\r\n";

const char dirlist_200_txt[]  = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %u\r\nX-Directory: true\r\nConnection: close\r\n\r\n";
const char dirlist_200_html[]  = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: %u\r\nX-Directory: true\r\nConnection: close\r\n\r\n";

// Temporary buffer for main thread usage
char tbuffer[WR_BLOCK_SIZE];

char auth_str[128]; // "Basic dXNlcjpwYXNz";

struct process_task {
	int fd;
	FILE* fdfile;
	time_t start_time;
	char status;
	int offset;
	long long fend;
	unsigned short request_size;
	unsigned char request_data[REQUEST_MAX_SIZE+1];
	DIR *dirlist;

	// List of free/nonfree tasks
	struct process_task * next;
	int id;
};
int listenfd;
struct process_task tasks[MAXCLIENTS];
struct process_task * free_task = &tasks[0];
struct process_task * proc_task = NULL;
struct pollfd fdtable[MAXCLIENTS+1];

int setNonblocking(int fd) {
	int flags;

#ifdef O_NONBLOCK
	/* If they have O_NONBLOCK, use the Posix way to do it */
	/* Fixme: O_NONBLOCK is defined but broken on SunOS 4.1.x and AIX 3.2.5. */
	if (-1 == (flags = fcntl(fd, F_GETFL, 0)))
		flags = 0;
	return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#else
	/* Otherwise, use the old way of doing it */
	flags = 1;
	return ioctl(fd, FIONBIO, &flags);
#endif
}

const char* mime_lookup(char* file) {
	char* extension = &file[strlen(file) - 1];
	while (*extension != '.') {
		if (extension == file)
			return mtypes[0].mime_type;  // No extension, default type
		extension--;
	}
	// Skip dot
	extension++;

	for (unsigned i = 1; i < sizeof(mtypes) / sizeof(struct mime_type); i++) {
		if (!stricmp2(extension, mtypes[i].extension)) {
			return mtypes[i].mime_type;
		}
	}
	return mtypes[0].mime_type;  // Not found, defaulting
}

long long lof(FILE * fd) {
	long long pos = ftello(fd);
	fseeko(fd,0,SEEK_END);
	long long len = ftello(fd);
	fseeko(fd,pos,SEEK_SET);
	return len;
}

void process_exit(int signal) {
	// Close all the connections and files
	// and then exit

	closesocket(listenfd);

	int i;
	for (i = 0; i < MAXCLIENTS; i++) {
		if (tasks[i].fd != -1) closesocket(tasks[i].fd);
		if (tasks[i].fdfile != 0) fclose(tasks[i].fdfile);
	}

#ifdef _WIN32
	WSACleanup();
#endif

	printf("Terminated by signal %d\n",signal);
	exit(0);
}

int fdtable_lookup(int fd) {
	int k;
	for (k = 0; k < MAXCLIENTS; k++)
		if (fdtable[k].fd == fd)
			return k;

	return 0;
}

int sock_error() {
#ifdef _WIN32
	int err = WSAGetLastError();
	return (err && err != WSAEWOULDBLOCK);
#else
	return (errno != EAGAIN && errno != EWOULDBLOCK);
#endif
}


void server_run (int port, int ctimeout, char * base_path, int dirlist) {
	signal (SIGTERM, process_exit);
	signal (SIGINT, process_exit);
#ifndef _WIN32
	signal(SIGHUP, process_exit);
	signal (SIGPIPE, SIG_IGN);
#endif

	int num_active_clients = 0;
	int i,j,k;

	/* Force the network socket into nonblocking mode */
	if (setNonblocking(listenfd) < 0) {
		printf("Error while trying to go NON-BLOCKING\n"); exit(1);
	}

	if(listen(listenfd,5) < 0) {
		printf("Error listening on the port\n"); perror("listen"); exit(1);
	}

	for (i = 0; i < MAXCLIENTS+1; i++) {
		fdtable[i].fd = -1;
		fdtable[i].events = POLLIN;  // By default
		fdtable[i].revents = 0;
	}
	for (i = 0; i < MAXCLIENTS; i++) {
		tasks[i].fd = -1;
		tasks[i].next = (i != MAXCLIENTS-1) ? &tasks[i+1] : 0;
		tasks[i].id = i;
	}
	fdtable[0].fd = listenfd;

	while(1) {
		// Unblock if more than 1 second have elapsed (to allow killing dead connections)
		poll(fdtable, num_active_clients+1, 1000);

		int fd = accept(listenfd, NULL, NULL);
		if (fd != -1) {
			setNonblocking(fd);

			if (free_task != 0) {
				// Add the fd to the poll wait table!
				assert(num_active_clients < MAXCLIENTS);
				int i = ++num_active_clients;
				fdtable[i].fd = fd;
				fdtable[i].events = POLLIN;  // By default we read (the request)

				struct process_task * t = free_task;
				t->fd = fd;
				t->request_size = 0;
				t->status = STATUS_REQ;
				t->fdfile = 0;
				t->dirlist = 0;
				time(&t->start_time);

				// Remove from free list, add to proc list
				free_task = free_task->next;
				t->next = proc_task;
				proc_task = t;
			} else {
				assert(num_active_clients == MAXCLIENTS);
				closesocket(fd);
			}
		}

		// Process the data
		struct process_task * t = proc_task;
		struct process_task * tp = NULL;
		while (t != NULL) {
			int force_end = 0;

			// HTTP REQUEST READ
			if (t->status == STATUS_REQ) {
				// Keep reading the request message
				int readbytes = recv(t->fd,&t->request_data[t->request_size],REQUEST_MAX_SIZE-t->request_size,0);
				if (readbytes >= 0) {
					t->request_size += readbytes;

					if (readbytes > 0)
						time(&t->start_time);   // Update timeout

					// Put null ends
					t->request_data[t->request_size] = 0;
					// Check request end, ignore the body!
					if (strstr((char*)t->request_data, crlf_crlf) != 0) {
						// We got all the header, reponse now!
						t->status = STATUS_RESP;
						fdtable[fdtable_lookup(t->fd)].events = POLLOUT;
						// Parse the request header

						int userange = 1;
						long long fstart = 0;
						if (header_attr_lookup((char*)t->request_data, "range:", crlf) < 0) {
							userange = 0;
							t->fend = LLONG_MAX;
						} else {
							if (parse_range_req(param_str, &fstart, &t->fend) < 0) {
								userange = 0;
								fstart = 0;
								t->fend = LLONG_MAX;
							}
						}

						// Auth
						int auth_ok = 1;
						if (auth_str[0] != 0) {
							if (header_attr_lookup((char*)t->request_data, "authorization:", crlf) < 0 || strcmp(param_str, auth_str)) {
								auth_ok = 0;
							}
						}

						if (!auth_ok) {
							RETURN_STRBUF(t, err_401);
						} else {
							int ishead = 0;
							int code = RTYPE_405;
							char file_path[MAX_PATH_LEN * 2];
							int isget = header_attr_lookup((char*)t->request_data, "get ", " ") >= 0; // Get the file
							if (!isget) ishead = header_attr_lookup((char*)t->request_data, "head ", " ") >= 0; // Get the file

							if (isget || ishead) {
								code = path_create(base_path, param_str, file_path);
								if (code == RTYPE_DIR && !dirlist) code = RTYPE_403;
							}

							switch (code) {
								case RTYPE_400:
									RETURN_STRBUF(t, err_400);
									break;
								case RTYPE_403:
									RETURN_STRBUF(t, err_403);
									break;
								case RTYPE_404:
									RETURN_STRBUF(t, err_404);
									break;
								case RTYPE_405:
									RETURN_STRBUF(t, err_405);
									break;
								case RTYPE_DIR:  // Dir
									if (!ishead)
										t->dirlist = opendir(file_path);
#ifdef HTMLLIST
									sprintf((char*)t->request_data, dirlist_200_html, dirlist_size(file_path));
#else
									sprintf((char*)t->request_data, dirlist_200_txt, dirlist_size(file_path));
#endif
									t->request_size = strlen((char*)t->request_data);
									break;
								case RTYPE_FIL: // File
								{
									FILE* fd = fopen(file_path, "rb");
									long long len = lof(fd);
									const char* mimetype = mime_lookup(file_path);
									if (t->fend > len - 1) t->fend = len - 1;  // Last byte, not size
									long long content_length = t->fend - fstart + 1;

									if (userange && isget) {
										sprintf((char*)t->request_data, partial_206, fstart, t->fend, len, content_length, mimetype);
										t->request_size = strlen((char*)t->request_data);
									} else {
										sprintf((char*)t->request_data, ok_200, content_length, mimetype);
										t->request_size = strlen((char*)t->request_data);
									}

									if (ishead) {
										fclose(fd);
									} else {
										t->fdfile = fd;
										fseeko(fd, fstart, SEEK_SET); // Seek the first byte
									}
									break;
								}
							};
						}
						t->offset = 0;
					}
				} else if (sock_error()) {
					force_end = 1;
				}
			}

			// HTTP RESPONSE BODY WRITE
			if (t->status == STATUS_RESP && !force_end) {

				if (t->offset == t->request_size) { // Try to feed more data into the buffers
					// Fetch some data from the file
					if (t->fdfile) {
						int toread = WR_BLOCK_SIZE;
						if (toread > (t->fend + 1 - ftello(t->fdfile))) toread = (t->fend + 1 - ftello(t->fdfile));
						if (toread < 0) toread = 0; // File could change its size...

						int numb = fread(tbuffer,1,toread,t->fdfile);
						if (numb > 0 && toread > 0) {
							// Try to write the data to the socket
							int bwritten = send(t->fd,tbuffer,numb,0);

							// Seek back if necessary
							int bw = bwritten >= 0 ? bwritten : 0;
							fseek(t->fdfile,-numb+bw,SEEK_CUR);

							if (bwritten >= 0) {
								time(&t->start_time);   // Update timeout
							} else if (sock_error()) { // Some unknown error!
								force_end = 1;
							}
						} else {
							// End of file, close the connection
							force_end = 1;
						}
					} else if (t->dirlist) {
						struct dirent *ep = readdir(t->dirlist);
						if (ep) {
							t->request_size = generate_dir_entry(t->request_data, ep);
							t->offset = 0;
						} else {
							closedir(t->dirlist);
							force_end = 1;
						}
					} else {
						force_end = 1;
					}
				}

				if (!force_end && t->offset < t->request_size) {  // Header
					int bwritten = send(t->fd,&t->request_data[t->offset],t->request_size-t->offset,0);

					if (bwritten >= 0) {
						t->offset += bwritten;
						time(&t->start_time);   // Update timeout
					} else if (sock_error()) { // Some unknown error!
						force_end = 1;
					}
				}
			}

			// Connection timeouts
			if (ctimeout > 0) {
				time_t cur_time; time(&cur_time);
				if (cur_time-t->start_time > ctimeout)
					force_end = 1;
			}

			struct process_task * nextt = t->next;
			if (force_end) { // Try to close the socket
				// close connection and update the fdtable
				closesocket(t->fd);
				for (k = 0; k < MAXCLIENTS; k++) {
					if (fdtable[k].fd == t->fd) {
						for (j = k; j < MAXCLIENTS; j++)
							fdtable[j].fd = fdtable[j+1].fd;
						fdtable[MAXCLIENTS].fd = -1;
						break;
					}
				}
				if (t->fdfile != 0)
					fclose(t->fdfile);
				t->fd = -1;
				t->fdfile = 0;
				num_active_clients--;

				// Remove from procesing list
				// do not advance tp!
				if (tp)
					tp->next = t->next;
				else
					proc_task = t->next;

				t->next = free_task;
				free_task = t;
			}
			else // Regular list advance
				tp = t;

			t = nextt;
		}
	}
}

int main(int argc, char** argv) {
	int port = 8080, timeout = 8, dirlist = 0;
	char base_path[MAX_PATH_LEN] = { 0 };
	getcwd(base_path, MAX_PATH_LEN - 1);
#ifndef _WIN32
	char sw_user[256] = "nobody";
#endif

	int i;
	int help = 0;
	for (i = 1; i < argc; i++) {
		// Port
		if (strcmp(argv[i], "-p") == 0) {
			if (++i >= argc || sscanf(argv[i], "%d", &port) != 1) {
				help = 1;
				break;
			}
		}
		// Timeout
		if (strcmp(argv[i], "-t") == 0) {
			if (++i >= argc || sscanf(argv[i], "%d", &timeout) != 1) {
				help = 1;
				break;
			}
		}
		// Base dir
		if (strcmp(argv[i], "-d") == 0) {
			if (++i >= argc) {
				help = 1;
				break;
			}
			int x;
			for (x = 0; argv[i][x]; x++) {
				base_path[x] = argv[i][x];
			}
			base_path[x] = 0;
			while (--x >= 0 && (base_path[x] == ' ' || base_path[x] == '\t' ||
				base_path[x] == '\r' || base_path[x] == '\n')) {
				base_path[x] = 0;
			}
			x++;
			while (--x >= 0 && (base_path[x] == '/' || base_path[x] == '\\')) {
				base_path[x] = 0;
			}
		}
		// Auth
		if (strcmp(argv[i], "-a") == 0) {
			if (++i >= argc) {
				help = 1;
				break;
			}
			strcpy(auth_str, argv[i]);
		}
		// Dir list
		if (strcmp(argv[i], "-l") == 0) {
			dirlist = 1;
		}
		// Help
		if (strcmp(argv[i], "-h") == 0) {
			help = 1;
			break;
		}
#ifndef _WIN32
		// User drop
		if (strcmp(argv[i], "-u") == 0) {
			if (++i >= argc) {
				help = 1;
				break;
			}
			strcpy(sw_user, argv[i]);
		}
#endif
	}
	if (help) {
		printf("Usage: server [-p port] [-t timeout] [-d base_dir] [-u user]\n"
			"    -p     Port             (Default port is 8080)\n"
			"    -t     Timeout          (Default timeout is 8 seconds of network inactivity)\n"
			"    -d     Base Dir         (Default dir is working dir)\n"
			"    -l     Enable dir lists (Off by default for security reasons)\n"
			"    -a     HTTP Auth        (Specify an auth string, i.e. \"Basic dXNlcjpwYXNz\")\n"
#ifndef _WIN32
			"    -u     Switch to user   (Switch to specified user (may drop privileges, by default nobody))\n"
#endif
		);
		exit(0);
	}

#ifdef _WIN32
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

	// Bind port!
	struct sockaddr_in servaddr;

	listenfd = socket(AF_INET, SOCK_STREAM, 0);
	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(port);
	int yes = 1;
	setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
	if (bind(listenfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
		printf("Error %u binding the port.\n", errno); perror("bind");
#ifdef _WIN32
		WSACleanup();
#endif
		exit(1);
	}

#ifndef _WIN32
	// Switch to user, unless empty or '-'
	if (sw_user[0] && (sw_user[0] != '-' || sw_user[1])) {
		struct passwd* pw = getpwnam(sw_user);
		if (pw == 0) {
			fprintf(stderr, "Could not find user %s\n", sw_user);
			exit(1);
		}
		setgid(pw->pw_gid);
		setuid(pw->pw_uid);
	}
#endif

	server_run(port, timeout, base_path, dirlist);
}
