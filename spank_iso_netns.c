/*
* Author: Ryan Cox
* 
* Copyright (C) 2025, Brigham Young University
* 
* This program is free software; you can redistribute it and/or
* modify it under the terms of the GNU General Public License
* as published by the Free Software Foundation; either version 2
* of the License, or (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, see
* <https://www.gnu.org/licenses/>.
*
* -----------------------------------------------------------------------------------------
*
* spank_iso_netns - A Slurm SPANK plugin that provides network namespace isolation for jobs
*
* This plugin creates a new network namespace for Slurm jobs, enabling network isolation
* and custom networking configurations per job. It supports:
*   - TCP and (someday) UDP socket proxying between namespaces
*   - Custom setup scripts for network configuration
*   - HTTP proxy configuration
*
* Compile with: gcc -I/usr/local/src/slurm -fPIC -shared -o spank_iso_netns{.so,.c}
*
*/

#define _GNU_SOURCE
#include <sched.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <slurm/spank.h>
#include <stdbool.h>

#include <sys/stat.h>
#include <fcntl.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <netinet/tcp.h>

/* for dropping privs */
#include <grp.h>
#include <sys/capability.h>
#include <pwd.h>

#define SPANK_MODULE_NAME_LC "spank_iso_netns"

/* BASH_SHELL in this case is the arguments for argv, not the path */
#ifdef __USE_BASH_LOGIN_SHELL__
#define BASH_SHELL "bash", "-l"
#else
#define BASH_SHELL "bash"
#endif

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

/* Configuration constants */
#define LISTEN_BACKLOG 10            /* Backlog size for listen() */
#define PROXY_EXTRA_LEN 64           /* Max characters in =extra portion of --iso-netns-proxies */
#define MAX_PROTO_LISTENERS 20       /* Maximum number of supported listeners per protocol */
#define MAX_PROXIES 100              /* Maximum number of supported fds to create for proxying into namespace */


/* Environment variable names */
#define ENVVAR_NAME_FDNUM "SPANK_ISO_NETNS_LISTENING_FD"                /* Socket file descriptor for listener */
#define ENVVAR_NAME_PORTNUM "SPANK_ISO_NETNS_LISTENING_PORT"            /* Port number for listener */
#define ENVVAR_NAME_PROTONUM "SPANK_ISO_NETNS_LISTENING_PROTO"          /* Protocol (tcp/udp) for listener */
#define ENVVAR_NAME_OPTIONS "SLURM_SPANK__SLURM_SPANK_OPTION_spank_iso_netns_iso_netns_options"           /* Options string */
#define ENVVAR_NAME_LISTENERS "SLURM_SPANK__SLURM_SPANK_OPTION_spank_iso_netns_iso_netns_listeners"       /* Number of listeners */
#define ENVVAR_NAME_PROXIES "SLURM_SPANK__SLURM_SPANK_OPTION_spank_iso_netns_iso_netns_proxies"           /* Proxy configurations */
#define ENVVAR_NAME_PPID "SLURMSTEPD_PID"                               /* Parent process ID - for netns commands */
#define ENVVAR_NAME_PROXY_IPNUM "SPANK_ISO_NETNS_PROXY_IP"              /* IP address for proxy */
#define ENVVAR_NAME_PROXY_FDNUM "SPANK_ISO_NETNS_PROXY_FD"              /* Socket FD for proxy */
#define ENVVAR_NAME_PROXY_PORTNUM "SPANK_ISO_NETNS_PROXY_PORT"          /* Port number for proxy */
#define ENVVAR_NAME_PROXY_PROTONUM "SPANK_ISO_NETNS_PROXY_PROTO"        /* Protocol (tcp/udp) for proxy */
#define ENVVAR_NAME_PROXY_EXTRANUM "SPANK_ISO_NETNS_PROXY_EXTRA"        /* Extra options for proxy */
#define ENVVAR_NAME_HTTP_PROXY_CONF "SPANK_ISO_NETNS_HTTP_PROXY_CONF"   /* HTTP proxy configuration */

/* String size constants */
#define UINT32_STR_SIZE 12           /* Size for uint32 string representations (includes sign for safety) */
#define ENVVAR_VALUE_MAXLEN 128      /* Maximum length for environment variable values */

/* Function prototypes */
static int _spank_opt_http_proxy_conf(int val, const char *optarg, int remote);
static int _spank_opt_proxies(int val, const char *optarg, int remote);
static int _spank_opt_options_process(int val, const char *optarg, int remote);
static int _spank_opt_listeners_process(int val, const char *optarg, int remote);
int _listen_to_port(spank_t sp, int proto, char *ip, int *port, char *envvar_proto_basename, char *envvar_ip_basename, char *envvar_port_basename, char *envvar_fd_basename, int envvar_idx);
int _run_cmd(spank_t sp, char *path, char **exec_argv);
int _exe_cmd(spank_t sp, char *path, char **exec_argv);
int _drop_privs(uid_t job_uid, gid_t job_gid);
void _print_net_ns_inode();

/* SPANK plugin declaration */
SPANK_PLUGIN(spank_iso_netns, 1);

/* Plugin state variables */
static bool spank_plugin_active = false;
static int opt_tcp_fd_cnt = 0;
static int opt_udp_fd_cnt = 0;
static char *opt_options = NULL;
static char *arg_setup_script = NULL;
static char *proxies = NULL;
static char *http_proxy_conf = NULL;

/* SPANK option table - these define the command-line options this plugin supports */
struct spank_option spank_opts[] =
{
	{
		"iso-netns-tcp-listeners",
		"<0-" TOSTRING(MAX_PROTO_LISTENERS) ">",
		"Deprecated. Use --iso-netns-listeners instead.",
		1,
		0,
		(spank_opt_cb_f) _spank_opt_listeners_process
	},
	{
		"iso-netns-listeners",
		"<0-" TOSTRING(MAX_PROTO_LISTENERS) ">[,<0-" TOSTRING(MAX_PROTO_LISTENERS) ">]",
		"TCP count or TCP,UDP count",
		1,
		0,
		(spank_opt_cb_f) _spank_opt_listeners_process
	},
	{
		"iso-netns-options",
		"<options>",
		"Internal use only.",
		1,
		0,
		(spank_opt_cb_f) _spank_opt_options_process
	},
	{
		"iso-netns-http-proxy-conf",
		"<path>",
		"Internal use only.",
		1,
		0,
		(spank_opt_cb_f) _spank_opt_http_proxy_conf
	},
	{
		"iso-netns-proxies",
		"[tcp|udp@]<ipv4_addr|[ipv6_addr]>:<port>[,...]",
		"Internal use only. Brackets around IPv6 addresses are mandatory",
		1,
		0,
		(spank_opt_cb_f) _spank_opt_proxies
	},
	SPANK_OPTIONS_TABLE_END
};

/**
 * Listen on a random port for a specified protocol
 * 
 * @param sp         SPANK handle
 * @param proto      Protocol (IPPROTO_TCP or IPPROTO_UDP)
 * @param envvar_idx Index to use for environment variable names
 * 
 * @return Socket file descriptor or negative on error
 */
int _listen_to_random_port(spank_t sp, int proto, int envvar_idx) {
	int port = 0; /* Port 0 tells the kernel to assign a random available port */
	return _listen_to_port(sp, proto, NULL, &port, ENVVAR_NAME_PROTONUM, NULL, ENVVAR_NAME_PORTNUM, ENVVAR_NAME_FDNUM, envvar_idx);
}


/**
 * Creates a socket and binds it to the specified address/port
 * 
 * This function creates a socket of the specified protocol, binds it to
 * the given address and port, and exports the details as environment
 * variables with the provided base names plus the index.
 * 
 * @param sp                    SPANK handle
 * @param proto                 Protocol (IPPROTO_TCP or IPPROTO_UDP)
 * @param ip                    IP address to bind to, or NULL for INADDR_ANY
 * @param port                  Pointer to port number (0 = random, returns assigned port)
 * @param envvar_proto_basename Base name for protocol environment variable
 * @param envvar_ip_basename    Base name for IP environment variable
 * @param envvar_port_basename  Base name for port environment variable
 * @param envvar_fd_basename    Base name for file descriptor environment variable
 * @param envvar_idx            Index to append to environment variable names
 * 
 * @return Socket file descriptor or negative on error
 */
int _listen_to_port(spank_t sp, int proto, char *ip, int *port, char *envvar_proto_basename, char *envvar_ip_basename, char *envvar_port_basename, char *envvar_fd_basename, int envvar_idx) {
	int sockfd, one = 1, retval;
	struct sockaddr_in server_addr, actual_addr;
	socklen_t addr_len = sizeof(actual_addr);
	
	/* Validate protocol */
	if (proto != IPPROTO_TCP && proto != IPPROTO_UDP) {
		slurm_error(SPANK_MODULE_NAME_LC ": Only TCP and UDP are supported but proto %d was specified", proto);
		return ESPANK_ERROR;
	}

	/* Create the appropriate socket type based on protocol */
	if (proto == IPPROTO_TCP) {
		sockfd = socket(AF_INET, SOCK_STREAM, 0);
	} else {
		sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	}
	if (sockfd == -1) {
		slurm_error(SPANK_MODULE_NAME_LC ": Socket creation failed: %m");
		return ESPANK_ERROR;;
	}

	/* For TCP sockets, enable TCP_NODELAY to reduce latency */
	if (proto == IPPROTO_TCP) {
		retval = setsockopt(sockfd, SOL_TCP, TCP_NODELAY, &one, sizeof(one));
		if (retval) {
			slurm_error(SPANK_MODULE_NAME_LC ": setsockopt with TCP_NODELAY: %m");
			return ESPANK_ERROR;
		}
	}
	
	/* Prepare the sockaddr_in structure */
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(*port);

	/* Set the bind address - either INADDR_ANY or specified IP */
	if (ip == NULL) {
		server_addr.sin_addr.s_addr = INADDR_ANY;
	} else {
		retval = inet_pton(AF_INET, ip, &(server_addr.sin_addr));
		if (retval != 1) {
			slurm_error(SPANK_MODULE_NAME_LC ": inet_pton for %s: %m", ip);
			return ESPANK_ERROR;
		}

	}
	
	/* Bind socket */
	retval = bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr));
	if (retval) {
		slurm_error(SPANK_MODULE_NAME_LC ": bind failed for port %d: %m");
		return ESPANK_ERROR;
	}

	/* Get the actual port assigned by the kernel (important if we requested port 0) */
	retval = getsockname(sockfd, (struct sockaddr *)&actual_addr, &addr_len);
	   	if (retval < 0) {
		slurm_error(SPANK_MODULE_NAME_LC ": getsockname failed for bind on port %d: %m", *port);
		close(sockfd);
		return ESPANK_ERROR;
	}

	/* Update the port value with the one actually assigned by the kernel */
	*port = ntohs(actual_addr.sin_port);

	/* For TCP sockets, start listening for connections */
	if (proto == IPPROTO_TCP) {
		/* Start listening */
		if (listen(sockfd, LISTEN_BACKLOG) != 0) {
			slurm_error(SPANK_MODULE_NAME_LC ": listen on tcp:%s:%d : %m", ip, *port);
			close(sockfd);
			return ESPANK_ERROR;
		}
	}

	/* FIXME Still trying to figure out UDP. I've gotten it semi-working in various tests (not sure
	 * this code was that test), but I have not yet figured out how to get replies sent out of the
	 * outer namespace.
	 */
	if (proto == IPPROTO_UDP) {
		/* Initialize with INADDR_ANY and port 0 to allow receiving from any peer */
	/*	struct sockaddr_in any_peer;
		memset(&any_peer, 0, sizeof(any_peer));
		any_peer.sin_family = AF_INET;
		any_peer.sin_addr.s_addr = INADDR_ANY;
		any_peer.sin_port = 0;

		retval = connect(sockfd, (struct sockaddr*)&any_peer, sizeof(any_peer));
		if (retval) {
			slurm_error(SPANK_MODULE_NAME_LC ": connect failed for UDP socket: %m");
			close(sockfd);
			return ESPANK_ERROR;
		}*/
	}

	/* Log the newly created listener information */
	slurm_info(SPANK_MODULE_NAME_LC ": Listening on %s port %d", (proto == IPPROTO_TCP ? "tcp" : "udp"), *port);

	char proto_str_name[ENVVAR_VALUE_MAXLEN], ip_str_name[ENVVAR_VALUE_MAXLEN], fd_str[6], fd_str_name[ENVVAR_VALUE_MAXLEN], port_str[6], port_str_name[ENVVAR_VALUE_MAXLEN];

	/* Set protocol environment variable */
	if (envvar_proto_basename) {
		snprintf(proto_str_name, ENVVAR_VALUE_MAXLEN, "%s_%d", envvar_proto_basename, envvar_idx);
		setenv(proto_str_name, (proto == IPPROTO_TCP ? "tcp" : "udp"), 1);
		spank_setenv(sp, proto_str_name, (proto == IPPROTO_TCP ? "tcp" : "udp"), 1);
	}

	/* Set IP address environment variable if provided */
	if (envvar_ip_basename && ip) {
		snprintf(ip_str_name, ENVVAR_VALUE_MAXLEN, "%s_%d", envvar_ip_basename, envvar_idx);
		setenv(ip_str_name, ip, 1);
		spank_setenv(sp, ip_str_name, ip, 1);
	}

	/* Set file descriptor environment variable */
	snprintf(fd_str_name, ENVVAR_VALUE_MAXLEN, "%s_%d", envvar_fd_basename, envvar_idx);
	snprintf(fd_str, 6, "%d", sockfd);
	setenv(fd_str_name, fd_str, 1);
	spank_setenv(sp, fd_str_name, fd_str, 1);

	/* Set port environment variable */
	snprintf(port_str_name, ENVVAR_VALUE_MAXLEN, "%s_%d", envvar_port_basename, envvar_idx);
	snprintf(port_str, 6, "%d", *port);
	setenv(port_str_name, port_str, 1);
	spank_setenv(sp, port_str_name, port_str, 1);

	return sockfd; /* Return the socket file descriptor */
}

/**
 * Execute a command with the current environment
 *
 * This function directly replaces the current process with the specified
 * command, after setting up Slurm-related environment variables.
 *
 * Call clearenv() before here if you want a clean environment, which you
 * usually do.
 *
 * @param sp        SPANK handle
 * @param path      Path to executable
 * @param exec_argv Command arguments
 */
void _exec_cmd(spank_t sp, char *path, char **exec_argv) {
	uid_t job_uid;
	u_int32_t job_id;
	char jobid_str[UINT32_STR_SIZE], jobuid_str[UINT32_STR_SIZE];

	/* Get job ID and set it in the environment */
	spank_get_item(sp, S_JOB_ID, &job_id);
	snprintf(jobid_str, UINT32_STR_SIZE, "%u", job_id);
	setenv("SLURM_JOB_ID", jobid_str, 1);

	/* Get job UID and set it in the environment */
	spank_get_item(sp, S_JOB_UID, &job_uid);
	snprintf(jobuid_str, UINT32_STR_SIZE, "%u", job_uid);
	setenv("SLURM_JOB_UID", jobuid_str, 1);

	/* Pass through plugin options if present */
	if (opt_options) {
		setenv(ENVVAR_NAME_OPTIONS, opt_options, 1);
	}

	/* Pass through proxy configurations if present */
	if (proxies) {
		setenv(ENVVAR_NAME_PROXIES, proxies, 1);
	}

	/* Log debugging information if enabled */
	slurm_debug2("_exec_cmd %s about to execve", path);
	for (int i = 0; (char *)(environ[i]) != NULL; i++) {
		slurm_debug2("_exec_cmd %s about to execve: environ[%d]='%s'", path, i, (char*)(environ[i]));
	}

	/* Execute the command, replacing the current process */
	execve(path, exec_argv, environ);

	/* execve failed */
	slurm_error(SPANK_MODULE_NAME_LC ": execve failed for %s: %m", path);
	exit(1);
}

/**
 * Run a command in a child process and wait for it to complete
 *
 * This function forks a child process to run the specified command
 * with a clean environment, and waits for it to complete.
 *
 * @param sp        SPANK handle
 * @param path      Path to executable
 * @param exec_argv Command arguments
 *
 * @return Exit status of the command
 */
int _run_cmd(spank_t sp, char *path, char **exec_argv) {
	int status, retval;
	pid_t child, ppid;

	/* Get parent PID for namespace operations */
	ppid = getppid();

	if ( (child = fork()) ) {
		/* Parent. Wait for child. */
		waitpid(child, &status, 0);
		if (status != 0) {
			slurm_error(SPANK_MODULE_NAME_LC ": _run_cmd '%s' ... returned %d", path, status);
		}
	} else {
		/* Child */
		char ppid_str[UINT32_STR_SIZE], listeners_str[UINT32_STR_SIZE];

		/* Start with clean environment then set some environment variables */
		clearenv();

		snprintf(ppid_str, UINT32_STR_SIZE, "%d", ppid);
		setenv(ENVVAR_NAME_PPID, ppid_str, 1);

		snprintf(listeners_str, UINT32_STR_SIZE, "%d", opt_tcp_fd_cnt);
		setenv(ENVVAR_NAME_LISTENERS, listeners_str, 1);

		/* Exec. This never returns */
		_exec_cmd(sp, path, exec_argv);
	}

	return status;
}

/**
 * SPANK hook for user initialization
 *
 * This function is called when the Slurm job is initializing in the user's context.
 * It sets up listening ports in the "outer" network namespace.
 *
 * @param sp    SPANK handle
 * @param argc  Number of plugin arguments
 * @param argv  Plugin arguments
 *
 * @return ESPANK_SUCCESS or error code
 */
int slurm_spank_user_init (spank_t sp, int argc, char **argv) {
	int retval, envvar_idx;

	if (!spank_plugin_active) {
		return 0;
	}

	/* Listen on TCP ports on the outside of the new namespace. The fds will never be closed in this SPANK plugin. */
	for (envvar_idx = 0; envvar_idx < opt_tcp_fd_cnt; envvar_idx++) {
		retval = _listen_to_random_port(sp, IPPROTO_TCP, envvar_idx);
		if (retval == -1) {
			slurm_error(SPANK_MODULE_NAME_LC ": Fail! Could not listen on a TCP port for index %d.", envvar_idx);
			return -1;
		}
	}

	/* Listen on UDP ports on the outside of the new namespace. The fds will never be closed in this SPANK plugin. FIXME UDP is currently broken. */
	for ( ; envvar_idx < opt_tcp_fd_cnt + opt_udp_fd_cnt; envvar_idx++) {
		retval = _listen_to_random_port(sp, IPPROTO_UDP, envvar_idx);
		if (retval == -1) {
			slurm_error(SPANK_MODULE_NAME_LC ": Fail! Could not listen on a UDP port for index %d.", envvar_idx);
			return -1;
		}
	}
	return 0;
}

/**
 * Parse an address string into protocol, IP, port, and extra data
 * 
 * This function parses strings in formats like:
 * - "tcp@192.168.1.1:8080=extradata"
 * - "udp@[2001:db8::1]:53"
 * - "10.0.0.1:80"
 * 
 * @param input      Input address string
 * @param proto      Output protocol (IPPROTO_TCP or IPPROTO_UDP)
 * @param ip         Output IP address (buffer must be at least INET6_ADDRSTRLEN size)
 * @param port       Output port number
 * @param extra      Output buffer for extra data after '='
 * @param extra_size Size of extra buffer
 * 
 * @return ESPANK_SUCCESS or error code
 */
static int _parse_address(const char *input, int *proto, char *ip, int *port, char *extra, size_t extra_size) {
	if (!input || !proto || !ip || !port || !extra || extra_size == 0) {
		return ESPANK_ERROR;
	}

	/* Initialize output values */
	*proto = IPPROTO_TCP;
	*port = 0;
	ip[0] = '\0';
	extra[0] = '\0';

	/* Make a working copy since we'll modify the string */
	char *work = strdup(input);
	if (!work) {
		slurm_error(SPANK_MODULE_NAME_LC ": could not strdup '%s': %m", input);
		return ESPANK_ERROR;
	}

	/* Extract optional extra string after '=' */
	char *eq = strchr(work, '=');
	if (eq) {
		*eq = '\0'; /* Split at the '=' */
		eq++; /* Move to the extra data */
		strncpy(extra, eq, extra_size - 1);
		extra[extra_size - 1] = '\0'; /* Ensure null termination */
	}

	/* Detect protocol: format could be "tcp@..." or "udp@..." or no protocol. */
	char *at = strchr(work, '@');
	if (at) {
		/* Extract protocol specifier */
		*at = '\0';
		if (strcmp(work, "tcp") == 0) {
			*proto = IPPROTO_TCP;
		} else if (strcmp(work, "udp") == 0) {
			*proto = IPPROTO_UDP;
		} else {
			free(work);
			slurm_error(SPANK_MODULE_NAME_LC ": '%s' contains invalid protocol specifier %s", work);
			return ESPANK_ERROR;
		}
		/* Move to the address part */
		at++;
	} else {
		/* No protocol specified, use default (TCP) */
		at = work;
	}

	/* Now at points to something like "127.0.0.1:8080" or "[2001:db8::1]:53" */
	int is_ipv6 = 0;
	char *addr_start = at;
	char *addr_end = NULL;
	char *port_str = NULL;

	/* Check if this is an IPv6 address (has square brackets) */
	if (*addr_start == '[') {
		/* IPv6 format expected: [ipv6_addr]:port */
		is_ipv6 = 1;
		addr_start++; /* Skip opening bracket */
		addr_end = strchr(addr_start, ']');
		if (!addr_end) {
			free(work);
			slurm_error(SPANK_MODULE_NAME_LC ": '%s' missing closing bracket for IPv6", input);
			return ESPANK_ERROR; // Missing closing bracket for IPv6
		}
		*addr_end = '\0'; /* Terminate IPv6 address */

		/* Check for port specifier after closing bracket */
		port_str = addr_end + 1;
		if (*port_str != ':') {
			free(work);
			slurm_error(SPANK_MODULE_NAME_LC ": '%s' does not contain port number after IPv6 address", input);
			return ESPANK_ERROR; // No port after IPv6 address
		}
		port_str++; /* Skip colon */
	} else {
		/* IPv4 or hostname: find the colon separating address and port */
		port_str = strrchr(addr_start, ':');
		if (!port_str) {
			free(work);
			slurm_error(SPANK_MODULE_NAME_LC ": '%s' does not contain port number", input);
			return ESPANK_ERROR; // No port present
		}
		*port_str = '\0'; /* Terminate address */
		port_str++; /* Skip colon */
	}

	/* Parse the port number */
	char *endptr = NULL;
	long port_num = strtol(port_str, &endptr, 10);
	if (*endptr != '\0' && *endptr != '\0') {
		free(work);
		slurm_error(SPANK_MODULE_NAME_LC ": '%s' contains garbage '%s' after port number", input, endptr);
		return ESPANK_ERROR; // garbage after port number
	}
	if (port_num <= 0 || port_num > 65535) {
		free(work);
		slurm_error(SPANK_MODULE_NAME_LC ": '%s' contains invalid port number '%d'", input, port_num);
		return ESPANK_ERROR; // Invalid port
	}
	*port = (int)port_num;

	/* Validate and store IP address */
	if (is_ipv6) {
		/* Validate IPv6 address */
		struct in6_addr addr6;
		if (inet_pton(AF_INET6, addr_start, &addr6) != 1) {
			free(work);
			slurm_error(SPANK_MODULE_NAME_LC ": '%s' contains invalid IPv6 address", input);
			return ESPANK_ERROR;
		}
		strncpy(ip, addr_start, INET6_ADDRSTRLEN - 1);
		ip[INET6_ADDRSTRLEN - 1] = '\0';
	} else {
		/* Validate IPv4 address */
		struct in_addr addr4;
		if (inet_pton(AF_INET, addr_start, &addr4) != 1) {
			free(work);
			slurm_error(SPANK_MODULE_NAME_LC ": '%s' contains invalid IPv4 address", input);
			return ESPANK_ERROR;
		}
		strncpy(ip, addr_start, INET_ADDRSTRLEN - 1);
		ip[INET_ADDRSTRLEN - 1] = '\0';
	}

	free(work);
	return ESPANK_SUCCESS;
}

/**
 * Sets up network proxy sockets in the isolated network namespace
 * 
 * This function parses the proxy configurations and sets up listening
 * sockets for each proxy configuration within the new network namespace.
 *
 * This is launched inside the child process 
 *
 * @param sp SPANK handle
 * 
 * @return ESPANK_SUCCESS or error code
 */
int _launch_proxies(spank_t sp) {
	int envvar_idx = 0, status, retval;

	slurm_debug(SPANK_MODULE_NAME_LC ": _launch_proxies called with proxies '%s'", proxies);

	/* Start environment from scratch rather than doing execve */
	clearenv();

	if (proxies) {
		/* Make a copy of input since strtok modifies the string */
		char *input_copy = strdup(proxies);

		/* Process each proxy configuration (comma-separated) */
		char *token = strtok(input_copy, ",");
		while (token && envvar_idx <= MAX_PROXIES) {
			char ip[INET6_ADDRSTRLEN], extra[PROXY_EXTRA_LEN];
			int proto, port;

			/* Parse address format */
			*extra = '\0';
			if (_parse_address(token, &proto, ip, &port, extra, PROXY_EXTRA_LEN) != 0) {
				slurm_error(SPANK_MODULE_NAME_LC ": Invalid address format: %s", token);
				free(input_copy);
				
				return ESPANK_ERROR;
			}

			/* Create and bind socket for this proxy */
			int sockfd = _listen_to_port(sp, proto, ip, &port, ENVVAR_NAME_PROXY_PROTONUM, ENVVAR_NAME_PROXY_IPNUM, ENVVAR_NAME_PROXY_PORTNUM, ENVVAR_NAME_PROXY_FDNUM, envvar_idx);
			if (sockfd < 0) {
				slurm_error(SPANK_MODULE_NAME_LC ": Failed to bind to %s:%d: %m", ip, port);
				free(input_copy);
				
				return ESPANK_ERROR;
			}
			slurm_debug("Bound to %s:%d in inner namespace for proxying", ip, port);

			/* Store any extra configuration data as environment variable */
			if (extra) {
				char extra_name[ENVVAR_VALUE_MAXLEN];	
				snprintf(extra_name, ENVVAR_VALUE_MAXLEN, "%s_%d", ENVVAR_NAME_PROXY_EXTRANUM, envvar_idx);
				setenv(extra_name, extra, 1);
				spank_setenv(sp, extra_name, extra, 1);
			}
			envvar_idx++;
			token = strtok(NULL, ",");
		}

		free(input_copy);
	}

	/* Ports in the inner namespace are now opened for proxying */
	return ESPANK_SUCCESS;
}

/**
 * Print the current process's network namespace inode number
 * 
 * This is useful for debugging network namespace isolation issues.
 */
void _print_net_ns_inode() {
	char path[64];
	struct stat st;

	/* Get path to current process's network namespace */
	snprintf(path, sizeof(path), "/proc/%d/ns/net", getpid());

	/* Get inode number of the namespace */
	if (stat(path, &st) == -1) {
		slurm_error(SPANK_MODULE_NAME_LC ": stat: %m");
		return;
	}

	slurm_info(SPANK_MODULE_NAME_LC ": pid %d netns=%lu", getpid(), st.st_ino);
}

/**
 * Drop privileges to the job's user and group
 * 
 * This is used when we need to run processes as the job user
 * rather than as root.
 * 
 * @param job_uid Job uid
 * @param job_gid Job gid
 * 
 * @return ESPANK_SUCCESS or error code
 */
int _drop_privs(uid_t job_uid, gid_t job_gid) {
	struct passwd *pw;
	cap_t caps;
	int retval;

	/* Look up user information for job_uid */
	pw = getpwuid(job_uid);
	if (!pw) {
		slurm_error(SPANK_MODULE_NAME_LC ": getpwuid: %m");
		return ESPANK_ERROR;
	}

	/* Initialize supplementary groups for the user */
	retval = initgroups(pw->pw_name, job_gid);
	if (retval) {
		slurm_error(SPANK_MODULE_NAME_LC ": initgroups: %m");
		return ESPANK_ERROR;
	}

	/* Set real, effective, and saved group IDs */
	retval = setresgid(job_gid, job_gid, job_gid);
	if (retval) {
		slurm_error(SPANK_MODULE_NAME_LC ": setresgid: %m");
		return ESPANK_ERROR;
	}

	/* Set real, effective, and saved user IDs */
	retval = setresuid(job_uid, job_uid, job_uid);
	if (retval) {
		slurm_error(SPANK_MODULE_NAME_LC ": setresuid: %m");
		return ESPANK_ERROR;
	}

	/* Drop all capabilities */
	caps = cap_init();
	if (!caps) {
		slurm_error(SPANK_MODULE_NAME_LC ": cap_init: %m");
		return ESPANK_ERROR;
	}

	retval = cap_set_proc(caps);
	if (retval) {
		slurm_error(SPANK_MODULE_NAME_LC ": cap_set_proc: %m");
		cap_free(caps);
		return ESPANK_ERROR;
	}

	retval = cap_free(caps);
	if (retval) {
		slurm_error(SPANK_MODULE_NAME_LC ": cap_free: %m");
		return ESPANK_ERROR;
	}

	return ESPANK_SUCCESS;
}

/**
 * SPANK hook for privileged task initialization
 *
 * This is the main function that sets up the isolated network namespace.
 * It runs as root and creates a new network namespace for the job.
 *
 * @param sp    SPANK handle
 * @param argc  Number of plugin arguments
 * @param argv  Plugin arguments
 *
 * @return ESPANK_SUCCESS or error code
 */
int slurm_spank_task_init_privileged (spank_t sp, int argc, char **argv) {
	pid_t child;
	int status, retval, envvar_idx = 0, actual_fd_count = 0, outerns_fd = -1;
	char nspath[32];
	spank_err_t rc;
	uid_t job_uid;
	gid_t job_gid;
	u_int32_t job_id;

	if (!spank_plugin_active) {
		return 0;
	}

	/* Only execute in the remote (slurmstepd) context */
	if (!spank_remote(sp))
		return 0;

	if (spank_context() != S_CTX_REMOTE)
		return 0;

	slurm_debug(SPANK_MODULE_NAME_LC ": slurm_spank_task_init_privileged running");

	/* Get job information for later privilege dropping */
	spank_get_item(sp, S_JOB_ID, &job_id);
	spank_get_item(sp, S_JOB_UID, &job_uid);
	spank_get_item(sp, S_JOB_GID, &job_gid);

	/* Run pre-namespace-creation setup script as root */
	slurm_debug(SPANK_MODULE_NAME_LC ": Will exec %s pre-ns-creation", arg_setup_script);
	char *pre_ns_creation_argv[] = { BASH_SHELL, arg_setup_script, "pre-ns-creation", NULL };
	retval = _run_cmd(sp,"/bin/bash", pre_ns_creation_argv);
	if (retval) {
		slurm_error(SPANK_MODULE_NAME_LC ": error: \"%s pre-ns-creation\" returned %d", arg_setup_script, retval);
		return ESPANK_ERROR;
	}

	/* Open a file descriptor to the parent's network namespace. We'll need this later to return to the original namespace.
	 * I would use pidfd_open but I don't know what all is backported into old RHEL kernels, so I'll keep this portable
	 */
	snprintf(nspath, 32, "/proc/%d/ns/net", getppid());
	outerns_fd = open(nspath, O_RDONLY);
	if (outerns_fd < 0) {
		slurm_error(SPANK_MODULE_NAME_LC ": open '%s': %m");
		return ESPANK_ERROR;
	}

	/* Create a new network namespace */
	retval = unshare(CLONE_NEWNET);
	if (retval) {
		slurm_error(SPANK_MODULE_NAME_LC ": unshare failed: %m. (uid = %d)", getuid());
		return ESPANK_ERROR;
	}

	/* Run post-namespace-creation setup script as root */
	slurm_debug(SPANK_MODULE_NAME_LC ": Will exec %s post-ns-creation", arg_setup_script);
	char *post_ns_creation_argv[] = { BASH_SHELL, arg_setup_script, "post-ns-creation", NULL };
	retval = _run_cmd(sp,"/bin/bash", post_ns_creation_argv);
	if (retval) {
		slurm_error(SPANK_MODULE_NAME_LC ": error: \"%s post-ns-creation\" returned %d", arg_setup_script, retval);
		return ESPANK_ERROR;
	}

	/* Fork a child process to handle proxy setup */
	if ( (child = fork()) ) {
		/* Parent. Wait for child. */
		waitpid(child, &status, 0);
		if (status != 0) {
			slurm_error(SPANK_MODULE_NAME_LC ": Unable to launch requested proxies.");
			return ESPANK_ERROR;
		}
	} else {
		/* Child. Close unneeded fds */
		int fdlimit = (int)sysconf(_SC_OPEN_MAX);
		for (int i = 4; i < fdlimit; i++) {
			if (i != outerns_fd) {
				close(i);
			}
		}

		/* Set up proxy sockets in the inner namespace */
		retval = _launch_proxies(sp);
		if (retval) {
			slurm_error(SPANK_MODULE_NAME_LC ": _launch_proxies failed");
			exit(ESPANK_ERROR);
		}

		/* Switch back to the outer network namespace */
		retval = setns(outerns_fd, 0);
		if (retval) {
			slurm_error(SPANK_MODULE_NAME_LC ": setns: %m");
			exit(ESPANK_ERROR);
		}

		/* Drop privileges to the job user for security */
		if (_drop_privs(job_uid, job_gid) != ESPANK_SUCCESS) {
			slurm_error(SPANK_MODULE_NAME_LC ": Could not drop privileges prior to script post-ns-creation-outer execution");
			exit(ESPANK_ERROR);
		}

		/* Set HTTP proxy configuration if provided */
		if (http_proxy_conf) {
			setenv(ENVVAR_NAME_HTTP_PROXY_CONF, http_proxy_conf, 1);
		}

		/* Run post-namespace-creation-outer setup script as job user */
		slurm_debug(SPANK_MODULE_NAME_LC ": Will exec %s post-ns-creation-outer", arg_setup_script);
		char *post_ns_creation_outer_argv[] = { BASH_SHELL, arg_setup_script, "post-ns-creation-outer", NULL };
		_exec_cmd(sp, "/bin/bash", post_ns_creation_outer_argv);
	}

	/* Log environment for debugging purposes */
	for (int i = 0; (char *)(environ[i]) != NULL; i++) {
		slurm_debug2("_exec_cmd about to return from func: environ[%d]='%s'", i, (char*)(environ[i]));
	}
	return retval;
}

/**
 * SPANK hook for task exit
 *
 * This function is called when a task exits and allows for cleanup operations.
 *
 * @param sp    SPANK handle
 * @param argc  Number of plugin arguments
 * @param argv  Plugin arguments
 *
 * @return ESPANK_SUCCESS or error code
 */
int slurm_spank_task_exit (spank_t sp, int argc, char **argv) {
	pid_t child;
	int status, retval;
	spank_err_t rc = ESPANK_SUCCESS;

	if (!spank_plugin_active) {
		goto cleanup;
	}

	/* Only execute in the remote (slurmstepd) context */
	if (!spank_remote(sp)) {
		goto cleanup;
	}

	if (spank_context() != S_CTX_REMOTE) {
		goto cleanup;
	}

	/* Run task-exit setup script */
	slurm_debug(SPANK_MODULE_NAME_LC ": Will exec %s task-exit", arg_setup_script);
	char *task_exit_argv[] = { BASH_SHELL, arg_setup_script, "task-exit", NULL };
	retval = _run_cmd(sp,"/bin/bash", task_exit_argv);
	if (retval) {
		slurm_error(SPANK_MODULE_NAME_LC ": error: \"%s task-exit\" returned %d", arg_setup_script, retval);
		rc = ESPANK_ERROR;
		goto cleanup;
	}

cleanup:
	if (opt_options) {
		free(opt_options);
	}
	return rc;
}

/**
 * SPANK hook for job termination
 *
 * This function is called when the job exits and allows for final cleanup.
 * We don't need it, so return success.
 *
 * @param sp    SPANK handle
 * @param argc  Number of plugin arguments
 * @param argv  Plugin arguments
 *
 * @return ESPANK_SUCCESS or error code
 */
int slurm_spank_exit (spank_t sp, int argc, char **argv) {
	return ESPANK_SUCCESS;
}

/**
 * Callback for HTTP proxy configuration option
 *
 * @param val     Option value
 * @param optarg  Option argument string
 * @param remote  Whether this is a remote call
 *
 * @return 0 on success, -1 on failure
 */
static int _spank_opt_http_proxy_conf(int val, const char *optarg, int remote)
{
	http_proxy_conf = strdup(optarg);
	return 0;
}

/**
 * Callback for network proxies option
 *
 * This parses the --iso-netns-proxies option which specifies
 * proxy endpoints to create in the isolated namespace.
 *
 * @param val     Option value
 * @param optarg  Option argument string
 * @param remote  Whether this is a remote call
 *
 * @return ESPANK_SUCCESS or error code
 */
static int _spank_opt_proxies(int val, const char *optarg, int remote) {
	char ip[INET6_ADDRSTRLEN], extra[PROXY_EXTRA_LEN];
	int proto, port, listener_count = 0;

	if (!optarg || !*optarg) {
		return ESPANK_ERROR;
	}

	/* Make a working copy of the input string */
	char *input_copy = strdup(optarg);
	if (!input_copy) {
		fprintf(stderr, "Memory allocation failed\n");
		return ESPANK_ERROR;
	}

	/* Parse and validate each proxy configuration */
	char *saveptr = NULL;
	char *token = strtok_r(input_copy, ",", &saveptr);
	while (token && listener_count < MAX_PROXIES) {
		/* Validate address format */
		if (_parse_address(token, &proto, ip, &port, extra, PROXY_EXTRA_LEN) != 0) {
			fprintf(stderr, "Invalid address format: '%s'\n", token);
			free(input_copy);
			return ESPANK_ERROR;
		}
		listener_count++;
		token = strtok_r(NULL, ",", &saveptr);
	}

	/* Ensure at least one valid proxy configuration was provided */
	if (listener_count == 0) {
		free(input_copy);
		return ESPANK_ERROR;
	}

	/* Store the full proxy configuration string for later use */
	proxies = strdup(optarg);
	if (!proxies) {
		free(input_copy);
		return ESPANK_ERROR;
	}

	free(input_copy);
	return ESPANK_SUCCESS;
}

/**
 * Callback for listeners option
 *
 * This parses the --iso-netns-listeners option which specifies
 * the number of TCP and UDP listeners to create.
 *
 * @param val     Option value
 * @param optarg  Option argument string
 * @param remote  Whether this is a remote call
 *
 * @return 0 on success, -1 on failure
 */
static int _spank_opt_listeners_process(int val, const char *optarg, int remote)
{
	spank_err_t err;
	int tcp_fdcnt = -1;
	int udp_fdcnt = 0;
	char *comma_pos;
	char *endptr;
	char optarg_copy[32];

	spank_plugin_active = true;

	/* Copy optarg to avoid modifying the original string */
	if (strlen(optarg) >= sizeof(optarg_copy)) {
		slurm_error(SPANK_MODULE_NAME_LC ": argument too long");
		return -1;
	}
	strncpy(optarg_copy, optarg, sizeof(optarg_copy) - 1);
	optarg_copy[sizeof(optarg_copy) - 1] = '\0';

	/* Check if this is a TCP,UDP pair or just TCP count */
	comma_pos = strchr(optarg_copy, ',');
	if (comma_pos) {
		/* Parse as TCP,UDP pair */
		*comma_pos = '\0';  /* Split string at comma */

		/* Parse TCP listener count */
		tcp_fdcnt = strtol(optarg_copy, &endptr, 10);
		if (*endptr != '\0') {
			slurm_error(SPANK_MODULE_NAME_LC ": invalid TCP fd count");
			return -1;
		}

		/* Parse UDP listener count */
		udp_fdcnt = strtol(comma_pos + 1, &endptr, 10);
		if (*endptr != '\0') {
			slurm_error(SPANK_MODULE_NAME_LC ": invalid UDP fd count");
			return -1;
		}
	} else {
		/* Parse as single TCP value */
		tcp_fdcnt = strtol(optarg_copy, &endptr, 10);
		if (*endptr != '\0') {
			slurm_error(SPANK_MODULE_NAME_LC ": invalid TCP fd count");
			return -1;
		}
	}

	/* Validate listener counts are within acceptable range */
	if (tcp_fdcnt < 0 || tcp_fdcnt > MAX_PROTO_LISTENERS) {
		slurm_error(SPANK_MODULE_NAME_LC ": TCP listeners must be between 0 and " TOSTRING(MAX_PROTO_LISTENERS));
		return -1;
	}
	if (udp_fdcnt < 0 || udp_fdcnt > MAX_PROTO_LISTENERS) {
		slurm_error(SPANK_MODULE_NAME_LC ": UDP listeners must be between 0 and " TOSTRING(MAX_PROTO_LISTENERS));
		return -1;
	}

	/* Store the validated values */
	opt_tcp_fd_cnt = tcp_fdcnt;
	opt_udp_fd_cnt = udp_fdcnt;

	return 0;
}

/**
 * Callback for options processing
 *
 * This handles the --iso-netns-options option.
 *
 * @param val     Option value
 * @param optarg  Option argument string
 * @param remote  Whether this is a remote call
 *
 * @return 0 on success
 */
static int _spank_opt_options_process(int val, const char *optarg, int remote)
{
	spank_plugin_active = true;
	opt_options = strdup(optarg);

	return 0;
}

/**
 * Parse a plugin argument from plugstack.conf
 *
 * @param arg Argument string
 *
 * @return ESPANK_SUCCESS or error code
 */
spank_err_t _parse_spank_arg(char *arg) {
	if (!strncmp("setup_script=", arg, 13)) {
		arg_setup_script = arg+13;
		return ESPANK_SUCCESS;
	} else {
		 slurm_error(SPANK_MODULE_NAME_LC ": unknown plugin parameter '%s' from plugstack.conf", arg);
	}
	return ESPANK_ERROR;
}

/**
 * SPANK initialization hook
 *
 * This is called when the plugin is first loaded. It registers
 * the supported command-line options and processes plugstack.conf arguments.
 *
 * @param sp    SPANK handle
 * @param argc  Number of plugin arguments
 * @param argv  Plugin arguments
 *
 * @return ESPANK_SUCCESS or error code
 */
int slurm_spank_init (spank_t sp, int argc, char **argv) {
	int i;
	spank_err_t rc = ESPANK_SUCCESS;

	/* Register all plugin options with SPANK */
	for (i = 0; spank_opts[i].name; i++) {
		if ((rc = spank_option_register(sp, &spank_opts[i])) != ESPANK_SUCCESS) {
			slurm_error(SPANK_MODULE_NAME_LC ": spank_option_register: error registering %s: %s", spank_opts[i].name, spank_strerror(rc));
			break;
		}
	}

	/* Process plugin arguments from plugstack.conf */
	for (i = 0; i < argc; i++) {
		_parse_spank_arg(argv[i]);
	}
	return rc;
}
