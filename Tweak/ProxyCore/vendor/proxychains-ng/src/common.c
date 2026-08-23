#include "common.h"
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>

const char *proxy_type_strmap[] = {
    "http",
    "socks4",
    "socks5",
};

const char *chain_type_strmap[] = {
    "dynamic_chain",
    "strict_chain",
    "random_chain",
    "round_robin_chain",
};

const char *proxy_state_strmap[] = {
    "play",
    "down",
    "blocked",
    "busy",
};

/* isnumericipv4() taken from libulz */
int pc_isnumericipv4(const char* ipstring) {
	size_t x = 0, n = 0, d = 0;
	int wasdot = 0;
	while(1) {
		switch(ipstring[x]) {
			case 0: goto done;
			case '.':
				if(!n || wasdot) return 0;
				d++;
				wasdot = 1;
				break;
			case '0': case '1': case '2': case '3': case '4':
			case '5': case '6': case '7': case '8': case '9':
				n++;
				wasdot = 0;
				break;
			default:
				return 0;
		}
		x++;
	}
	done:
	if(d == 3 && n >= 4 && n <= 12) return 1;
	return 0;
}

// stolen from libulz (C) rofl0r
void pc_stringfromipv4(unsigned char *ip_buf_4_bytes, char *outbuf_16_bytes) {
	unsigned char *p;
	char *o = outbuf_16_bytes;
	unsigned char n;
	for(p = ip_buf_4_bytes; p < ip_buf_4_bytes + 4; p++) {
		n = *p;
		if(*p >= 100) {
			if(*p >= 200)
				*(o++) = '2';
			else
				*(o++) = '1';
			n %= 100;
		}
		if(*p >= 10) {
			*(o++) = (n / 10) + '0';
			n %= 10;
		}
		*(o++) = n + '0';
		*(o++) = '.';
	}
	o[-1] = 0;
}

static int check_path(char *path) {
	if(!path)
		return 0;
	return access(path, R_OK) != -1;
}

char *get_config_path(char* default_path, char* pbuf, size_t bufsize) {
	(void)default_path;
	Dl_info dli;
	if(!dladdr((void*)&get_config_path, &dli) || !dli.dli_fname || !dli.dli_fname[0])
		return NULL;

	snprintf(pbuf, bufsize, "%s", dli.dli_fname);
	char *slash = strrchr(pbuf, '/');
	if(!slash)
		return NULL;
	*slash = '\0';

	// Only read the config file managed by LCTailscaleControl.
	// This avoids interference from other proxychains.conf files on the system.
	// The dylib may be installed in <shared root>/Tweaks or a subfolder of Tweaks
	// (LiveContainer shared-app mode). In both cases the managed config lives in
	// <shared root>/LCProxy/proxychains.conf.
	char *tweaks = NULL;
	size_t plen = strlen(pbuf);
	for (size_t i = plen; i >= 7; i--) {
		if (pbuf[i - 7] == '/' && strncmp(pbuf + i - 7, "/Tweaks", 7) == 0) {
			tweaks = pbuf + i - 7;
			break;
		}
	}
	if (tweaks) {
		*tweaks = '\0';
		if (strlen(pbuf) + sizeof("/LCProxy/" PROXYCHAINS_CONF_FILE) <= bufsize) {
			strncat(pbuf, "/LCProxy/" PROXYCHAINS_CONF_FILE, bufsize - strlen(pbuf) - 1);
		} else {
			return NULL;
		}
	} else {
		const char *base = strrchr(pbuf, '/');
		base = base ? base + 1 : pbuf;
		if(strcmp(base, "LCProxy") == 0) {
			if(strlen(pbuf) + sizeof("/" PROXYCHAINS_CONF_FILE) <= bufsize) {
				strncat(pbuf, "/" PROXYCHAINS_CONF_FILE, bufsize - strlen(pbuf) - 1);
			} else {
				return NULL;
			}
		} else {
			if(strlen(pbuf) + sizeof("/../LCProxy/" PROXYCHAINS_CONF_FILE) <= bufsize) {
				strncat(pbuf, "/../LCProxy/" PROXYCHAINS_CONF_FILE, bufsize - strlen(pbuf) - 1);
			} else {
				return NULL;
			}
		}
	}

	if(check_path(pbuf))
		return pbuf;
	return NULL;
}
