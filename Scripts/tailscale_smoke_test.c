#include "tailscale.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    const char *key = getenv("TAILSCALE_AUTH_KEY");
    if (!key || !*key) {
        printf("SKIP: no TAILSCALE_AUTH_KEY\n");
        return 0;
    }

    tailscale sd = tailscale_new();
    if (sd < 0) {
        fprintf(stderr, "tailscale_new failed\n");
        return 1;
    }

    const char *tmp = getenv("TMPDIR");
    char dir[512];
    snprintf(dir, sizeof(dir), "%s/tailscale-ci-%ld", tmp ? tmp : "/tmp", (long)getpid());
    tailscale_set_dir(sd, dir);
    tailscale_set_hostname(sd, "ci-tailscale-test");
    tailscale_set_authkey(sd, key);
    tailscale_set_ephemeral(sd, 1);
    tailscale_set_disable_p2p(sd, 1);

    if (tailscale_up(sd) != 0) {
        char err[1024] = {0};
        tailscale_errmsg(sd, err, sizeof(err));
        fprintf(stderr, "tailscale_up failed: %s\n", err);
        tailscale_close(sd);
        return 1;
    }

    char buf[1024 * 1024];
    if (tailscale_get_status_json(sd, buf, sizeof(buf)) != 0) {
        fprintf(stderr, "tailscale_get_status_json failed\n");
        tailscale_close(sd);
        return 1;
    }
    if (!strstr(buf, "\"BackendState\":\"Running\"")) {
        fprintf(stderr, "not running: %.200s\n", buf);
        tailscale_close(sd);
        return 1;
    }

    if (tailscale_get_full_status_json(sd, buf, sizeof(buf)) != 0) {
        fprintf(stderr, "tailscale_get_full_status_json failed\n");
        tailscale_close(sd);
        return 1;
    }

    if (tailscale_get_prefs_json(sd, buf, sizeof(buf)) != 0) {
        fprintf(stderr, "tailscale_get_prefs_json failed\n");
        tailscale_close(sd);
        return 1;
    }

    if (tailscale_set_exit_node(sd, "", 0) != 0) {
        fprintf(stderr, "tailscale_set_exit_node(clear) failed\n");
        tailscale_close(sd);
        return 1;
    }

    tailscale_close(sd);
    printf("tailscale smoke test OK\n");
    return 0;
}
