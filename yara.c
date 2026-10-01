#include "yara.h"

#ifdef HAVE_YARA

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <dirent.h>
#include <sys/stat.h>
#include <yara.h>

#ifndef YARA_RULES_DIR
#define YARA_RULES_DIR "/etc/pigcloud-tee/yara"
#endif

#define YARA_TIMEOUT_SECONDS 15

static YR_RULES *g_rules = NULL;
static int g_initialized = 0;

typedef struct {
    int matched;
    char rule_name[256];
} scan_ctx_t;

static int yara_scan_callback(YR_SCAN_CONTEXT *context,
                              int message, void *message_data, void *user_data)
{
    (void)context;
    scan_ctx_t *ctx = (scan_ctx_t *)user_data;
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        YR_RULE *rule = (YR_RULE *)message_data;
        ctx->matched = 1;
        if (rule && rule->identifier && ctx->rule_name[0] == '\0') {
            snprintf(ctx->rule_name, sizeof(ctx->rule_name), "%s", rule->identifier);
        }
    }
    return CALLBACK_CONTINUE;
}

static int compile_dir_rules(YR_COMPILER *compiler, const char *dir_path, int *rules_added)
{
    DIR *dir = opendir(dir_path);
    if (!dir) {
        return 0;
    }

    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        size_t nlen = strlen(ent->d_name);
        if (nlen < 4 || strcasecmp(ent->d_name + nlen - 4, ".yar") != 0) {
            continue;
        }
        char path[1024];
        if (snprintf(path, sizeof(path), "%s/%s", dir_path, ent->d_name) >= (int)sizeof(path)) {
            continue;
        }
        FILE *fp = fopen(path, "r");
        if (!fp) continue;

        int errors = yr_compiler_add_file(compiler, fp, NULL, path);
        fclose(fp);
        if (errors > 0) {
            fprintf(stderr, "WARN: YARA: %d compile error(s) in %s\n", errors, path);
        } else {
            (*rules_added)++;
        }
    }
    closedir(dir);
    return 0;
}

int pigcloud_yara_init(void)
{
    if (g_initialized) return 0;

    if (yr_initialize() != ERROR_SUCCESS) {
        fprintf(stderr, "WARN: yr_initialize() failed — YARA scanning disabled\n");
        return -1;
    }

    struct stat st;
    if (stat(YARA_RULES_DIR, &st) != 0 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "INFO: YARA rules dir not found (%s) — scanning disabled\n", YARA_RULES_DIR);
        g_initialized = 1;
        return 0;
    }

    YR_COMPILER *compiler = NULL;
    if (yr_compiler_create(&compiler) != ERROR_SUCCESS) {
        fprintf(stderr, "WARN: yr_compiler_create() failed\n");
        yr_finalize();
        return -1;
    }

    int rules_added = 0;
    compile_dir_rules(compiler, YARA_RULES_DIR, &rules_added);

    if (rules_added == 0) {
        fprintf(stderr, "INFO: YARA: no rule files in %s — scanning disabled\n", YARA_RULES_DIR);
        yr_compiler_destroy(compiler);
        g_initialized = 1;
        return 0;
    }

    if (yr_compiler_get_rules(compiler, &g_rules) != ERROR_SUCCESS) {
        fprintf(stderr, "WARN: yr_compiler_get_rules() failed\n");
        yr_compiler_destroy(compiler);
        yr_finalize();
        return -1;
    }

    yr_compiler_destroy(compiler);
    fprintf(stderr, "INFO: YARA: loaded %d rule file(s) from %s\n", rules_added, YARA_RULES_DIR);
    g_initialized = 1;
    return 0;
}

pigcloud_yara_verdict_t pigcloud_yara_scan(
    const unsigned char *data, size_t len,
    char *rule_name_out, size_t rule_name_size)
{
    if (rule_name_out && rule_name_size > 0) rule_name_out[0] = '\0';

    if (!g_initialized || !g_rules) {
        return PIGCLOUD_YARA_UNAVAILABLE;
    }

    scan_ctx_t ctx = { .matched = 0 };
    int rc = yr_rules_scan_mem(
        g_rules,
        data, len,
        0,
        yara_scan_callback,
        &ctx,
        YARA_TIMEOUT_SECONDS
    );

    if (rc == ERROR_SCAN_TIMEOUT) {
        return PIGCLOUD_YARA_TIMEOUT;
    }
    if (rc != ERROR_SUCCESS) {
        return PIGCLOUD_YARA_UNAVAILABLE;
    }

    if (ctx.matched) {
        if (rule_name_out && rule_name_size > 0 && ctx.rule_name[0]) {
            snprintf(rule_name_out, rule_name_size, "%s", ctx.rule_name);
        }
        return PIGCLOUD_YARA_MATCH;
    }
    return PIGCLOUD_YARA_CLEAN;
}

void pigcloud_yara_destroy(void)
{
    if (!g_initialized) return;
    if (g_rules) {
        yr_rules_destroy(g_rules);
        g_rules = NULL;
    }
    yr_finalize();
    g_initialized = 0;
}

#else

int pigcloud_yara_init(void) { return 0; }
pigcloud_yara_verdict_t pigcloud_yara_scan(
    const unsigned char *data, size_t len,
    char *rule_name_out, size_t rule_name_size)
{
    (void)data; (void)len;
    if (rule_name_out && rule_name_size > 0) rule_name_out[0] = '\0';
    return PIGCLOUD_YARA_UNAVAILABLE;
}
void pigcloud_yara_destroy(void) {}

#endif
