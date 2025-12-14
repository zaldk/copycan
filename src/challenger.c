#include "mongoose.h"
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>

FILE *log_fp = NULL;

// Helper to log to file with timestamp
void logger(const char *fmt, ...) {
    if (!log_fp) return;

    time_t rawtime;
    struct tm *timeinfo;
    char time_str[20];
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    strftime(time_str, sizeof(time_str), "%H:%M:%S", timeinfo);

    fprintf(log_fp, "[%s] ", time_str);

    va_list args;
    va_start(args, fmt);
    vfprintf(log_fp, fmt, args);
    va_end(args);

    fflush(log_fp);
}

// Difficulty: 4 hex zeroes (16 bits) at the end.
int check_difficulty(unsigned char *hash) {
    if (hash[31] != 0) return 0;
    if (hash[30] != 0) return 0;
    return 1;
}

static void fn(struct mg_connection *c, int ev, void *ev_data) {
    if (ev == MG_EV_HTTP_MSG) {
        struct mg_http_message *hm = (struct mg_http_message *) ev_data;

        if (mg_match(hm->uri, mg_str("/verify"), NULL)) {
            int clen = 0, plen = 0;
            // Get offsets
            int coff = mg_json_get(hm->body, "$.content", &clen);
            int poff = mg_json_get(hm->body, "$.prefix", &plen);

            if (coff >= 0 && poff >= 0) {
                const char *cptr_raw = hm->body.buf + coff;
                const char *pptr_raw = hm->body.buf + poff;

                // Allocate buffers
                char *content_clean = calloc(1, clen + 1);
                char *prefix_clean = calloc(1, plen + 1);

                mg_json_unescape(mg_str_n(cptr_raw, clen), content_clean, clen);
                mg_json_unescape(mg_str_n(pptr_raw, plen), prefix_clean, plen);
                size_t c_len = strnlen(content_clean, clen+1) - 2;
                size_t p_len = strnlen(prefix_clean, plen+1) - 2;
                content_clean += 1;
                prefix_clean += 1;

                // --- Concatenate for one-shot SHA256 ---
                size_t total_len = p_len + c_len;
                unsigned char *combined = malloc(total_len);
                if (combined) {
                    memcpy(combined, prefix_clean, p_len);
                    memcpy(combined + p_len, content_clean, c_len);

                    unsigned char hash[SHA256_DIGEST_LENGTH] = {0};

                    // One-shot OpenSSL call
                    SHA256(combined, total_len, hash);

                    int valid = check_difficulty(hash);

                    // Debug Logging
                    logger("Checking: Prefix=%s|%d Content=%s|%d Combined=%s|%d\n", prefix_clean, p_len, content_clean, c_len, combined, total_len);
                    fprintf(log_fp, "       Hash: ");
                    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) fprintf(log_fp, "%02X", hash[i]);
                    fprintf(log_fp, "\n");
                    fflush(log_fp);

                    logger("[Challenger:%s] Result: %s\n", (char*)c->fn_data, valid ? "PASS" : "FAIL");

                    mg_http_reply(c, 200, "Content-Type: application/json\r\n",
                                  "{ \"valid\": %s }", valid ? "true" : "false");

                    free(combined);
                } else {
                    logger("[Challenger:%s] Memory Allocation Error\n", (char*)c->fn_data);
                    mg_http_reply(c, 500, "", "Internal Server Error");
                }

                free(content_clean-1);
                free(prefix_clean-1);
            } else {
                logger("[Challenger:%s] Bad Request (Missing JSON fields)\n", (char*)c->fn_data);
                mg_http_reply(c, 400, "", "Bad Request");
            }
        } else {
            mg_http_reply(c, 404, "", "Not Found");
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <port>\n", argv[0]);
        return 1;
    }

    log_fp = fopen("challenger.log", "a");
    if (log_fp == NULL) {
        perror("Failed to open challenger.log");
        return 1;
    }
    setbuf(log_fp, NULL);

    struct mg_mgr mgr;
    mg_mgr_init(&mgr);

    char addr[32];
    snprintf(addr, sizeof(addr), "0.0.0.0:%s", argv[1]);

    mg_http_listen(&mgr, addr, fn, argv[1]);

    logger("--------------------------------------------------\n");
    logger("[Main] Service started on %s\n", addr);

    for (;;) mg_mgr_poll(&mgr, 1000);

    mg_mgr_free(&mgr);
    fclose(log_fp);
    return 0;
}
