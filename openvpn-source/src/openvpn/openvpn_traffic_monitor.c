/*
 * OpenVPN Traffic Monitor Plugin
 * 
 * This plugin monitors all decrypted/encrypted traffic in OpenVPN,
 * outputting plaintext data in hexadecimal format.
 * 
 * It hooks into the crypto layer to capture:
 * 1. Control channel messages (TLS handshake, key negotiation)
 * 2. Data channel traffic (actual tunneled IP packets)
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syshead.h"
#include "plugin.h"
#include "openvpn-plugin.h"
#include "buffer.h"
#include "error.h"
#include "ssl.h"
#include "crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* Plugin context structure */
struct traffic_monitor_context {
    int log_fd;              /* File descriptor for log output */
    FILE *log_file;          /* File stream for log output */
    bool log_to_stdout;      /* Whether to log to stdout instead of file */
    uint64_t packet_count;   /* Total packets monitored */
    uint64_t byte_count;     /* Total bytes monitored */
    time_t start_time;       /* Plugin start time */
};

/* Global plugin context */
static struct traffic_monitor_context *g_ctx = NULL;

/* Debug levels */
#define MONITOR_D_INFO     0x0001
#define MONITOR_D_PACKET   0x0002
#define MONITOR_D_HEX      0x0004
#define MONITOR_D_CONTROL  0x0008
#define MONITOR_D_DATA     0x0010

static int monitor_debug_level = MONITOR_D_INFO | MONITOR_D_PACKET | MONITOR_D_HEX;

/**
 * Print buffer content as hexadecimal string
 */
static void
print_hex_dump(FILE *fp, const char *prefix, const uint8_t *data, size_t len, int indent)
{
    char indent_str[32];
    int i, j;
    
    if (!fp || !data || len == 0)
        return;
    
    memset(indent_str, ' ', indent);
    indent_str[indent] = '\0';
    
    fprintf(fp, "%s%s (%zu bytes):\n", indent_str, prefix, len);
    
    for (i = 0; i < len; i += 16)
    {
        fprintf(fp, "%s%08x  ", indent_str, i);
        
        /* Hex values */
        for (j = 0; j < 16 && (i + j) < len; j++)
        {
            fprintf(fp, "%02x ", data[i + j]);
            if (j == 7)
                fprintf(fp, " ");
        }
        
        /* Pad with spaces */
        for (; j < 16; j++)
        {
            fprintf(fp, "   ");
            if (j == 7)
                fprintf(fp, " ");
        }
        
        /* ASCII representation */
        fprintf(fp, " |");
        for (j = 0; j < 16 && (i + j) < len; j++)
        {
            unsigned char c = data[i + j];
            fprintf(fp, "%c", (c >= 32 && c < 127) ? c : '.');
        }
        fprintf(fp, "|\n");
    }
}

/**
 * Print buffer content as compact hex string (single line)
 */
static void
print_hex_compact(FILE *fp, const char *prefix, const uint8_t *data, size_t len)
{
    size_t i;
    
    if (!fp || !data || len == 0)
        return;
    
    fprintf(fp, "%s [%zu bytes]: ", prefix, len);
    
    for (i = 0; i < len && i < 512; i++)  /* Limit to first 512 bytes */
    {
        fprintf(fp, "%02x", data[i]);
        if (i % 4 == 3 && i < len - 1)
            fprintf(fp, " ");
    }
    
    if (len > 512)
        fprintf(fp, "... (truncated)");
    
    fprintf(fp, "\n");
}

/**
 * Get current timestamp as string
 */
static void
get_timestamp(char *buf, size_t size)
{
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    
    strftime(buf, size, "%Y-%m-%d %H:%M:%S", tm_info);
}

/**
 * Log a control channel packet (plaintext after decryption)
 */
static void
monitor_control_packet(struct traffic_monitor_context *ctx,
                       const char *direction,
                       const uint8_t *data,
                       size_t len,
                       const char *peer_info)
{
    char timestamp[64];
    const char *opcode_names[] = {
        "P_CONTROL_HARD_RESET_CLIENT_V2",
        "P_CONTROL_HARD_RESET_SERVER_V2",
        "P_CONTROL_SOFT_RESET_V1",
        "P_CONTROL_V1",
        "P_ACK_V1",
        "P_CONTROL_HARD_RESET_CLIENT_V3",
        "P_CONTROL_WKC_V1"
    };
    const char *opcode_name = "UNKNOWN";
    uint8_t opcode;
    
    if (!ctx || !data || len < 1)
        return;
    
    if (!(monitor_debug_level & MONITOR_D_CONTROL))
        return;
    
    get_timestamp(timestamp, sizeof(timestamp));
    
    /* Extract opcode from first byte */
    opcode = (*data >> P_OPCODE_SHIFT) & 0x0F;
    if (opcode < sizeof(opcode_names)/sizeof(opcode_names[0]))
        opcode_name = opcode_names[opcode];
    
    if (ctx->log_file)
    {
        fprintf(ctx->log_file, "\n");
        fprintf(ctx->log_file, "=== CONTROL CHANNEL [%s] %s ===\n", direction, timestamp);
        if (peer_info)
            fprintf(ctx->log_file, "Peer: %s\n", peer_info);
        fprintf(ctx->log_file, "Opcode: %s (%d)\n", opcode_name, opcode);
        
        if (monitor_debug_level & MONITOR_D_HEX)
        {
            print_hex_dump(ctx->log_file, "Plaintext payload", data, len, 0);
        }
        else
        {
            print_hex_compact(ctx->log_file, "Plaintext payload", data, len);
        }
        
        fflush(ctx->log_file);
    }
    
    if (ctx->log_to_stdout)
    {
        printf("\n=== CONTROL CHANNEL [%s] %s ===\n", direction, timestamp);
        if (peer_info)
            printf("Peer: %s\n", peer_info);
        printf("Opcode: %s (%d)\n", opcode_name, opcode);
        
        if (monitor_debug_level & MONITOR_D_HEX)
        {
            print_hex_dump(stdout, "Plaintext payload", data, len, 0);
        }
        else
        {
            print_hex_compact(stdout, "Plaintext payload", data, len);
        }
        
        fflush(stdout);
    }
    
    ctx->packet_count++;
    ctx->byte_count += len;
}

/**
 * Log a data channel packet (plaintext after decryption)
 */
static void
monitor_data_packet(struct traffic_monitor_context *ctx,
                    const char *direction,
                    const uint8_t *data,
                    size_t len,
                    const char *peer_info)
{
    char timestamp[64];
    
    if (!ctx || !data || len == 0)
        return;
    
    if (!(monitor_debug_level & MONITOR_D_DATA))
        return;
    
    get_timestamp(timestamp, sizeof(timestamp));
    
    if (ctx->log_file)
    {
        fprintf(ctx->log_file, "\n");
        fprintf(ctx->log_file, "--- DATA CHANNEL [%s] %s ---\n", direction, timestamp);
        if (peer_info)
            fprintf(ctx->log_file, "Peer: %s\n", peer_info);
        fprintf(ctx->log_file, "Packet length: %zu bytes\n", len);
        
        /* Show IP header info if present */
        if (len >= 20)
        {
            uint8_t ip_version = (data[0] >> 4) & 0x0F;
            if (ip_version == 4 && len >= 20)
            {
                fprintf(ctx->log_file, "IPv4 Packet: src=%d.%d.%d.%d, dst=%d.%d.%d.%d, proto=%d\n",
                        data[12], data[13], data[14], data[15],
                        data[16], data[17], data[18], data[19],
                        data[9]);
            }
            else if (ip_version == 6 && len >= 40)
            {
                fprintf(ctx->log_file, "IPv6 Packet\n");
            }
        }
        
        if (monitor_debug_level & MONITOR_D_HEX)
        {
            print_hex_dump(ctx->log_file, "Plaintext payload", data, len, 0);
        }
        else
        {
            print_hex_compact(ctx->log_file, "Plaintext payload", data, len);
        }
        
        fflush(ctx->log_file);
    }
    
    if (ctx->log_to_stdout)
    {
        printf("\n--- DATA CHANNEL [%s] %s ---\n", direction, timestamp);
        if (peer_info)
            printf("Peer: %s\n", peer_info);
        printf("Packet length: %zu bytes\n", len);
        
        /* Show IP header info if present */
        if (len >= 20)
        {
            uint8_t ip_version = (data[0] >> 4) & 0x0F;
            if (ip_version == 4 && len >= 20)
            {
                printf("IPv4 Packet: src=%d.%d.%d.%d, dst=%d.%d.%d.%d, proto=%d\n",
                        data[12], data[13], data[14], data[15],
                        data[16], data[17], data[18], data[19],
                        data[9]);
            }
            else if (ip_version == 6 && len >= 40)
            {
                printf("IPv6 Packet\n");
            }
        }
        
        if (monitor_debug_level & MONITOR_D_HEX)
        {
            print_hex_dump(stdout, "Plaintext payload", data, len, 0);
        }
        else
        {
            print_hex_compact(stdout, "Plaintext payload", data, len);
        }
        
        fflush(stdout);
    }
    
    ctx->packet_count++;
    ctx->byte_count += len;
}

/**
 * Initialize plugin
 */
OPENVPN_EXPORT int
openvpn_plugin_open_v3(const int v3structver,
                       struct openvpn_plugin_args_open_in const *args,
                       struct openvpn_plugin_args_open_return *ret)
{
    struct traffic_monitor_context *ctx;
    const char *log_file_path = NULL;
    int i;
    
    msg(D_PLUGIN, "Traffic Monitor Plugin: initializing...");
    
    /* Parse arguments */
    for (i = 0; args->argv[i]; i++)
    {
        if (strncmp(args->argv[i], "log=", 4) == 0)
        {
            log_file_path = args->argv[i] + 4;
        }
        else if (strcmp(args->argv[i], "stdout") == 0)
        {
            /* Will log to stdout */
        }
        else if (strncmp(args->argv[i], "debug=", 6) == 0)
        {
            monitor_debug_level = atoi(args->argv[i] + 6);
        }
    }
    
    /* Allocate context */
    ctx = (struct traffic_monitor_context *)calloc(1, sizeof(struct traffic_monitor_context));
    if (!ctx)
    {
        msg(D_PLUGIN, "Traffic Monitor Plugin: failed to allocate context");
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }
    
    ctx->start_time = time(NULL);
    ctx->packet_count = 0;
    ctx->byte_count = 0;
    
    /* Setup logging */
    if (log_file_path && strlen(log_file_path) > 0)
    {
        ctx->log_file = fopen(log_file_path, "a");
        if (!ctx->log_file)
        {
            msg(D_PLUGIN, "Traffic Monitor Plugin: failed to open log file: %s", log_file_path);
            free(ctx);
            return OPENVPN_PLUGIN_FUNC_ERROR;
        }
        ctx->log_to_stdout = false;
        fprintf(ctx->log_file, "=== Traffic Monitor Plugin Started ===\n");
        fprintf(ctx->log_file, "Log file: %s\n", log_file_path);
        fflush(ctx->log_file);
    }
    else
    {
        ctx->log_to_stdout = true;
        printf("=== Traffic Monitor Plugin Started ===\n");
        printf("Logging to stdout\n");
        fflush(stdout);
    }
    
    g_ctx = ctx;
    
    /* Setup return structure */
    ret->handle = ctx;
    ret->struct_version = OPENVPN_PLUGIN_STRUCT_VERSION_CURRENT;
    ret->callbacks = NULL;  /* We use hook-based monitoring, not callbacks */
    
    msg(D_PLUGIN, "Traffic Monitor Plugin: initialized successfully");
    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

/**
 * Close plugin
 */
OPENVPN_EXPORT int
openvpn_plugin_close_v1(openvpn_plugin_handle_t handle)
{
    struct traffic_monitor_context *ctx = (struct traffic_monitor_context *)handle;
    char timestamp[64];
    
    if (!ctx)
        return OPENVPN_PLUGIN_FUNC_SUCCESS;
    
    get_timestamp(timestamp, sizeof(timestamp));
    
    if (ctx->log_file)
    {
        fprintf(ctx->log_file, "\n=== Traffic Monitor Plugin Stopped ===\n");
        fprintf(ctx->log_file, "Timestamp: %s\n", timestamp);
        fprintf(ctx->log_file, "Total packets monitored: %lu\n", (unsigned long)ctx->packet_count);
        fprintf(ctx->log_file, "Total bytes monitored: %lu\n", (unsigned long)ctx->byte_count);
        fclose(ctx->log_file);
    }
    
    if (ctx->log_to_stdout)
    {
        printf("\n=== Traffic Monitor Plugin Stopped ===\n");
        printf("Timestamp: %s\n", timestamp);
        printf("Total packets monitored: %lu\n", (unsigned long)ctx->packet_count);
        printf("Total bytes monitored: %lu\n", (unsigned long)ctx->byte_count);
        fflush(stdout);
    }
    
    free(ctx);
    g_ctx = NULL;
    
    msg(D_PLUGIN, "Traffic Monitor Plugin: closed");
    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

/**
 * Plugin constructor
 */
OPENVPN_EXPORT void
openvpn_plugin_constructor(void)
{
    msg(D_PLUGIN, "Traffic Monitor Plugin: constructor called");
}

/**
 * Plugin destructor
 */
OPENVPN_EXPORT void
openvpn_plugin_destructor(void)
{
    msg(D_PLUGIN, "Traffic Monitor Plugin: destructor called");
}

/*
 * Hook functions for monitoring decrypted/encrypted traffic
 * These need to be integrated into OpenVPN's crypto.c and ssl_pkt.c
 */

/**
 * Hook called after decrypting a control channel packet
 * This should be called from read_control_auth() in ssl_pkt.c
 * after successful authentication/decryption
 */
void
traffic_monitor_control_decrypted(const uint8_t *data, size_t len,
                                   const char *peer_info, bool incoming)
{
    if (!g_ctx || !data || len == 0)
        return;
    
    monitor_control_packet(g_ctx, incoming ? "RX" : "TX", data, len, peer_info);
}

/**
 * Hook called after decrypting a data channel packet
 * This should be called from openvpn_decrypt() in crypto.c
 * after successful decryption
 */
void
traffic_monitor_data_decrypted(const uint8_t *data, size_t len,
                                const char *peer_info, bool incoming)
{
    if (!g_ctx || !data || len == 0)
        return;
    
    monitor_data_packet(g_ctx, incoming ? "RX" : "TX", data, len, peer_info);
}

/**
 * Hook called before encrypting a control channel packet
 * This should be called from write_control_auth() in ssl_pkt.c
 * before encryption
 */
void
traffic_monitor_control_encrypted(const uint8_t *data, size_t len,
                                   const char *peer_info, bool incoming)
{
    if (!g_ctx || !data || len == 0)
        return;
    
    monitor_control_packet(g_ctx, incoming ? "RX" : "TX", data, len, peer_info);
}

/**
 * Hook called before encrypting a data channel packet
 * This should be called from openvpn_encrypt() in crypto.c
 * before encryption
 */
void
traffic_monitor_data_encrypted(const uint8_t *data, size_t len,
                                const char *peer_info, bool incoming)
{
    if (!g_ctx || !data || len == 0)
        return;
    
    monitor_data_packet(g_ctx, incoming ? "RX" : "TX", data, len, peer_info);
}
