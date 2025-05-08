#ifndef NETWORK_MONITOR3_H
#define NETWORK_MONITOR3_H

// Start with winsock headers
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

// Then include other Windows headers
#include <windows.h>
#include <process.h>
#include <wininet.h>
#include <io.h>

// Standard C libraries
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <ctype.h>
#include <math.h>
#include <stdbool.h>

// Link required libraries
#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "wininet.lib")
#endif

// Constants
#define SERVICE_NAME "NexLog"
#define SERVICE_DISPLAY_NAME "Enhanced Network Traffic Monitor v3"
#define SERVICE_DESC "Advanced network traffic capture and anomaly detection service"

#define SERVER_IP "34.173.42.188"
#define SERVER_PORT 3000
#define LOG_RETENTION_HOURS 6
#define SEND_INTERVAL 30
#define PING_INTERVAL 90
#define MAX_PACKET_SIZE 65536
#define MAX_FLOWS 10000
#define MAX_CONNECTIONS_TRACKED 100 // Per host connection history
#define CONNECTION_WINDOW 2         // Time window in seconds for connection stats
#define MAX_SERVICE_NAME 32
#define MAX_FLAG_NAME 8
#define MAX_HOSTS_TRACKED 5000
#define HASH_TABLE_SIZE 8192

// Protocol definitions
#define PROTO_TCP 6
#define PROTO_UDP 17
#define PROTO_ICMP 1
#define CLOCK_REALTIME 0

// TCP flag masks
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20
#define TCP_ECE 0x40
#define TCP_CWR 0x80

// Struct definitions for packet headers
typedef struct
{
    unsigned char ip_hl : 4;
    unsigned char ip_v : 4;
    unsigned char ip_tos;
    unsigned short ip_len;
    unsigned short ip_id;
    unsigned short ip_off;
    unsigned char ip_ttl;
    unsigned char ip_p;
    unsigned short ip_sum;
    unsigned int ip_src;
    unsigned int ip_dst;
} IP_HEADER;

typedef struct
{
    unsigned short th_sport;
    unsigned short th_dport;
    unsigned int th_seq;
    unsigned int th_ack;
    unsigned char th_x2 : 4;
    unsigned char th_off : 4;
    unsigned char th_flags;
    unsigned short th_win;
    unsigned short th_sum;
    unsigned short th_urp;
} TCP_HEADER;

typedef struct
{
    unsigned short uh_sport;
    unsigned short uh_dport;
    unsigned short uh_len;
    unsigned short uh_sum;
} UDP_HEADER;

typedef struct
{
    unsigned char type;
    unsigned char code;
    unsigned short checksum;
    unsigned int rest_of_header;
} ICMP_HEADER;

// Service type enumeration
typedef enum
{
    SRV_UNKNOWN = 0,
    SRV_AOL,
    SRV_AUTH,
    SRV_BGP,
    SRV_COURIER,
    SRV_CSNET_NS,
    SRV_CTF,
    SRV_DAYTIME,
    SRV_DISCARD,
    SRV_DOMAIN,
    SRV_DOMAIN_U,
    SRV_ECHO,
    SRV_ECO_I,
    SRV_ECR_I,
    SRV_EFS,
    SRV_EXEC,
    SRV_FINGER,
    SRV_FTP,
    SRV_FTP_DATA,
    SRV_GOPHER,
    SRV_HARVEST,
    SRV_HOSTNAMES,
    SRV_HTTP,
    SRV_HTTP_2784,
    SRV_HTTP_443,
    SRV_HTTP_8001,
    SRV_IMAP4,
    SRV_IRC,
    SRV_ISO_TSAP,
    SRV_KLOGIN,
    SRV_KSHELL,
    SRV_LDAP,
    SRV_LINK,
    SRV_LOGIN,
    SRV_MTP,
    SRV_NAME,
    SRV_NETBIOS_DGM,
    SRV_NETBIOS_NS,
    SRV_NETBIOS_SSN,
    SRV_NETSTAT,
    SRV_NNSP,
    SRV_NNTP,
    SRV_NTP_U,
    SRV_OTHER,
    SRV_PM_DUMP,
    SRV_POP_2,
    SRV_POP_3,
    SRV_PRINTER,
    SRV_PRIVATE,
    SRV_RED_I,
    SRV_REMOTE_JOB,
    SRV_RJE,
    SRV_SHELL,
    SRV_SMTP,
    SRV_SQL_NET,
    SRV_SSH,
    SRV_SUNRPC,
    SRV_SUPDUP,
    SRV_SYSTAT,
    SRV_TELNET,
    SRV_TFTP_U,
    SRV_TIM_I,
    SRV_TIME,
    SRV_URH_I,
    SRV_URP_I,
    SRV_UUCP,
    SRV_UUCP_PATH,
    SRV_VMNET,
    SRV_WHOIS,
    SRV_X11,
    SRV_Z39_50,
    SRV_MAX
} service_type_t;

// Connection flag types (for reporting)
typedef enum
{
    F_OTH = 0, // Other
    F_REJ,     // Rejected
    F_RSTO,    // Reset by originator
    F_RSTOS0,  // Reset by originator with SYN flag but no ACK
    F_RSTR,    // Reset by responder
    F_S0,      // SYN without reply
    F_S1,      // SYN and reply without ACK
    F_S2,      // SYN and SYN-ACK with no final ACK
    F_S3,      // Connection attempt with errors
    F_SF,      // Normal established and closed
    F_SH       // SYN followed by FIN without ACK
} flag_type_t;

// Flow identification key
typedef struct
{
    unsigned int src_ip;
    unsigned int dst_ip;
    unsigned short src_port;
    unsigned short dst_port;
    unsigned char protocol;
} FLOW_KEY;

// Enhanced flow data structure
typedef struct flow_data
{
    FLOW_KEY key; // Flow identification key

    // Service identification
    char service_name[MAX_SERVICE_NAME]; // Service name
    service_type_t service;              // Service classification

    // Timing information
    time_t first_seen;
    time_t last_log_time; // First packet time
    time_t last_seen;     // Last packet time

    // Traffic counters
    unsigned int packets;         // Total packets
    unsigned int src_packets;     // Packets from source
    unsigned int dst_packets;     // Packets from destination
    unsigned long long bytes;     // Total bytes
    unsigned long long src_bytes; // Bytes from source
    unsigned long long dst_bytes; // Bytes from destination

    // TCP specific information
    unsigned char tcp_flags_union; // All TCP flags seen (union)
    char flag_str[16];             // String representation of flags
    flag_type_t flag;              // Connection flag classification

    // Special conditions
    int land;           // Land attack detection (1=detected)
    int wrong_fragment; // IP fragment issues (1=detected)
    int urgent;         // TCP urgent flag seen (1=yes)

    // Statistical counters
    int count;              // Connections from same source IP
    int srv_count;          // Connections to same service
    double serror_rate;     // SYN error rate
    double rerror_rate;     // REJ error rate
    double srv_serror_rate; // SYN error rate for service
    double srv_rerror_rate; // REJ error rate for service
    double same_srv_rate;   // Same service connection rate
    double diff_srv_rate;   // Different service connection rate

    // Destination statistics
    int dst_host_count;            // Count of connections to dst host
    int dst_host_srv_count;        // Count of connections to dst host service
    double dst_host_same_srv_rate; // Same service rate for dst host
    double dst_host_diff_srv_rate; // Different service rate for dst host

    // Payload analysis
    double entropy;      // Payload entropy
    char dns_query[256]; // DNS query if detected

    // Hash table link
    struct flow_data *next; // For hash collision chaining
} FLOW_DATA;

// Host tracking structure
typedef struct host_data
{
    unsigned int ip; // Host IP address
    time_t first_seen;
    time_t last_seen;

    // Connection history (sliding window)
    struct
    {
        time_t timestamp;
        service_type_t service;
        unsigned int dst_ip;
        unsigned short dst_port;
        flag_type_t flag;
    } conn_history[MAX_CONNECTIONS_TRACKED];
    int history_index;

    // Connection statistics (computed from history)
    int total_connections;
    int same_srv_connections;
    int diff_srv_connections;
    int error_connections;     // Connection errors
    int syn_error_connections; // SYN errors
    int rej_error_connections; // Rejected connections

    // Unique destination tracking
    int unique_dst_hosts;    // Number of unique destination hosts
    int unique_dst_services; // Number of unique destination services

    // Hash table link
    struct host_data *next;
} HOST_DATA;

// Port-service mapping structure
typedef struct
{
    unsigned short port;
    unsigned char protocol; // TCP=6, UDP=17
    service_type_t service;
} PORT_SERVICE_MAPPING;

// Configuration structure
typedef struct
{
    char output_file[MAX_PATH];
    int capture_interval;
    int file_rotation_size;
    int log_level;
    char log_file[MAX_PATH];
    int send_enabled;
    char server_url[MAX_PATH];
    int send_interval;
    int ping_interval;
    int log_retention_hours;
    char bind_interface[16];

    // Enhanced configuration options
    int enable_advanced_stats;    // Enable advanced statistics
    int enable_anomaly_detection; // Enable anomaly detection
    int connection_window;        // Time window for connection statistics (seconds)
    int max_host_memory;          // Maximum hosts to keep in memory
    double anomaly_threshold;     // Threshold for anomaly alerts
} Config;

// Log queue node structure
typedef struct LogQueueNode
{
    char *json_data;
    struct LogQueueNode *next;
} LogQueueNode;

// Hash table structure
typedef struct
{
    void **buckets;
    size_t size;
    size_t item_count;
    CRITICAL_SECTION lock;
} HASH_TABLE;

// Global variable declarations
extern Config config;
extern int running;
extern FILE *output_fp;
extern FILE *log_fp;
extern SERVICE_STATUS service_status;
extern SERVICE_STATUS_HANDLE service_status_handle;
extern HANDLE stop_event;
extern HANDLE worker_thread;
extern HANDLE sender_thread;
extern HANDLE ping_thread;
extern HANDLE cleanup_thread;
extern HANDLE stats_thread;
extern CRITICAL_SECTION log_queue_lock;
extern CRITICAL_SECTION flow_table_lock;
extern CRITICAL_SECTION host_table_lock;
extern LogQueueNode *log_queue_head;
extern LogQueueNode *log_queue_tail;
extern int log_queue_size;
extern time_t last_send_time;
extern time_t last_ping_time;
extern SOCKET capture_socket;
extern HASH_TABLE *flow_table;
extern HASH_TABLE *host_table;
extern int flow_count;
extern const char *service_names[];
extern const char *flag_names[];
extern PORT_SERVICE_MAPPING port_service_mappings[];

// Utility functions
void write_to_log(int level, const char *format, ...);
void init_default_config(void);
void parse_config_file(const char *config_file);
void dump_config(void);
char *get_command_output(const char *command);
char *get_current_timestamp(void);
char *ip_to_string(unsigned int ip);
int clock_gettime(int ignored, struct timespec *spec);

// Hash table management
HASH_TABLE *hash_table_create(size_t size);
void hash_table_free(HASH_TABLE *table, void (*free_fn)(void *));
void *hash_table_get(HASH_TABLE *table, void *key, size_t key_size, unsigned int (*hash_fn)(void *, size_t), int (*compare_fn)(void *, void *));
int hash_table_put(HASH_TABLE *table, void *key, size_t key_size, void *value, unsigned int (*hash_fn)(void *, size_t), int (*compare_fn)(void *, void *));
void hash_table_foreach(HASH_TABLE *table, void (*fn)(void *, void *), void *user_data);

// Hash and comparison functions
unsigned int hash_flow_key(FLOW_KEY *key);
int compare_flow_keys(FLOW_KEY *key1, FLOW_KEY *key2);
unsigned int hash_ip_address(unsigned int *ip);
int compare_ip_addresses(unsigned int *ip1, unsigned int *ip2);

// Service identification
void init_service_mapping(void);
service_type_t get_service_by_port(unsigned short port, unsigned char protocol);
const char *get_service_name(service_type_t service);
const char *get_flag_name(flag_type_t flag);

// Network capture functions
int init_capture(void);
int init_winsock(void);
int get_primary_ipv4_address(char *ip_buffer, size_t buffer_size);
int create_raw_socket(void);
unsigned int __stdcall capture_thread(void *arg);

// Packet processing
void process_packet(unsigned char *buffer, int size);
void parse_ip_packet(unsigned char *buffer, int size);
void parse_tcp_packet(unsigned char *buffer, int size, IP_HEADER *ip_header);
void parse_udp_packet(unsigned char *buffer, int size, IP_HEADER *ip_header);
void parse_icmp_packet(unsigned char *buffer, int size, IP_HEADER *ip_header);

// Flow management
FLOW_DATA *find_or_create_flow(FLOW_KEY *key);
void update_flow_stats(FLOW_DATA *flow, int is_src_to_dst, int size, unsigned char tcp_flags);
void update_flow_connection_stats(FLOW_DATA *flow);
void write_flow_log(FLOW_DATA *flow);
flag_type_t classify_tcp_connection(unsigned char flags_union, int packets);

// Host tracking
HOST_DATA *find_or_create_host(unsigned int ip);
void update_host_stats(HOST_DATA *host, FLOW_DATA *flow, int is_source);
void update_host_connection_stats(HOST_DATA *host);
double calculate_rate(int numerator, int denominator);

// Anomaly detection
double calculate_entropy(unsigned char *data, int size);
int has_dns_pattern(unsigned char *data, int size, char *query, int query_size);
int detect_anomalies(FLOW_DATA *flow);

// Data transmission
void add_to_send_queue(const char *json_data);
int send_data_to_server(void);
int ping_server(void);
void cleanup_old_logs(void);
void rotate_output_file(void);
unsigned int __stdcall sender_thread_func(void *arg);
unsigned int __stdcall ping_thread_func(void *arg);
unsigned int __stdcall cleanup_thread_func(void *arg);
unsigned int __stdcall stats_thread_func(void *arg);

// Service management
void cleanup_and_exit(int exit_code);
void WINAPI ServiceMain(DWORD argc, LPTSTR *argv);
void WINAPI ServiceCtrlHandler(DWORD control);
void set_service_status(DWORD current_state, DWORD win32_exit_code, DWORD wait_hint);
int install_service(void);
int remove_service(void);
int start_service(void);
int stop_service(void);
void print_usage(void);

#endif /* NEX_LOG */