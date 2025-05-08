
#include <stdarg.h>
#include "nexlog.h"

/* Global Variables */
Config config;
int running = 0;
FILE *output_fp = NULL;
FILE *log_fp = NULL;
SERVICE_STATUS service_status;
SERVICE_STATUS_HANDLE service_status_handle;
HANDLE stop_event = NULL;
HANDLE worker_thread = NULL;
HANDLE sender_thread = NULL;
HANDLE ping_thread = NULL;
HANDLE cleanup_thread = NULL;
HANDLE stats_thread = NULL;
CRITICAL_SECTION log_queue_lock;
CRITICAL_SECTION flow_table_lock;
CRITICAL_SECTION host_table_lock;
LogQueueNode *log_queue_head = NULL;
LogQueueNode *log_queue_tail = NULL;
int log_queue_size = 0;
time_t last_send_time = 0;
time_t last_ping_time = 0;
SOCKET capture_socket = INVALID_SOCKET;
HASH_TABLE *flow_table = NULL;
HASH_TABLE *host_table = NULL;
int flow_count = 0;

/* Service name to string mapping array */
const char *service_names[SRV_MAX] = {
    "unknown",
    "aol", "auth", "bgp", "courier", "csnet_ns", "ctf",
    "daytime", "discard", "domain", "domain_u", "echo",
    "eco_i", "ecr_i", "efs", "exec", "finger", "ftp",
    "ftp_data", "gopher", "harvest", "hostnames", "http",
    "http_2784", "http_443", "http_8001", "imap4", "IRC",
    "iso_tsap", "klogin", "kshell", "ldap", "link", "login",
    "mtp", "name", "netbios_dgm", "netbios_ns", "netbios_ssn",
    "netstat", "nnsp", "nntp", "ntp_u", "other", "pm_dump",
    "pop_2", "pop_3", "printer", "private", "red_i",
    "remote_job", "rje", "shell", "smtp", "sql_net", "ssh",
    "sunrpc", "supdup", "systat", "telnet", "tftp_u", "tim_i",
    "time", "urh_i", "urp_i", "uucp", "uucp_path", "vmnet",
    "whois", "X11", "Z39_50"};

/* TCP connection flag names */
const char *flag_names[] = {
    "OTH", "REJ", "RSTO", "RSTOS0", "RSTR", "S0",
    "S1", "S2", "S3", "SF", "SH"};

/* Port to service mappings array */
PORT_SERVICE_MAPPING port_service_mappings[] = {
    {7, 6, SRV_ECHO},           // Echo TCP
    {7, 17, SRV_ECHO},          // Echo UDP
    {9, 6, SRV_DISCARD},        // Discard TCP
    {9, 17, SRV_DISCARD},       // Discard UDP
    {13, 6, SRV_DAYTIME},       // Daytime TCP
    {13, 17, SRV_DAYTIME},      // Daytime UDP
    {20, 6, SRV_FTP_DATA},      // FTP Data
    {21, 6, SRV_FTP},           // FTP Control
    {22, 6, SRV_SSH},           // SSH
    {23, 6, SRV_TELNET},        // Telnet
    {25, 6, SRV_SMTP},          // SMTP
    {37, 6, SRV_TIME},          // Time TCP
    {37, 17, SRV_TIME},         // Time UDP
    {43, 6, SRV_WHOIS},         // WHOIS
    {53, 6, SRV_DOMAIN},        // DNS TCP
    {53, 17, SRV_DOMAIN},       // DNS UDP
    {69, 17, SRV_TFTP_U},       // TFTP
    {70, 6, SRV_GOPHER},        // Gopher
    {79, 6, SRV_FINGER},        // Finger
    {80, 6, SRV_HTTP},          // HTTP
    {109, 6, SRV_POP_2},        // POP2
    {110, 6, SRV_POP_3},        // POP3
    {111, 6, SRV_SUNRPC},       // Sun RPC TCP
    {111, 17, SRV_SUNRPC},      // Sun RPC UDP
    {113, 6, SRV_AUTH},         // AUTH
    {119, 6, SRV_NNTP},         // NNTP
    {123, 17, SRV_NTP_U},       // NTP
    {137, 17, SRV_NETBIOS_NS},  // NetBIOS Name Service
    {138, 17, SRV_NETBIOS_DGM}, // NetBIOS Datagram
    {139, 6, SRV_NETBIOS_SSN},  // NetBIOS Session
    {143, 6, SRV_IMAP4},        // IMAP
    {179, 6, SRV_BGP},          // BGP
    {389, 6, SRV_LDAP},         // LDAP
    {443, 6, SRV_HTTP_443},     // HTTPS
    {514, 6, SRV_SHELL},        // Remote Shell
    {515, 6, SRV_PRINTER},      // Printer
    {520, 17, SRV_EFS},         // EFS
    {543, 6, SRV_KLOGIN},       // Kerberos Login
    {544, 6, SRV_KSHELL},       // Kerberos Shell
    {587, 6, SRV_SMTP},         // SMTP Submission
    {631, 6, SRV_PRINTER},      // IPP Printing
    {1433, 6, SRV_SQL_NET},     // MS SQL
    {2784, 6, SRV_HTTP_2784},   // HTTP on port 2784
    {3306, 6, SRV_SQL_NET},     // MySQL
    {5900, 6, SRV_X11},         // VNC
    {6000, 6, SRV_X11},         // X11
    {6667, 6, SRV_IRC},         // IRC
    {8001, 6, SRV_HTTP_8001},   // HTTP on port 8001
    {0, 0, SRV_UNKNOWN}         // End marker
};

/* Write a message to the log file */
void write_to_log(int level, const char *format, ...)
{
    if (level > config.log_level)
        return;

    time_t now;
    struct tm *time_info;
    char timestamp[26];
    char message[1024];
    char full_message[1100];
    va_list args;

    time(&now);
    time_info = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", time_info);

    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);

    const char *level_str;
    switch (level)
    {
    case 1:
        level_str = "ERROR";
        break;
    case 2:
        level_str = "INFO";
        break;
    case 3:
        level_str = "DEBUG";
        break;
    default:
        level_str = "UNKNOWN";
    }

    snprintf(full_message, sizeof(full_message), "[%s] [%s] %s\n", timestamp, level_str, message);

    if (log_fp)
    {
        fputs(full_message, log_fp);
        fflush(log_fp);
    }
    else
    {
        // If log file not open, write to stdout
        fputs(full_message, stdout);
    }
}

/* Get current timestamp as string */
char *get_current_timestamp(void)
{
    static char timestamp[64];
    time_t now;
    struct tm *time_info;

    time(&now);
    time_info = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", time_info);

    return timestamp;
}

/* Convert IP address to string */
char *ip_to_string(unsigned int ip)
{
    struct in_addr addr;
    static char str[INET_ADDRSTRLEN];

    addr.s_addr = ip;
    inet_ntop(AF_INET, &addr, str, sizeof(str));

    return str;
}

/* MinGW-compatible clock_gettime implementation */
int clock_gettime(int ignored, struct timespec *spec)
{
    FILETIME ft;
    ULARGE_INTEGER uli;
    ULONGLONG ull;

    if (!spec)
        return -1;

    GetSystemTimeAsFileTime(&ft);
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    ull = uli.QuadPart;
    ull /= 10;                   /* Convert to microseconds */
    ull -= 11644473600000000ULL; /* Adjust epoch */

    spec->tv_sec = (time_t)(ull / 1000000);
    spec->tv_nsec = (long)((ull % 1000000) * 1000);

    return 0;
}

/* Initialize default configuration */
void init_default_config(void)
{
    char program_data[MAX_PATH];
    GetEnvironmentVariable("ProgramData", program_data, MAX_PATH);

    // Set default configuration values
    strcpy(config.output_file, "nexlog.json");
    sprintf(config.log_file, "%s\\NexLog3\\nexlog.log", program_data);
    config.capture_interval = 60;
    config.file_rotation_size = 10;
    config.log_level = 2;
    config.send_enabled = 1;
    sprintf(config.server_url, "http://%s:%d/api/network_data", SERVER_IP, SERVER_PORT);
    config.send_interval = SEND_INTERVAL;
    config.ping_interval = PING_INTERVAL;
    config.log_retention_hours = LOG_RETENTION_HOURS;
    strcpy(config.bind_interface, "0.0.0.0");

    // Enhanced configuration options
    config.enable_advanced_stats = 1;
    config.enable_anomaly_detection = 1;
    config.connection_window = CONNECTION_WINDOW;
    config.max_host_memory = MAX_HOSTS_TRACKED;
    config.anomaly_threshold = 0.95;

    write_to_log(3, "Default configuration initialized");
}

/* Parse configuration file */
void parse_config_file(const char *config_file)
{
    FILE *fp = fopen(config_file, "r");
    if (!fp)
    {
        write_to_log(1, "Could not open config file: %s", config_file);
        return;
    }

    write_to_log(2, "Parsing configuration file: %s", config_file);

    char line[512];
    while (fgets(line, sizeof(line), fp))
    {
        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r')
            continue;

        // Remove trailing newline
        size_t len = strlen(line);
        if (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
            line[len - 1] = '\0';

        // Find equal sign
        char *equals = strchr(line, '=');
        if (!equals)
            continue;

        // Split key and value
        *equals = '\0';
        char *key = line;
        char *value = equals + 1;

        // Remove trailing whitespace from key
        char *end = key + strlen(key) - 1;
        while (end > key && isspace((unsigned char)*end))
            *end-- = '\0';

        // Remove leading whitespace from value
        while (*value && isspace((unsigned char)*value))
            value++;

        // Apply setting
        if (strcmp(key, "output_file") == 0)
            strncpy(config.output_file, value, sizeof(config.output_file) - 1);
        else if (strcmp(key, "log_file") == 0)
            strncpy(config.log_file, value, sizeof(config.log_file) - 1);
        else if (strcmp(key, "capture_interval") == 0)
            config.capture_interval = atoi(value);
        else if (strcmp(key, "file_rotation_size") == 0)
            config.file_rotation_size = atoi(value);
        else if (strcmp(key, "log_level") == 0)
            config.log_level = atoi(value);
        else if (strcmp(key, "send_enabled") == 0)
            config.send_enabled = atoi(value);
        else if (strcmp(key, "server_url") == 0)
            strncpy(config.server_url, value, sizeof(config.server_url) - 1);
        else if (strcmp(key, "send_interval") == 0)
            config.send_interval = atoi(value);
        else if (strcmp(key, "ping_interval") == 0)
            config.ping_interval = atoi(value);
        else if (strcmp(key, "log_retention_hours") == 0)
            config.log_retention_hours = atoi(value);
        else if (strcmp(key, "bind_interface") == 0)
            strncpy(config.bind_interface, value, sizeof(config.bind_interface) - 1);
        else if (strcmp(key, "enable_advanced_stats") == 0)
            config.enable_advanced_stats = atoi(value);
        else if (strcmp(key, "enable_anomaly_detection") == 0)
            config.enable_anomaly_detection = atoi(value);
        else if (strcmp(key, "connection_window") == 0)
            config.connection_window = atoi(value);
        else if (strcmp(key, "max_host_memory") == 0)
            config.max_host_memory = atoi(value);
        else if (strcmp(key, "anomaly_threshold") == 0)
            config.anomaly_threshold = atof(value);
    }

    fclose(fp);
    write_to_log(2, "Configuration loaded from %s", config_file);
}

/* Dump current configuration to log */
void dump_config(void)
{
    write_to_log(2, "------- Current Configuration -------");
    write_to_log(2, "Output File: %s", config.output_file);
    write_to_log(2, "Log File: %s", config.log_file);
    write_to_log(2, "Capture Interval: %d seconds", config.capture_interval);
    write_to_log(2, "File Rotation Size: %d MB", config.file_rotation_size);
    write_to_log(2, "Log Level: %d", config.log_level);
    write_to_log(2, "Send Enabled: %s", config.send_enabled ? "Yes" : "No");
    write_to_log(2, "Server URL: %s", config.server_url);
    write_to_log(2, "Send Interval: %d seconds", config.send_interval);
    write_to_log(2, "Ping Interval: %d seconds", config.ping_interval);
    write_to_log(2, "Log Retention: %d hours", config.log_retention_hours);
    write_to_log(2, "Bind Interface: %s", config.bind_interface);
    write_to_log(2, "Advanced Stats: %s", config.enable_advanced_stats ? "Enabled" : "Disabled");
    write_to_log(2, "Anomaly Detection: %s", config.enable_anomaly_detection ? "Enabled" : "Disabled");
    write_to_log(2, "Connection Window: %d seconds", config.connection_window);
    write_to_log(2, "Max Host Memory: %d hosts", config.max_host_memory);
    write_to_log(2, "Anomaly Threshold: %.2f", config.anomaly_threshold);
    write_to_log(2, "------------------------------------");
}

/* Create a new hash table */
HASH_TABLE *hash_table_create(size_t size)
{
    HASH_TABLE *table = (HASH_TABLE *)malloc(sizeof(HASH_TABLE));
    if (!table)
        return NULL;

    table->buckets = (void **)calloc(size, sizeof(void *));
    if (!table->buckets)
    {
        free(table);
        return NULL;
    }

    table->size = size;
    table->item_count = 0;
    InitializeCriticalSection(&table->lock);
    return table;
}

/* Free a hash table */
void hash_table_free(HASH_TABLE *table, void (*free_fn)(void *))
{
    if (!table)
        return;

    if (table->buckets)
    {
        for (size_t i = 0; i < table->size; i++)
        {
            // Needs specific logic based on FLOW_DATA/HOST_DATA structure
            // Assuming linked list structure with 'next' pointer
            void *current = table->buckets[i];
            while (current)
            {
                FLOW_DATA *flow_current = (FLOW_DATA *)current; // Cast to known struct type
                void *next = flow_current->next;                // Access the 'next' field
                if (free_fn)
                    free_fn(current);
                else
                    free(current);
                current = next;
            }
        }
        free(table->buckets);
    }

    DeleteCriticalSection(&table->lock);
    free(table);
}

/* Hash function for FLOW_KEY */
unsigned int hash_flow_key(FLOW_KEY *key)
{
    unsigned int hash = 0;
    hash ^= key->src_ip;        // Use XOR for better distribution
    hash ^= (key->dst_ip >> 8); // Shift to mix bits
    hash ^= (key->src_port << 16) | key->dst_port;
    hash ^= (unsigned int)key->protocol << 5; // Include protocol
    return hash;
}

/* Compare two FLOW_KEY structures */
int compare_flow_keys(FLOW_KEY *key1, FLOW_KEY *key2)
{
    return key1->src_ip == key2->src_ip &&
           key1->dst_ip == key2->dst_ip &&
           key1->src_port == key2->src_port &&
           key1->dst_port == key2->dst_port &&
           key1->protocol == key2->protocol;
}

/* Hash function for IP address */
unsigned int hash_ip_address(unsigned int *ip)
{
    // Simple hash, good enough for IPs which are already somewhat random
    return *ip;
}

/* Compare two IP addresses */
int compare_ip_addresses(unsigned int *ip1, unsigned int *ip2)
{
    return *ip1 == *ip2;
}

/* Get an item from the hash table */
// Note: The hash/compare functions passed here should match the *key* type,
// not necessarily the value type being stored.
void *hash_table_get(HASH_TABLE *table, void *key, size_t key_size,
                     unsigned int (*hash_fn)(void *, size_t), // Function for key hashing
                     int (*compare_fn)(void *, void *))       // Function for key comparison
{
    if (!table || !key || !hash_fn || !compare_fn)
        return NULL;

    unsigned int hash = hash_fn(key, key_size);
    unsigned int index = hash % table->size;

    EnterCriticalSection(&table->lock);
    void *current = table->buckets[index];

    while (current)
    {
        // Get the key from the *stored structure* (e.g., FLOW_DATA.key or HOST_DATA.ip)
        void *current_key_ptr = NULL;
        if (compare_fn == (int (*)(void *, void *))compare_flow_keys)
        {
            // Stored item is FLOW_DATA, key is at flow->key
            current_key_ptr = &((FLOW_DATA *)current)->key;
        }
        else if (compare_fn == (int (*)(void *, void *))compare_ip_addresses)
        {
            // Stored item is HOST_DATA, key is at host->ip
            current_key_ptr = &((HOST_DATA *)current)->ip;
        }
        else
        {
            // Should not happen if used correctly
            LeaveCriticalSection(&table->lock);
            return NULL;
        }

        if (compare_fn(current_key_ptr, key))
        {
            LeaveCriticalSection(&table->lock);
            return current; // Return pointer to the *whole structure* (FLOW_DATA or HOST_DATA)
        }

        // Move to next item in chain (assumes next pointer is part of the structure)
        if (compare_fn == (int (*)(void *, void *))compare_flow_keys)
        {
            current = ((FLOW_DATA *)current)->next;
        }
        else if (compare_fn == (int (*)(void *, void *))compare_ip_addresses)
        {
            current = ((HOST_DATA *)current)->next;
        }
        else
        {
            current = NULL; // Should not happen
        }
    }

    LeaveCriticalSection(&table->lock);
    return NULL;
}

/* Put an item into the hash table */
// Note: The hash/compare functions passed here should match the *key* type.
// The 'value' is the pointer to the *entire structure* (FLOW_DATA or HOST_DATA).
int hash_table_put(HASH_TABLE *table, void *key, size_t key_size, void *value,
                   unsigned int (*hash_fn)(void *, size_t), // Function for key hashing
                   int (*compare_fn)(void *, void *))       // Function for key comparison
{
    if (!table || !key || !value || !hash_fn || !compare_fn)
        return 0;

    unsigned int hash = hash_fn(key, key_size);
    unsigned int index = hash % table->size;

    EnterCriticalSection(&table->lock);

    // Check if key already exists
    void *current = table->buckets[index];
    while (current)
    {
        // Get the key from the stored structure
        void *current_key_ptr = NULL;
        if (compare_fn == (int (*)(void *, void *))compare_flow_keys)
        {
            current_key_ptr = &((FLOW_DATA *)current)->key;
        }
        else if (compare_fn == (int (*)(void *, void *))compare_ip_addresses)
        {
            current_key_ptr = &((HOST_DATA *)current)->ip;
        }
        else
        {
            LeaveCriticalSection(&table->lock);
            return 0; // Error: Unknown comparison function
        }

        if (compare_fn(current_key_ptr, key))
        {
            // Key exists - Cannot simply replace, as caller owns memory.
            // This function assumes caller checks existence with get first.
            // If update was needed, it would require freeing old value first.
            LeaveCriticalSection(&table->lock);
            return 0; // Indicate key already exists or error
        }

        // Move to next item in chain
        if (compare_fn == (int (*)(void *, void *))compare_flow_keys)
        {
            current = ((FLOW_DATA *)current)->next;
        }
        else if (compare_fn == (int (*)(void *, void *))compare_ip_addresses)
        {
            current = ((HOST_DATA *)current)->next;
        }
        else
        {
            current = NULL; // Should not happen
        }
    }

    // Key doesn't exist, add new entry (value) at head of list
    // Set the 'next' pointer within the new structure being added.
    if (compare_fn == (int (*)(void *, void *))compare_flow_keys)
    {
        ((FLOW_DATA *)value)->next = (FLOW_DATA *)table->buckets[index];
    }
    else if (compare_fn == (int (*)(void *, void *))compare_ip_addresses)
    {
        ((HOST_DATA *)value)->next = (HOST_DATA *)table->buckets[index];
    }
    else
    {
        LeaveCriticalSection(&table->lock);
        return 0; // Error: Unknown comparison function
    }

    table->buckets[index] = value;
    table->item_count++;

    LeaveCriticalSection(&table->lock);
    return 1; // Indicate success
}

/* Iterate over all items in the hash table */
void hash_table_foreach(HASH_TABLE *table, void (*fn)(void *, void *), void *user_data)
{
    if (!table || !fn)
        return;

    EnterCriticalSection(&table->lock);

    for (size_t i = 0; i < table->size; i++)
    {
        void *current = table->buckets[i];
        while (current)
        {
            // Need to know the structure type to get 'next'
            // We assume it's either FLOW_DATA or HOST_DATA based on context
            // (A more robust implementation might store type info or use void**)
            void *next = NULL;
            // Heuristic: Check if the user_data hints at the type or make an assumption.
            // THIS IS A WEAK POINT - assumes all items in table are same type
            // for getting 'next'. Let's assume FLOW_DATA structure based on usage.
            // A better way is needed if tables mix types or if host_table is iterated.
            if (flow_table == table)
            { // Crude check
                next = ((FLOW_DATA *)current)->next;
            }
            else if (host_table == table)
            {
                next = ((HOST_DATA *)current)->next;
            }
            else
            {
                // Default assumption or error
                next = NULL; // Cannot safely get next if type unknown
                write_to_log(1, "hash_table_foreach: Cannot determine structure type for 'next'");
            }

            fn(current, user_data); // Call the user function

            // Advance using the saved 'next' pointer
            current = next;
        }
    }

    LeaveCriticalSection(&table->lock);
}

/* Initialize service port mapping */
void init_service_mapping(void)
{
    write_to_log(2, "Initializing service port mapping (using static array)");
    // Nothing dynamic to do - we use a static array
}

/* Get service type from port number and protocol */
service_type_t get_service_by_port(unsigned short port, unsigned char protocol)
{
    // Look up in our mapping table
    for (int i = 0; port_service_mappings[i].port != 0; i++)
    {
        if (port_service_mappings[i].port == port &&
            port_service_mappings[i].protocol == protocol)
        {
            return port_service_mappings[i].service;
        }
    }

    // Some special cases
    if ((port >= 1024 && port <= 49151) || // Registered ports
        (port >= 49152 && port <= 65535))  // Dynamic/private ports
    {
        return SRV_PRIVATE;
    }

    return SRV_UNKNOWN;
}

/* Get service name for a service type */
const char *get_service_name(service_type_t service)
{
    if (service >= 0 && service < SRV_MAX)
        return service_names[service];

    return service_names[SRV_UNKNOWN];
}

/* Get flag name for a flag type */
const char *get_flag_name(flag_type_t flag)
{
    if (flag >= 0 && flag <= F_SH)
        return flag_names[flag];

    return flag_names[F_OTH];
}

/* Classify TCP connection based on flags and number of packets */
flag_type_t classify_tcp_connection(unsigned char flags_union, int packets)
{
    // Check flag patterns
    if (flags_union & TCP_RST)
    {
        if (flags_union & TCP_SYN)
        {
            // SYN was sent but got a reset
            if (!(flags_union & TCP_ACK))
                return F_RSTOS0; // Reset after SYN without ACK
            return F_RSTO;       // Reset by originator
        }
        return F_RSTR; // Reset by responder
    }

    if (flags_union & TCP_SYN)
    {
        if (!(flags_union & TCP_ACK))
        {
            if (packets <= 1)
                return F_S0; // SYN only, no reply

            if (flags_union & TCP_FIN)
                return F_SH; // SYN followed by FIN without ACK
        }

        // We need both SYN and ACK to consider S1/S2/S3/SF
        if (flags_union & TCP_ACK)
        {
            if (packets <= 2 && !(flags_union & TCP_FIN)) // SYN-ACK seen, but no final ACK or FIN yet
                return F_S1;                              // Treat as SYN and reply without final ACK for now

            // S2/S3/SF require more context than just flags_union and packets seen *so far*
            // A simple heuristic:
            if (flags_union & TCP_FIN)
                return F_SF; // If SYN, ACK, and FIN seen, assume normal close

            // If SYN and ACK seen, but no FIN/RST yet, it's likely ongoing or stalled
            // Hard to distinguish S2/S3 accurately without state tracking.
            // Let's lean towards S3 if packets > 2 and no FIN/RST yet.
            if (packets > 2 && !(flags_union & TCP_FIN))
                return F_S3; // Assume connection attempt with potential errors or still establishing
        }
        else
        {
            // SYN without ACK - already handled by F_S0 / F_SH above
        }
    }

    if (flags_union & TCP_FIN && !(flags_union & TCP_SYN)) // FIN without SYN (might be part of close or rejected)
        return F_REJ;                                      // Simplified: Treat FIN without SYN as rejected or other close

    return F_OTH; // Other patterns
}

/* Initialize Winsock */
int init_winsock(void)
{
    WSADATA wsa_data;
    int result = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    if (result != 0)
    {
        write_to_log(1, "WSAStartup failed: %d", result);
        return 0;
    }

    write_to_log(3, "Winsock initialized successfully");
    return 1;
}

/* Helper function to get a suitable primary IPv4 address */
int get_primary_ipv4_address(char *ip_buffer, size_t buffer_size)
{
    PIP_ADAPTER_ADDRESSES pAddresses = NULL;
    ULONG outBufLen = 15000; // Initial buffer size
    ULONG Iterations = 0;
    DWORD dwRetVal = 0;
    char *found_ip = NULL;

    // Allocate memory for adapter addresses
    do
    {
        pAddresses = (IP_ADAPTER_ADDRESSES *)malloc(outBufLen);
        if (pAddresses == NULL)
        {
            write_to_log(1, "Memory allocation failed for GetAdaptersAddresses");
            return 0;
        }

        dwRetVal = GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER, NULL, pAddresses, &outBufLen);

        if (dwRetVal == ERROR_BUFFER_OVERFLOW)
        {
            free(pAddresses);
            pAddresses = NULL;
        }
        else
        {
            break;
        }

        Iterations++;
    } while ((dwRetVal == ERROR_BUFFER_OVERFLOW) && (Iterations < 3));

    if (dwRetVal == NO_ERROR)
    {
        // Iterate through adapters
        PIP_ADAPTER_ADDRESSES pCurrAddresses = pAddresses;
        while (pCurrAddresses)
        {
            // Check if adapter is operational and not loopback
            if (pCurrAddresses->OperStatus == IfOperStatusUp && pCurrAddresses->IfType != IF_TYPE_SOFTWARE_LOOPBACK)
            {
                // Iterate through unicast addresses for this adapter
                PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pCurrAddresses->FirstUnicastAddress;
                while (pUnicast)
                {
                    struct sockaddr *sa = pUnicast->Address.lpSockaddr;
                    if (sa->sa_family == AF_INET)
                    { // Found an IPv4 address
                        struct sockaddr_in *sa_in = (struct sockaddr_in *)sa;
                        inet_ntop(AF_INET, &(sa_in->sin_addr), ip_buffer, buffer_size);
                        write_to_log(3, "Found suitable IPv4 interface: %s (%ws)", ip_buffer, pCurrAddresses->FriendlyName);
                        found_ip = ip_buffer;
                        goto cleanup; // Use the first operational, non-loopback IPv4 found
                    }
                    pUnicast = pUnicast->Next;
                }
            }
            pCurrAddresses = pCurrAddresses->Next;
        }
        // If loop completes without finding one
        write_to_log(1, "No suitable UP, non-loopback IPv4 interface found.");
    }
    else
    {
        write_to_log(1, "GetAdaptersAddresses failed with error: %d", dwRetVal);
    }

cleanup:
    if (pAddresses)
    {
        free(pAddresses);
    }
    return (found_ip != NULL); // Return 1 if found, 0 otherwise
}

/* Create raw socket for packet capture */
int create_raw_socket(void)
{
    // Create a RAW socket
    capture_socket = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if (capture_socket == INVALID_SOCKET)
    {
        write_to_log(1, "Failed to create raw socket: %d", WSAGetLastError());
        return 0;
    }
    write_to_log(3, "Raw socket created (pre-config).");

    // --- Binding Logic ---
    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(0); // Port doesn't matter for raw IP

    char bind_ip_str[INET_ADDRSTRLEN];
    int use_specific_ip = 0;

    // Check if a specific, valid interface IP is configured
    if (config.bind_interface[0] != '\0' && strcmp(config.bind_interface, "0.0.0.0") != 0)
    {
        // Use the IP specified in the config file
        strncpy(bind_ip_str, config.bind_interface, sizeof(bind_ip_str) - 1);
        bind_ip_str[sizeof(bind_ip_str) - 1] = '\0'; // Ensure null termination
        // Basic validation (doesn't guarantee it's a *local* IP)
        struct in_addr temp_addr;
        if (inet_pton(AF_INET, bind_ip_str, &temp_addr) == 1)
        {
            use_specific_ip = 1;
            write_to_log(2, "Using configured bind interface: %s", bind_ip_str);
        }
        else
        {
            write_to_log(1, "Invalid IP format in config bind_interface: '%s'. Attempting auto-detection.", config.bind_interface);
            use_specific_ip = 0; // Fallback to auto-detection
        }
    }

    // If no valid specific IP configured, try auto-detection
    if (!use_specific_ip)
    {
        write_to_log(2, "Bind interface not specified or invalid, attempting auto-detection...");
        if (get_primary_ipv4_address(bind_ip_str, sizeof(bind_ip_str)))
        {
            use_specific_ip = 1;
            write_to_log(2, "Auto-detected interface IP for binding: %s", bind_ip_str);
        }
        else
        {
            write_to_log(1, "Could not auto-detect a suitable local IPv4 address to bind. SIO_RCVALL requires a specific IP.");
            closesocket(capture_socket);
            capture_socket = INVALID_SOCKET;
            return 0; // Cannot proceed without a specific IP for SIO_RCVALL
        }
    }

    // Convert string IP to address structure for binding
    if (inet_pton(AF_INET, bind_ip_str, &bind_addr.sin_addr) != 1)
    {
        // This case should ideally be caught earlier, but double-check
        write_to_log(1, "Internal error: Invalid bind IP address format during conversion: %s", bind_ip_str);
        closesocket(capture_socket);
        capture_socket = INVALID_SOCKET;
        return 0;
    }

    // Bind the socket to the specific interface IP
    if (bind(capture_socket, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) == SOCKET_ERROR)
    {
        write_to_log(1, "Failed to bind socket to %s: %d", bind_ip_str, WSAGetLastError());
        closesocket(capture_socket);
        capture_socket = INVALID_SOCKET;
        return 0;
    }
    write_to_log(2, "Successfully bound socket to interface: %s", bind_ip_str);
    // --- End Binding Logic ---

    int optval_hdrincl = 1;
    if (setsockopt(capture_socket, IPPROTO_IP, IP_HDRINCL, (char *)&optval_hdrincl, sizeof(optval_hdrincl)) == SOCKET_ERROR)
    {
        write_to_log(1, "Warning: Failed to set IP_HDRINCL: %d. Capture might still work.", WSAGetLastError());
        // Continue anyway, often not critical just for capture
    }

    u_long optval_promisc = 1; // Use u_long for ioctlsocket control codes
    DWORD bytesReturned = 0;   // Required for WSAIoctl
    if (WSAIoctl(capture_socket, SIO_RCVALL, &optval_promisc, sizeof(optval_promisc),
                 NULL, 0, &bytesReturned, NULL, NULL) == SOCKET_ERROR)
    {
        DWORD error_code = WSAGetLastError();
        write_to_log(1, "Failed to enable promiscuous mode (SIO_RCVALL) on %s: %d", bind_ip_str, error_code);

        // Check for specific, common errors and provide hints
        if (error_code == WSAEACCES)
        { // WSAEACCES (10013)
            write_to_log(1, "Hint: Error WSAEACCES (%d) typically means the program lacks Administrator privileges.", error_code);
        }
        else if (error_code == WSAEINVAL)
        { // WSAEINVAL (10022)
            write_to_log(1, "Hint: Error WSAEINVAL (%d) often means the socket wasn't bound to a specific local IP, the IP was invalid, or SIO_RCVALL is not supported/enabled on this interface/system.", error_code);
        }
        else
        {
            // Log other potential Winsock errors
            write_to_log(1, "Hint: Unexpected Winsock error %d occurred.", error_code);
        }

        closesocket(capture_socket);
        capture_socket = INVALID_SOCKET;
        return 0; // Cannot proceed without promiscuous mode
    }
    write_to_log(2, "Promiscuous mode (SIO_RCVALL) enabled successfully on %s", bind_ip_str);

    // Optional: Increase receive buffer size to reduce packet drops under load
    int rcvbuf_size = 8 * 1024 * 1024; // 8MB
    if (setsockopt(capture_socket, SOL_SOCKET, SO_RCVBUF, (char *)&rcvbuf_size, sizeof(rcvbuf_size)) == SOCKET_ERROR)
    {
        write_to_log(1, "Warning: Failed to set receive buffer size to %d bytes: %d", rcvbuf_size, WSAGetLastError());
    }
    else
    {
        write_to_log(3, "Socket receive buffer size set to %d bytes.", rcvbuf_size);
    }

    // Set socket to non-blocking mode using FIONBIO
    u_long mode = 1; // 1 for non-blocking, 0 for blocking
    if (ioctlsocket(capture_socket, FIONBIO, &mode) == SOCKET_ERROR)
    {
        write_to_log(1, "Failed to set non-blocking mode (FIONBIO): %d", WSAGetLastError());
        // Clean up by disabling promiscuous mode before closing
        optval_promisc = RCVALL_OFF; // Turn off SIO_RCVALL (best effort)
        WSAIoctl(capture_socket, SIO_RCVALL, &optval_promisc, sizeof(optval_promisc),
                 NULL, 0, &bytesReturned, NULL, NULL);
        closesocket(capture_socket);
        capture_socket = INVALID_SOCKET;
        return 0; // Non-blocking is essential for the loop structure
    }
    write_to_log(3, "Socket set to non-blocking mode.");

    write_to_log(2, "Raw socket created and configured successfully for interface %s", bind_ip_str);
    return 1; // Success
}

/* Initialize packet capture */
int init_capture(void)
{
    // Initialize hash tables
    flow_table = hash_table_create(HASH_TABLE_SIZE);
    if (!flow_table)
    {
        write_to_log(1, "Failed to create flow hash table");
        return 0;
    }

    host_table = hash_table_create(HASH_TABLE_SIZE);
    if (!host_table)
    {
        write_to_log(1, "Failed to create host hash table");
        hash_table_free(flow_table, free);
        flow_table = NULL;
        return 0;
    }

    // Initialize critical sections
    InitializeCriticalSection(&flow_table_lock);
    InitializeCriticalSection(&host_table_lock);

    // Initialize service mappings
    init_service_mapping();

    // Initialize Winsock
    if (!init_winsock())
    {
        DeleteCriticalSection(&flow_table_lock);
        DeleteCriticalSection(&host_table_lock);
        hash_table_free(flow_table, free);
        hash_table_free(host_table, free);
        flow_table = NULL;
        host_table = NULL;
        return 0;
    }

    // Create raw socket
    if (!create_raw_socket())
    {
        DeleteCriticalSection(&flow_table_lock);
        DeleteCriticalSection(&host_table_lock);
        hash_table_free(flow_table, free);
        hash_table_free(host_table, free);
        flow_table = NULL;
        host_table = NULL;
        WSACleanup();
        return 0;
    }

    // Open output file
    output_fp = fopen(config.output_file, "a"); // Append mode is safer for restarts
    if (!output_fp)
    {
        char output_dir[MAX_PATH];
        strncpy(output_dir, config.output_file, sizeof(output_dir) - 1);
        char *last_slash = strrchr(output_dir, '\\');
        if (last_slash)
        {
            *last_slash = '\0';
            CreateDirectory(output_dir, NULL);
            output_fp = fopen(config.output_file, "a"); // Try again after creating dir
        }
        if (!output_fp)
        {
            write_to_log(1, "Error opening output file: %s", config.output_file);
            DeleteCriticalSection(&flow_table_lock);
            DeleteCriticalSection(&host_table_lock);
            hash_table_free(flow_table, free);
            hash_table_free(host_table, free);
            flow_table = NULL;
            host_table = NULL;
            closesocket(capture_socket);
            WSACleanup();
            return 0;
        }
    }

    write_to_log(2, "Capture subsystem initialized successfully");
    return 1;
}

/* Find or create a flow record */
FLOW_DATA *find_or_create_flow(FLOW_KEY *key)
{
    if (!key)
        return NULL;

    // First, try to find existing flow
    FLOW_DATA *flow = NULL;

    EnterCriticalSection(&flow_table_lock);

    // Lookup in hash table
    flow = (FLOW_DATA *)hash_table_get(
        flow_table,
        key,
        sizeof(FLOW_KEY),
        (unsigned int (*)(void *, size_t))hash_flow_key,
        (int (*)(void *, void *))compare_flow_keys);

    if (flow)
    {
        LeaveCriticalSection(&flow_table_lock);
        return flow;
    }

    // --- Create new flow if not found ---

    // Check if we've hit the flow limit (optional, prevents memory exhaustion)
    if (flow_count >= MAX_FLOWS)
    {
        // Implement a cleanup strategy here (e.g., remove oldest flow)
        // For now, just log and deny creation
        write_to_log(1, "Maximum flow limit (%d) reached. Cannot create new flow.", MAX_FLOWS);
        LeaveCriticalSection(&flow_table_lock);
        return NULL;
    }

    flow = (FLOW_DATA *)calloc(1, sizeof(FLOW_DATA));
    if (!flow)
    {
        LeaveCriticalSection(&flow_table_lock);
        write_to_log(1, "Memory allocation failed for flow data");
        return NULL;
    }

    // Initialize new flow
    flow->key = *key;
    flow->first_seen = time(NULL);
    flow->last_seen = flow->first_seen;
    flow->next = NULL; // Explicitly set next pointer for new node

    // Identify service
    // Prefer destination port for service ID, but check source for common client->server patterns
    flow->service = get_service_by_port(key->dst_port, key->protocol);
    if (flow->service == SRV_UNKNOWN || flow->service == SRV_PRIVATE)
    {
        service_type_t src_service = get_service_by_port(key->src_port, key->protocol);
        // If dest is unknown/private but source is a known server port, use source
        if (src_service != SRV_UNKNOWN && src_service != SRV_PRIVATE)
        {
            // This case is less common but might happen (e.g., server initiating connection)
            // Let's stick with destination port as primary identifier for now
            // flow->service = src_service;
        }
    }
    strncpy(flow->service_name, get_service_name(flow->service), MAX_SERVICE_NAME - 1);
    flow->service_name[MAX_SERVICE_NAME - 1] = '\0'; // Ensure null termination

    // Check for LAND attack (same source and destination)
    flow->land = (key->src_ip == key->dst_ip && key->src_port == key->dst_port) ? 1 : 0;

    // Insert into hash table
    if (!hash_table_put(
            flow_table,
            &flow->key, // Pass pointer to the key within the structure
            sizeof(FLOW_KEY),
            flow, // Pass pointer to the whole structure
            (unsigned int (*)(void *, size_t))hash_flow_key,
            (int (*)(void *, void *))compare_flow_keys))
    {
        // Put failed (e.g., duplicate key race condition, though lock should prevent)
        write_to_log(1, "Failed to insert new flow into hash table.");
        free(flow);
        flow = NULL;
    }
    else
    {
        flow_count++;
        write_to_log(3, "Created new flow. Total flows: %d", flow_count);
    }

    LeaveCriticalSection(&flow_table_lock);
    return flow;
}

/* Find or create a host record */
HOST_DATA *find_or_create_host(unsigned int ip)
{
    if (!ip)
        return NULL;

    // First, try to find existing host
    HOST_DATA *host = NULL;

    EnterCriticalSection(&host_table_lock);

    // Lookup in hash table
    host = (HOST_DATA *)hash_table_get(
        host_table,
        &ip, // Pass pointer to the IP key
        sizeof(unsigned int),
        (unsigned int (*)(void *, size_t))hash_ip_address,
        (int (*)(void *, void *))compare_ip_addresses);

    if (host)
    {
        LeaveCriticalSection(&host_table_lock);
        return host;
    }

    // --- Create new host if not found ---

    // Check if we've hit the host limit (optional)
    // Consider using table->item_count vs a separate counter if host_table only stores HOST_DATA
    if (host_table->item_count >= config.max_host_memory)
    {
        // Implement cleanup (e.g., remove oldest host based on last_seen)
        write_to_log(1, "Maximum host memory limit (%d) reached. Cannot create new host.", config.max_host_memory);
        LeaveCriticalSection(&host_table_lock);
        return NULL;
    }

    host = (HOST_DATA *)calloc(1, sizeof(HOST_DATA));
    if (!host)
    {
        LeaveCriticalSection(&host_table_lock);
        write_to_log(1, "Memory allocation failed for host data");
        return NULL;
    }

    // Initialize new host
    host->ip = ip;
    host->first_seen = time(NULL);
    host->last_seen = host->first_seen;
    host->history_index = 0;
    host->next = NULL; // Explicitly set next pointer

    // Insert into hash table
    if (!hash_table_put(
            host_table,
            &host->ip, // Pass pointer to the key (IP address)
            sizeof(unsigned int),
            host, // Pass pointer to the whole structure
            (unsigned int (*)(void *, size_t))hash_ip_address,
            (int (*)(void *, void *))compare_ip_addresses))
    {
        write_to_log(1, "Failed to insert new host into hash table.");
        free(host);
        host = NULL;
    }
    else
    {
        write_to_log(3, "Created new host tracking for %s. Total hosts: %zu", ip_to_string(ip), host_table->item_count);
    }

    LeaveCriticalSection(&host_table_lock);
    return host;
}

/* Process captured packet */
void process_packet(unsigned char *buffer, int size)
{
    if (size < sizeof(IP_HEADER))
    {
        // Don't log excessively for very small packets, could be noise/fragments
        // write_to_log(3, "Received packet too small for IP header: %d bytes", size);
        return;
    }

    // Process IP header
    parse_ip_packet(buffer, size);
}

/* Parse IP packet */
void parse_ip_packet(unsigned char *buffer, int size)
{
    IP_HEADER *ip_header = (IP_HEADER *)buffer;

    // Basic sanity checks
    if (ip_header->ip_v != 4)
    { // Only handle IPv4
        return;
    }

    // Calculate header length
    int ip_header_len = ip_header->ip_hl * 4;
    if (ip_header_len < 20 || ip_header_len > size) // Min IP header size is 20
    {
        write_to_log(3, "Invalid IP header length: %d bytes (Packet size: %d)", ip_header_len, size);
        return;
    }

    // Validate packet length from header vs actual received size
    unsigned short ip_len = ntohs(ip_header->ip_len);
    if (ip_len < ip_header_len || ip_len > size) // Total length must be >= header length and <= received size
    {
        write_to_log(3, "IP packet size mismatch: header total len=%d, header len=%d, actual recv=%d", ip_len, ip_header_len, size);
        // We can still try processing based on 'size', but ip_len is suspicious
        // Let's use the smaller of ip_len and size for payload calculation
        size = (ip_len < size) ? ip_len : size;
        if (size < ip_header_len)
            return; // Cannot proceed if reported size is less than header
    }
    else
    {
        // Use the length reported by the IP header if it's valid and smaller than received size
        size = ip_len;
    }

    // Process based on protocol
    switch (ip_header->ip_p)
    {
    case PROTO_TCP:
        parse_tcp_packet(buffer + ip_header_len, size - ip_header_len, ip_header);
        break;
    case PROTO_UDP:
        parse_udp_packet(buffer + ip_header_len, size - ip_header_len, ip_header);
        break;
    case PROTO_ICMP:
        parse_icmp_packet(buffer + ip_header_len, size - ip_header_len, ip_header);
        break;
    default:
        // Log other protocols if needed for debugging
        // write_to_log(3, "Ignoring non-TCP/UDP/ICMP packet (Proto: %d)", ip_header->ip_p);
        break;
    }
}

/* Update flow statistics */
void update_flow_stats(FLOW_DATA *flow, int is_src_to_dst, int ip_payload_size, unsigned char tcp_flags)
{
    if (!flow)
        return;

    // Need synchronization if multiple threads could update the *same* flow concurrently
    // Assuming capture_thread is single-threaded processing packets sequentially for now.
    // If stats_thread modifies flows, locks would be needed here.

    flow->last_seen = time(NULL);
    flow->packets++;
    flow->bytes += ip_payload_size; // Add the size of the transport layer payload + header

    // Track directionality (assuming is_src_to_dst is reliable)
    // Currently, the parser calls always assume is_src_to_dst=1.
    // A more robust flow tracker would determine direction based on IP/port matching.
    // Let's assume the current packet directionality matches the flow's key direction.
    flow->src_packets++; // Simplified: assume all packets are src->dst for now
    flow->src_bytes += ip_payload_size;

    // For TCP flows, update flags
    if (flow->key.protocol == PROTO_TCP && tcp_flags)
    {
        unsigned char old_flags = flow->tcp_flags_union;
        flow->tcp_flags_union |= tcp_flags;

        // Only update flag string and classification if flags actually changed
        if (flow->tcp_flags_union != old_flags || flow->flag == 0) // Update if changed or first time
        {
            // Update flag string representation
            sprintf(flow->flag_str, "%c%c%c%c%c%c",
                    (flow->tcp_flags_union & TCP_URG) ? 'U' : '-',  // URG
                    (flow->tcp_flags_union & TCP_ACK) ? 'A' : '-',  // ACK
                    (flow->tcp_flags_union & TCP_PSH) ? 'P' : '-',  // PSH
                    (flow->tcp_flags_union & TCP_RST) ? 'R' : '-',  // RST
                    (flow->tcp_flags_union & TCP_SYN) ? 'S' : '-',  // SYN
                    (flow->tcp_flags_union & TCP_FIN) ? 'F' : '-'); // FIN
            flow->flag_str[sizeof(flow->flag_str) - 1] = '\0';      // Ensure null termination

            // Update connection flag classification based on cumulative flags
            flow->flag = classify_tcp_connection(flow->tcp_flags_union, flow->packets);
        }
    }
    else if (flow->key.protocol != PROTO_TCP)
    {
        // Non-TCP flows don't have these flags
        strcpy(flow->flag_str, "------");
        flow->flag = F_OTH; // Or a more specific non-TCP flag if defined
    }
}

/* Calculate rate (handles division by zero) */
double calculate_rate(int numerator, int denominator)
{
    if (denominator <= 0) // Check for zero or negative denominator
        return 0.0;

    double rate = (double)numerator / denominator;
    // Clamp rate between 0.0 and 1.0
    if (rate < 0.0)
        return 0.0;
    if (rate > 1.0)
        return 1.0;
    return rate;
}

/* Update host statistics with flow information */
void update_host_stats(HOST_DATA *host, FLOW_DATA *flow, int is_source)
{
    if (!host || !flow)
        return;

    // Lock needed if multiple threads update the same host record
    // Assuming single-threaded access from capture thread for now.
    EnterCriticalSection(&host_table_lock); // Lock needed as stats use history

    host->last_seen = time(NULL);

    // Update connection history (only if advanced stats enabled)
    if (config.enable_advanced_stats)
    {
        int idx = host->history_index;
        host->conn_history[idx].timestamp = flow->last_seen; // Use flow's last seen time
        host->conn_history[idx].service = flow->service;

        // Record the *other* end of the connection relative to this host
        if (is_source) // If 'host' is the source of 'flow'
        {
            host->conn_history[idx].dst_ip = flow->key.dst_ip;
            host->conn_history[idx].dst_port = flow->key.dst_port;
        }
        else // If 'host' is the destination of 'flow'
        {
            // We record the source of the flow as the 'destination' from this host's perspective
            // This might be confusing. Let's record the remote IP consistently.
            host->conn_history[idx].dst_ip = flow->key.src_ip;     // The other host involved
            host->conn_history[idx].dst_port = flow->key.src_port; // The other host's port
        }

        // Store the final classified flag for the flow
        host->conn_history[idx].flag = flow->flag;

        // Move to next index (circular buffer)
        host->history_index = (host->history_index + 1) % MAX_CONNECTIONS_TRACKED;
    }

    // Basic counter update (can be done even if advanced stats off)
    host->total_connections++; // Increment for every flow associated (direction doesn't matter here)

    // Note: Detailed stats like same_srv, diff_srv, error rates are calculated
    // *on demand* in update_flow_connection_stats, not stored cumulatively here.
    // This keeps host_data smaller but requires iterating history.

    LeaveCriticalSection(&host_table_lock);
}

/* Calculate connection statistics for flow */
void update_flow_connection_stats(FLOW_DATA *flow)
{
    if (!flow || !config.enable_advanced_stats) // Only calculate if enabled
        return;

    // --- Source Host Based Stats ---
    EnterCriticalSection(&host_table_lock); // Need lock to access host history safely

    // Find source host
    HOST_DATA *src_host = (HOST_DATA *)hash_table_get(
        host_table,
        &flow->key.src_ip,
        sizeof(unsigned int),
        (unsigned int (*)(void *, size_t))hash_ip_address,
        (int (*)(void *, void *))compare_ip_addresses);

    if (src_host)
    {
        // Get connection statistics from source host tracking within the time window
        time_t current_time = flow->last_seen; // Use flow's last update time as 'now'
        time_t window_start = current_time - config.connection_window;
        int total_count = 0;         // Connections from src_host in window
        int same_srv_count = 0;      // Connections from src_host to same service in window
        int diff_srv_count = 0;      // Connections from src_host to different services in window
        int syn_error_count = 0;     // SYN errors from src_host in window
        int rej_error_count = 0;     // REJ errors from src_host in window
        int srv_syn_error_count = 0; // SYN errors from src_host to same service in window
        int srv_rej_error_count = 0; // REJ errors from src_host to same service in window

        // Iterate through the source host's connection history
        for (int i = 0; i < MAX_CONNECTIONS_TRACKED; i++)
        {
            // Get index, wrap around if needed
            int history_idx = (src_host->history_index - 1 - i + MAX_CONNECTIONS_TRACKED) % MAX_CONNECTIONS_TRACKED;
            struct
            {
                time_t timestamp;
                service_type_t service;
                unsigned int dst_ip;
                unsigned short dst_port;
                flag_type_t flag;
            } entry;
            memcpy(&entry, &(src_host->conn_history[history_idx]), sizeof(entry));

            if (entry.timestamp >= window_start && entry.timestamp <= current_time) // Check if within time window
            {
                total_count++;
                flag_type_t flag = entry.flag;

                // Service comparison
                if (entry.service == flow->service)
                {
                    same_srv_count++;
                    // Count service-specific errors
                    if (flag == F_S0 || flag == F_S1 || flag == F_S2 || flag == F_S3)
                        srv_syn_error_count++;
                    if (flag == F_REJ) // Assuming F_REJ is the primary rejection flag
                        srv_rej_error_count++;
                }
                else
                {
                    diff_srv_count++;
                }

                // Count overall errors for the source host
                if (flag == F_S0 || flag == F_S1 || flag == F_S2 || flag == F_S3)
                    syn_error_count++;
                if (flag == F_REJ)
                    rej_error_count++;
            }
            else if (entry.timestamp == 0)
            {
                // Stop if we hit uninitialized part of history
                break;
            }
            else if (entry.timestamp < window_start)
            {
                // Stop searching once we go past the time window start
                break;
            }
        }

        // Set connection statistics for the flow based on source host history
        flow->count = total_count;        // KDD:'count' - connections to same host in past 2s
        flow->srv_count = same_srv_count; // KDD:'srv_count' - connections to same service in past 2s

        flow->same_srv_rate = calculate_rate(same_srv_count, total_count);
        flow->diff_srv_rate = calculate_rate(diff_srv_count, total_count);
        flow->serror_rate = calculate_rate(syn_error_count, total_count);
        flow->rerror_rate = calculate_rate(rej_error_count, total_count); // Rate of REJ errors

        flow->srv_serror_rate = calculate_rate(srv_syn_error_count, same_srv_count);
        flow->srv_rerror_rate = calculate_rate(srv_rej_error_count, same_srv_count);
    }
    else
    {
        // Source host not found or no history - zero out rates
        flow->count = 0;
        flow->srv_count = 0;
        flow->same_srv_rate = 0.0;
        flow->diff_srv_rate = 0.0;
        flow->serror_rate = 0.0;
        flow->rerror_rate = 0.0;
        flow->srv_serror_rate = 0.0;
        flow->srv_rerror_rate = 0.0;
    }

    // --- Destination Host Based Stats ---
    // Find destination host
    HOST_DATA *dst_host = (HOST_DATA *)hash_table_get(
        host_table,
        &flow->key.dst_ip,
        sizeof(unsigned int),
        (unsigned int (*)(void *, size_t))hash_ip_address,
        (int (*)(void *, void *))compare_ip_addresses);

    if (dst_host)
    {
        // Calculate stats for connections *to* the destination host within the time window
        time_t current_time = flow->last_seen;
        time_t window_start = current_time - config.connection_window; // Use same window
        int dst_total_count = 0;                                       // Connections *to* dst_host in window
        int dst_same_srv_count = 0;                                    // Connections *to* dst_host for same service in window
        int dst_diff_srv_count = 0;                                    // Connections *to* dst_host for different services in window
        // Note: Error rates based on destination host history are less standard in KDD feature set,
        // but could be calculated similarly if needed. KDD focuses on destination host service distribution.

        // Iterate through the destination host's connection history
        for (int i = 0; i < MAX_CONNECTIONS_TRACKED; i++)
        {
            int history_idx = (dst_host->history_index - 1 - i + MAX_CONNECTIONS_TRACKED) % MAX_CONNECTIONS_TRACKED;
            struct
            {
                time_t timestamp;
                service_type_t service;
                unsigned int dst_ip;
                unsigned short dst_port;
                flag_type_t flag;
            } entry;
            memcpy(&entry, &(dst_host->conn_history[history_idx]), sizeof(entry));

            if (entry.timestamp >= window_start && entry.timestamp <= current_time)
            {

                // Re-use src_host if available, otherwise skip these stats.
                if (src_host)
                {
                    // Reset counters for this calculation method
                    dst_total_count = 0;
                    dst_same_srv_count = 0;
                    dst_diff_srv_count = 0;
                    int dst_conn_limit = 100; // KDD often uses 100 connections history for dst_host features

                    for (int j = 0; j < MAX_CONNECTIONS_TRACKED && j < dst_conn_limit; ++j)
                    {
                        int src_hist_idx = (src_host->history_index - 1 - j + MAX_CONNECTIONS_TRACKED) % MAX_CONNECTIONS_TRACKED;
                        struct
                        {
                            time_t timestamp;
                            service_type_t service;
                            unsigned int dst_ip;
                            unsigned short dst_port;
                            flag_type_t flag;
                        } src_entry;
                        memcpy(&src_entry, &(src_host->conn_history[src_hist_idx]), sizeof(src_entry));

                        if (src_entry.timestamp == 0)
                            break; // Stop if history empty

                        // Check if this historical connection from src_host went to the *same destination* as our current flow
                        if (src_entry.dst_ip == flow->key.dst_ip)
                        {
                            dst_total_count++;
                            if (src_entry.service == flow->service)
                            {
                                dst_same_srv_count++;
                            }
                            else
                            {
                                dst_diff_srv_count++;
                            }
                        }
                    }
                    // Now set the dst_host stats based on this src_host history scan
                    flow->dst_host_count = dst_total_count;
                    flow->dst_host_srv_count = dst_same_srv_count;
                    flow->dst_host_same_srv_rate = calculate_rate(dst_same_srv_count, dst_total_count);
                    flow->dst_host_diff_srv_rate = calculate_rate(dst_diff_srv_count, dst_total_count);

                    // Break the outer loop since we recalculated using src_host history
                    break; // Exit the dst_host history loop (i loop)
                }
                else
                {
                    // Cannot calculate dst_host stats without src_host history access
                    flow->dst_host_count = 0;
                    flow->dst_host_srv_count = 0;
                    flow->dst_host_same_srv_rate = 0.0;
                    flow->dst_host_diff_srv_rate = 0.0;
                    break; // Exit the dst_host history loop (i loop)
                }
            }
            else if (entry.timestamp == 0)
            {
                break; // Stop if we hit uninitialized part of history
            }
            else if (entry.timestamp < window_start)
            {
                // Stop if we go past the time window (if using dst_host history directly)
                // break;
            }
        }
        // If the loop finished without recalculating via src_host (e.g., src_host was NULL)
        // ensure stats are zeroed.
        if (!src_host)
        {
            flow->dst_host_count = 0;
            flow->dst_host_srv_count = 0;
            flow->dst_host_same_srv_rate = 0.0;
            flow->dst_host_diff_srv_rate = 0.0;
        }
    }
    else
    {
        // Destination host not found - zero out rates
        flow->dst_host_count = 0;
        flow->dst_host_srv_count = 0;
        flow->dst_host_same_srv_rate = 0.0;
        flow->dst_host_diff_srv_rate = 0.0;
    }

    LeaveCriticalSection(&host_table_lock); // Release lock
}

/* Calculate Shannon entropy of data */
double calculate_entropy(unsigned char *data, int size)
{
    if (!data || size <= 0)
        return 0.0;

    long long frequencies[256] = {0}; // Use long long for potentially large counts
    double entropy = 0.0;
    double log2 = log(2.0); // Precompute log(2)

    /* Count byte frequencies */
    for (int i = 0; i < size; i++)
    {
        frequencies[data[i]]++;
    }

    /* Calculate Shannon entropy */
    for (int i = 0; i < 256; i++)
    {
        if (frequencies[i] > 0)
        {
            double probability = (double)frequencies[i] / size;
            entropy -= probability * (log(probability) / log2); // Use precomputed log2
        }
    }
    // Clamp entropy between 0 and 8
    if (entropy < 0.0)
        entropy = 0.0;
    if (entropy > 8.0)
        entropy = 8.0;

    return entropy;
}

/* Check for DNS query pattern in data */
int has_dns_pattern(unsigned char *data, int size, char *query, int query_size)
{
    if (!data || !query || query_size <= 0)
        return 0;

    /* Clear query buffer */
    memset(query, 0, query_size);

    /* Basic DNS header check */
    if (size < 13) // Need at least 12 bytes header + 1 byte for first label length/null terminator
        return 0;

    // DNS Header structure (simplified):
    // Transaction ID (2 bytes)
    // Flags (2 bytes) - QR must be 0 for query
    // Questions (2 bytes) - Must be > 0
    // Answer RRs (2 bytes)
    // Authority RRs (2 bytes)
    // Additional RRs (2 bytes)

    // Check Flags: QR bit must be 0 for a query
    if ((data[2] & 0x80) != 0)
    {
        return 0; // This is a response (QR=1), not a query
    }
    // Check Questions: Must have at least one question
    unsigned short qdcount = ntohs(*(unsigned short *)&data[4]);
    if (qdcount == 0)
    {
        return 0; // No questions in this packet
    }

    /* Skip the 12-byte DNS header */
    int pos = 12;
    int query_pos = 0;

    /* Parse QNAME (domain name) */
    while (pos < size)
    {
        unsigned char label_len = data[pos];

        // Check for null terminator (end of QNAME)
        if (label_len == 0)
        {
            pos++; // Consume the null terminator
            break;
        }

        // Check for pointer (compressed name) - Queries shouldn't typically use pointers in QNAME
        if ((label_len & 0xC0) == 0xC0)
        {
            write_to_log(3, "DNS Query parsing encountered compression pointer - unexpected.");
            // Technically invalid in QNAME, but let's stop parsing here.
            break;
        }

        // Check for valid label length (0 < length <= 63)
        if (label_len > 63)
        {
            write_to_log(3, "Invalid DNS label length: %d at pos %d", label_len, pos);
            return 0; // Invalid format
        }

        pos++; // Move past length byte

        /* Make sure label doesn't exceed buffer */
        if (pos + label_len > size)
        {
            write_to_log(3, "DNS label extends beyond packet size");
            return 0; // Truncated packet?
        }

        /* If not the first label, add dot */
        if (query_pos > 0 && query_pos < query_size - 1)
        {
            query[query_pos++] = '.';
        }
        else if (query_pos >= query_size - 1)
        {
            write_to_log(3, "DNS query name buffer too small");
            return 0; // Query too long for buffer
        }

        /* Copy label to query buffer */
        for (int i = 0; i < label_len; i++)
        {
            if (query_pos >= query_size - 1)
            {
                write_to_log(3, "DNS query name buffer too small during copy");
                query[query_pos] = '\0'; // Ensure null termination before returning
                return (query_pos > 0);  // Return true if we copied anything
            }
            // Copy printable chars, replace others with '.'
            query[query_pos++] = isprint(data[pos + i]) ? data[pos + i] : '.';
        }

        pos += label_len; // Move past the label itself
    }

    // After QNAME, expect QTYPE (2 bytes) and QCLASS (2 bytes)
    if (pos + 4 > size)
    {
        // We might have reached end of packet right after QNAME
        // Accept if QNAME was parsed.
        write_to_log(3, "DNS packet too short for QTYPE/QCLASS");
    }

    /* Ensure null termination */
    if (query_pos < query_size)
    {
        query[query_pos] = '\0';
    }
    else if (query_size > 0)
    {
        query[query_size - 1] = '\0'; // Force null term if overflowed slightly
    }

    return (query_pos > 0); // Return true if we extracted any name part
}

/* Detect potential anomalies in flow data */
int detect_anomalies(FLOW_DATA *flow)
{
    if (!flow || !config.enable_anomaly_detection) // Only detect if enabled
        return 0;

    int anomaly_detected = 0;
    char reason[128] = "";

    // Simple heuristic checks for suspicious patterns

    // 1. LAND attack (same source and destination IP/port)
    if (flow->land)
    {
        anomaly_detected = 1;
        strcpy(reason, "LAND attack");
    }

    // 2. High entropy with non-encrypted services (potential obfuscation/exfil)
    // Threshold might need tuning. Be careful not to flag legitimate compressed data.
    if (!anomaly_detected && flow->entropy > 7.0 && // Slightly lower threshold
        flow->bytes > 100 &&                        // Only for flows with some data
        (flow->service != SRV_SSH && flow->service != SRV_HTTP_443 && flow->service != SRV_FTP_DATA))
    {
        anomaly_detected = 1;
        sprintf(reason, "High entropy (%.2f) on non-std-encrypted service %s", flow->entropy, flow->service_name);
    }

    // 3. Connection error rates exceeding threshold
    // Consider the number of connections ('count') to avoid flagging single errors on sparse traffic.
    if (!anomaly_detected && flow->count > 5)
    { // Require at least a few connections
        if (flow->serror_rate >= config.anomaly_threshold)
        {
            anomaly_detected = 1;
            sprintf(reason, "High SYN error rate (%.2f)", flow->serror_rate);
        }
        else if (flow->rerror_rate >= config.anomaly_threshold)
        {
            anomaly_detected = 1;
            sprintf(reason, "High REJ/RST error rate (%.2f)", flow->rerror_rate);
        }
        else if (flow->srv_serror_rate >= config.anomaly_threshold && flow->srv_count > 2)
        { // Service specific
            anomaly_detected = 1;
            sprintf(reason, "High service SYN error rate (%.2f for %s)", flow->srv_serror_rate, flow->service_name);
        }
        else if (flow->srv_rerror_rate >= config.anomaly_threshold && flow->srv_count > 2)
        {
            anomaly_detected = 1;
            sprintf(reason, "High service REJ/RST error rate (%.2f for %s)", flow->srv_rerror_rate, flow->service_name);
        }
    }

    // 4. Unusual service access patterns (high rate of different services from one source)
    if (!anomaly_detected && flow->count > 10 && // Need enough connections to judge rate
        flow->diff_srv_rate >= config.anomaly_threshold)
    {
        anomaly_detected = 1;
        sprintf(reason, "High different service rate (%.2f)", flow->diff_srv_rate);
    }

    // 5. Scanning behavior (many connections to *same destination host*, trying *different services*)
    // Use dst_host stats calculated earlier.
    if (!anomaly_detected && flow->dst_host_count > 10 && // Check if scanning same host
        flow->dst_host_diff_srv_rate >= 0.8)              // High proportion of different services tried
    {
        anomaly_detected = 1;
        sprintf(reason, "Potential scan detected (DstHostCount:%d, DstDiffSrvRate:%.2f)",
                flow->dst_host_count, flow->dst_host_diff_srv_rate);
    }

    // 6. Check for Urgent flag usage (rare, sometimes used maliciously)
    if (!anomaly_detected && flow->urgent > 0)
    {
        anomaly_detected = 1;
        strcpy(reason, "TCP Urgent flag set");
    }

    // 7. Check for wrong fragment (can indicate evasion attempts)
    if (!anomaly_detected && flow->wrong_fragment > 0)
    {
        anomaly_detected = 1;
        strcpy(reason, "Wrong IP fragment detected");
    }

    // Log if anomaly detected
    if (anomaly_detected)
    {
        write_to_log(1, "ANOMALY DETECTED: %s:%d -> %s:%d (%s) Reason: %s",
                     ip_to_string(flow->key.src_ip), flow->key.src_port,
                     ip_to_string(flow->key.dst_ip), flow->key.dst_port,
                     flow->service_name, reason);
    }

    return anomaly_detected;
}

/* Write flow data to log file in JSON format */
void write_flow_log(FLOW_DATA *flow)
{
    if (!flow)
        return; // Should not happen if called correctly

    // Ensure output file is open
    if (!output_fp)
    {
        // Attempt to reopen if closed unexpectedly
        output_fp = fopen(config.output_file, "a");
        if (!output_fp)
        {
            write_to_log(1, "Cannot write flow log, output file not open: %s", config.output_file);
            return;
        }
        write_to_log(2, "Reopened output file for writing: %s", config.output_file);
    }

    // Convert IP addresses to strings
    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];

    // Use thread-safe versions if available, otherwise basic static buffer is okay
    // if logging is single-threaded or protected.
    strcpy(src_ip_str, ip_to_string(flow->key.src_ip));
    strcpy(dst_ip_str, ip_to_string(flow->key.dst_ip));

    // Get current time (use flow's last_seen for consistency)
    char timestamp[64];
    time_t log_time = flow->last_seen;
    struct tm *tm_info = localtime(&log_time);
    if (tm_info)
    {
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%S", tm_info); // ISO 8601-ish
    }
    else
    {
        strcpy(timestamp, "unknown_time");
    }

    // Calculate duration
    double duration = difftime(flow->last_seen, flow->first_seen);
    if (duration < 0)
        duration = 0.0; // Ensure non-negative duration

    // Format the JSON entry with enhanced features
    char json_entry[2048]; // Increased buffer size
    int offset = 0;
    int remaining_size = sizeof(json_entry);
    int written;

    // Use snprintf for safer string building
    written = snprintf(json_entry + offset, remaining_size, "{");
    offset += written;
    remaining_size -= written;

    // Basic flow info
    written = snprintf(json_entry + offset, remaining_size,
                       "\"timestamp\":\"%s\",\"duration\":%.3f,\"protocol\":\"%s\","
                       "\"src_ip\":\"%s\",\"src_port\":%d,\"dst_ip\":\"%s\",\"dst_port\":%d,"
                       "\"service\":\"%s\",\"packets\":%u,\"bytes\":%llu,"
                       "\"src_packets\":%u,\"dst_packets\":%u,\"src_bytes\":%llu,\"dst_bytes\":%llu,",
                       timestamp, duration,
                       (flow->key.protocol == PROTO_TCP) ? "TCP" : (flow->key.protocol == PROTO_UDP) ? "UDP"
                                                               : (flow->key.protocol == PROTO_ICMP)  ? "ICMP"
                                                                                                     : "UNKNOWN",
                       src_ip_str, flow->key.src_port, dst_ip_str, flow->key.dst_port,
                       flow->service_name,
                       flow->packets, flow->bytes,
                       flow->src_packets, flow->dst_packets, flow->src_bytes, flow->dst_bytes);
    if (written < 0 || written >= remaining_size)
        goto buffer_error;
    offset += written;
    remaining_size -= written;

    // TCP Specific / Flags
    written = snprintf(json_entry + offset, remaining_size,
                       "\"flags\":\"%s\",\"flag\":\"%s\",\"flag_code\":%d,",
                       flow->flag_str, get_flag_name(flow->flag), flow->flag);
    if (written < 0 || written >= remaining_size)
        goto buffer_error;
    offset += written;
    remaining_size -= written;

    // Features
    written = snprintf(json_entry + offset, remaining_size,
                       "\"land\":%d,\"wrong_fragment\":%d,\"urgent\":%d,\"entropy\":%.4f,",
                       flow->land, flow->wrong_fragment, flow->urgent, flow->entropy);
    if (written < 0 || written >= remaining_size)
        goto buffer_error;
    offset += written;
    remaining_size -= written;

    // Connection Stats (Source Host Perspective)
    written = snprintf(json_entry + offset, remaining_size,
                       "\"count\":%d,\"srv_count\":%d,"
                       "\"serror_rate\":%.4f,\"srv_serror_rate\":%.4f,\"rerror_rate\":%.4f,\"srv_rerror_rate\":%.4f,"
                       "\"same_srv_rate\":%.4f,\"diff_srv_rate\":%.4f,",
                       flow->count, flow->srv_count,
                       flow->serror_rate, flow->srv_serror_rate, flow->rerror_rate, flow->srv_rerror_rate,
                       flow->same_srv_rate, flow->diff_srv_rate);
    if (written < 0 || written >= remaining_size)
        goto buffer_error;
    offset += written;
    remaining_size -= written;

    // Connection Stats (Destination Host Perspective)
    written = snprintf(json_entry + offset, remaining_size,
                       "\"dst_host_count\":%d,\"dst_host_srv_count\":%d,"
                       "\"dst_host_same_srv_rate\":%.4f,\"dst_host_diff_srv_rate\":%.4f",
                       flow->dst_host_count, flow->dst_host_srv_count,
                       flow->dst_host_same_srv_rate, flow->dst_host_diff_srv_rate);
    if (written < 0 || written >= remaining_size)
        goto buffer_error;
    offset += written;
    remaining_size -= written;

    // Add DNS query if present
    if (flow->dns_query[0])
    {
        // Basic JSON string escaping (replace backslash and quote)
        char safe_dns_query[sizeof(flow->dns_query) * 2]; // Allocate more space for escapes
        int sq_idx = 0;
        for (int i = 0; flow->dns_query[i] != '\0' && sq_idx < sizeof(safe_dns_query) - 2; ++i)
        {
            if (flow->dns_query[i] == '\\' || flow->dns_query[i] == '"')
            {
                safe_dns_query[sq_idx++] = '\\';
            }
            safe_dns_query[sq_idx++] = flow->dns_query[i];
        }
        safe_dns_query[sq_idx] = '\0';

        written = snprintf(json_entry + offset, remaining_size, ",\"dns_query\":\"%s\"", safe_dns_query);
        if (written < 0 || written >= remaining_size)
            goto buffer_error;
        offset += written;
        remaining_size -= written;
    }

    // Close JSON object
    written = snprintf(json_entry + offset, remaining_size, "}");
    if (written < 0 || written >= remaining_size)
        goto buffer_error;
    offset += written;
    remaining_size -= written;

    // Write to local log file
    fprintf(output_fp, "%s\n", json_entry);
    fflush(output_fp); // Ensure data is written promptly

    // Add to send queue if enabled
    if (config.send_enabled)
    {
        add_to_send_queue(json_entry);
    }

    // Check if rotation needed (only check occasionally or based on bytes written)
    // ftell can be slow on large files. Check every N records or so.
    if (flow->packets % 100 == 0)
    { // Check every 100 packets added to this flow
        long file_size = ftell(output_fp);
        if (file_size > (long)config.file_rotation_size * 1024 * 1024)
        {
            rotate_output_file();
            // After rotation, output_fp is reopened, check again
            if (!output_fp)
            {
                write_to_log(1, "Output file failed to reopen after rotation.");
                // Consider attempting recovery or stopping logging.
            }
        }
    }

    // Perform anomaly detection (after all stats are updated)
    detect_anomalies(flow); // Logged internally if detected

    // Cleanup: Should closed/timed-out flows be removed from hash table?
    // Yes, implement flow timeout/cleanup logic elsewhere (e.g., in stats_thread or cleanup_thread)
    // For now, this function only logs the current state.

    return; // Success

buffer_error:
    write_to_log(1, "Buffer overflow while formatting JSON log entry for flow %s:%d -> %s:%d",
                 src_ip_str, flow->key.src_port, dst_ip_str, flow->key.dst_port);
    // Optionally write a truncated or error message to the log file
    fprintf(output_fp, "{\"error\":\"JSON buffer overflow\"}\n");
    fflush(output_fp);
}

/* Add a log entry to the send queue */
void add_to_send_queue(const char *json_data)
{
    if (!json_data || !config.send_enabled)
        return;

    write_to_log(3, "Adding data to send queue");

    LogQueueNode *new_node = (LogQueueNode *)malloc(sizeof(LogQueueNode));
    if (!new_node)
    {
        write_to_log(1, "Failed to allocate memory for queue node");
        return;
    }

    new_node->json_data = _strdup(json_data); // Use _strdup for Windows/MSVC
    if (!new_node->json_data)
    {
        write_to_log(1, "Failed to allocate memory for JSON data copy");
        free(new_node);
        return;
    }
    new_node->next = NULL;

    EnterCriticalSection(&log_queue_lock);
    if (!log_queue_head) // Queue is empty
    {
        log_queue_head = new_node;
        log_queue_tail = new_node;
    }
    else // Add to end of queue
    {
        log_queue_tail->next = new_node;
        log_queue_tail = new_node;
    }
    log_queue_size++;
    int current_size = log_queue_size; // Read size while holding lock
    LeaveCriticalSection(&log_queue_lock);

    write_to_log(3, "Queue size now: %d", current_size);

    // Trigger immediate send based on size threshold (can be adjusted)
    if (current_size >= 100) // Increased threshold for less frequent triggers
    {
        write_to_log(2, "Queue threshold reached (%d), triggering potential send", current_size);
        // Set last_send_time to 0 to encourage the sender thread to send soon.
        // Avoid directly calling send_data_to_server here to prevent blocking capture.
        // A dedicated sender thread handles the actual sending based on time/size.
        // last_send_time = 0; // Let sender thread handle timing based on interval
    }
}

/* Send data to the server */
int send_data_to_server(void)
{
    HINTERNET hInternet = NULL, hConnect = NULL, hRequest = NULL;
    BOOL result = FALSE;
    DWORD statusCode = 0, statusCodeSize = sizeof(statusCode);
    char hostname[MAX_COMPUTERNAME_LENGTH + 1] = {0};            // Use defined constant
    DWORD hostname_len = sizeof(hostname) / sizeof(hostname[0]); // Size in characters
    char *payload = NULL;
    int queue_entries = 0;
    char *data_array = NULL;
    size_t data_size = 0;
    size_t total_size = 0;
    LogQueueNode *current = NULL;
    LogQueueNode *head_to_send = NULL; // Keep track of the batch being sent

    EnterCriticalSection(&log_queue_lock);
    if (!log_queue_head)
    {
        LeaveCriticalSection(&log_queue_lock);
        return 1; // Nothing to send
    }
    // Move the current queue head to a temporary list to send
    head_to_send = log_queue_head;
    log_queue_head = NULL; // Reset main queue pointers
    log_queue_tail = NULL;
    queue_entries = log_queue_size;
    log_queue_size = 0;
    LeaveCriticalSection(&log_queue_lock);

    if (queue_entries == 0)
    {
        // Should not happen if head_to_send was not NULL, but check anyway
        return 1;
    }

    // Get computer name (do this outside lock)
    if (!GetComputerNameA(hostname, &hostname_len))
    {
        strncpy(hostname, "unknown_host", sizeof(hostname) - 1);
        hostname[sizeof(hostname) - 1] = '\0';
        write_to_log(1, "Failed to get computer name: %d", GetLastError());
    }

    /* First pass: calculate required size for JSON array */
    total_size = 3; // For "[" and "]" and null terminator
    current = head_to_send;
    while (current)
    {
        if (current->json_data)
        {
            total_size += strlen(current->json_data) + 1; // +1 for potential comma
        }
        current = current->next;
    }

    data_array = (char *)malloc(total_size);
    if (!data_array)
    {
        write_to_log(1, "Failed to allocate memory for data array (%zu bytes)", total_size);
        // Need to free the nodes in head_to_send list
        current = head_to_send;
        while (current)
        {
            LogQueueNode *next = current->next;
            if (current->json_data)
                free(current->json_data);
            free(current);
            current = next;
        }
        return 0; // Allocation failure
    }

    /* Build the JSON array string */
    strcpy(data_array, "[");
    data_size = 1;
    current = head_to_send;
    int first = 1;
    while (current)
    {
        if (current->json_data)
        {
            if (!first)
            {
                // Check buffer space before strcat
                if (data_size + 1 >= total_size)
                {
                    write_to_log(1, "Buffer overflow detected while building JSON array (comma)");
                    free(data_array);
                    goto cleanup_nodes; // Error exit
                }
                strcat(data_array, ",");
                data_size++;
            }
            // Check buffer space before strcat
            size_t json_len = strlen(current->json_data);
            if (data_size + json_len >= total_size)
            {
                write_to_log(1, "Buffer overflow detected while building JSON array (data)");
                free(data_array);
                goto cleanup_nodes; // Error exit
            }
            strcat(data_array, current->json_data);
            data_size += json_len;
            first = 0;
        }
        current = current->next;
    }
    // Check buffer space before strcat
    if (data_size + 1 >= total_size)
    {
        write_to_log(1, "Buffer overflow detected while building JSON array (end bracket)");
        free(data_array);
        goto cleanup_nodes; // Error exit
    }
    strcat(data_array, "]");
    data_size += 1;

    write_to_log(2, "Sending %d network entries to server", queue_entries);

    /* Construct the final payload */
    // Size = length of format string + hostname + data_array + some buffer
    size_t payload_size = strlen("{\"client_id\":\"\",\"data\":}") + strlen(hostname) + data_size + 32;
    payload = (char *)malloc(payload_size);
    if (!payload)
    {
        write_to_log(1, "Failed to allocate memory for payload");
        free(data_array);
        goto cleanup_nodes; // Error exit
    }

    sprintf(payload, "{\"client_id\":\"%s\",\"data\":%s}", hostname, data_array);
    free(data_array); // Free the intermediate array

    /* --- WinINet HTTP POST --- */
    hInternet = InternetOpenA("NexLogClient/3.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet)
    {
        write_to_log(1, "Failed to initialize WinINet (InternetOpenA): %d", GetLastError());
        free(payload);
        goto cleanup_nodes; // Error exit (don't retry immediately)
    }

    // Set timeouts (sensible defaults)
    DWORD connect_timeout = 10000; // 10 seconds
    DWORD send_timeout = 30000;    // 30 seconds
    DWORD receive_timeout = 30000; // 30 seconds
    InternetSetOption(hInternet, INTERNET_OPTION_CONNECT_TIMEOUT, &connect_timeout, sizeof(DWORD));
    InternetSetOption(hInternet, INTERNET_OPTION_SEND_TIMEOUT, &send_timeout, sizeof(DWORD));
    InternetSetOption(hInternet, INTERNET_OPTION_RECEIVE_TIMEOUT, &receive_timeout, sizeof(DWORD));

    // Parse server URL from config
    char host[256] = SERVER_IP;                // Default host
    INTERNET_PORT port = SERVER_PORT;          // Default port (use INTERNET_PORT type)
    char path[MAX_PATH] = "/api/network_data"; // Default path
    char scheme[16] = "http";                  // Default scheme

    if (strlen(config.server_url) > 0)
    {
        URL_COMPONENTS urlComp;
        memset(&urlComp, 0, sizeof(urlComp));
        urlComp.dwStructSize = sizeof(urlComp);
        // Provide buffers for components
        urlComp.lpszScheme = scheme;
        urlComp.dwSchemeLength = sizeof(scheme);
        urlComp.lpszHostName = host;
        urlComp.dwHostNameLength = sizeof(host);
        urlComp.lpszUrlPath = path;
        urlComp.dwUrlPathLength = sizeof(path);

        if (!InternetCrackUrlA(config.server_url, 0, 0, &urlComp))
        {
            write_to_log(1, "Failed to parse server URL: %s, Error: %d", config.server_url, GetLastError());
            // Stick with defaults or handle error
        }
        else
        {
            port = urlComp.nPort; // Get port from parsed URL
            // Ensure path starts with '/' if it exists
            if (path[0] != '/' && urlComp.dwUrlPathLength > 0)
            {
                memmove(path + 1, path, urlComp.dwUrlPathLength);
                path[0] = '/';
                path[urlComp.dwUrlPathLength + 1] = '\0';
            }
            else if (urlComp.dwUrlPathLength == 0)
            {
                strcpy(path, "/"); // Default to root path if none specified
            }
            write_to_log(3, "Parsed Server URL: Scheme=%s, Host=%s, Port=%d, Path=%s", scheme, host, port, path);
        }
    }

    hConnect = InternetConnectA(hInternet, host, port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect)
    {
        write_to_log(1, "Failed to connect to server %s:%d: %d", host, port, GetLastError());
        InternetCloseHandle(hInternet);
        free(payload);
        goto cleanup_nodes; // Error exit
    }

    // Determine flags based on scheme (HTTPS or HTTP)
    DWORD requestFlags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_UI;
    if (_stricmp(scheme, "https") == 0)
    {
        requestFlags |= INTERNET_FLAG_SECURE; // Add secure flag for HTTPS
    }

    hRequest = HttpOpenRequestA(hConnect, "POST", path, NULL, NULL, NULL, requestFlags, 0);
    if (!hRequest)
    {
        write_to_log(1, "Failed to create HTTP request (HttpOpenRequestA): %d", GetLastError());
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        free(payload);
        goto cleanup_nodes; // Error exit
    }

    // Send the request with JSON payload
    const char *headers = "Content-Type: application/json\r\n"; // Keep-Alive is default in HTTP/1.1
    result = HttpSendRequestA(hRequest, headers, (DWORD)strlen(headers), payload, (DWORD)strlen(payload));
    if (!result)
    {
        write_to_log(1, "Failed to send data (HttpSendRequestA): %d", GetLastError());
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        free(payload);
        goto cleanup_nodes; // Error exit
    }

    // Check the HTTP response status code
    if (!HttpQueryInfoA(hRequest, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
                        &statusCode, &statusCodeSize, NULL))
    {
        write_to_log(1, "Failed to get HTTP status code (HttpQueryInfoA): %d", GetLastError());
        // Continue to cleanup, but consider the send failed
        result = FALSE;
    }
    else
    {
        result = (statusCode >= 200 && statusCode < 300); // Success is 2xx
        if (result)
        {
            write_to_log(2, "Successfully sent %d network entries to server (%d bytes payload). Status: %d",
                         queue_entries, (int)strlen(payload), statusCode);
        }
        else
        {
            write_to_log(1, "Server returned non-success status code: %d", statusCode);
            // Optionally read response body for more info
            char responseBuffer[512];
            DWORD bytesRead = 0;
            if (InternetReadFile(hRequest, responseBuffer, sizeof(responseBuffer) - 1, &bytesRead) && bytesRead > 0)
            {
                responseBuffer[bytesRead] = '\0';
                write_to_log(1, "Server response snippet: %s", responseBuffer);
            }
        }
    }

    // Cleanup WinINet handles
    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
    free(payload);

    // Free the nodes that were successfully sent
    current = head_to_send;
    while (current)
    {
        LogQueueNode *next = current->next;
        if (current->json_data)
            free(current->json_data);
        free(current);
        current = next;
    }

    return result; // Return success (TRUE) or failure (FALSE)

cleanup_nodes:
    // Free the list of nodes that we failed to send
    write_to_log(1, "Cleaning up unsent queue nodes due to error.");
    current = head_to_send;
    while (current)
    {
        LogQueueNode *next = current->next;
        if (current->json_data)
            free(current->json_data);
        free(current);
        current = next;
    }
    // Since we failed, maybe try putting them back? Risky, could lead to infinite loop.
    // Better to just discard them after logging the failure.
    return 0; // Indicate failure
}

/* Ping the server */
int ping_server(void)
{
    HINTERNET hInternet = NULL, hConnect = NULL, hRequest = NULL;
    BOOL result = FALSE;
    DWORD statusCode = 0, statusCodeSize = sizeof(statusCode);
    char hostname[MAX_COMPUTERNAME_LENGTH + 1] = {0};
    DWORD hostname_len = sizeof(hostname) / sizeof(hostname[0]);
    char computer_info[512] = {0}; // Buffer for POST data

    if (!config.send_enabled)
    {             // Don't ping if sending is disabled
        return 1; // Pretend it's okay
    }

    // Get computer name
    if (!GetComputerNameA(hostname, &hostname_len))
    {
        strncpy(hostname, "unknown_host", sizeof(hostname) - 1);
        hostname[sizeof(hostname) - 1] = '\0';
        write_to_log(1, "Ping: Failed to get computer name: %d", GetLastError());
    }
    // Format POST data (simple key=value)
    sprintf(computer_info, "client_id=%s", hostname);

    write_to_log(3, "Pinging server at %s with client_id=%s", config.server_url, hostname); // Use full URL in log

    hInternet = InternetOpenA("NexLogClientPing/3.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet)
    {
        write_to_log(1, "Ping: Failed to initialize WinINet (InternetOpenA): %d", GetLastError());
        return 0;
    }

    // Use shorter timeouts for ping
    DWORD connect_timeout = 5000; // 5 seconds
    DWORD send_timeout = 5000;    // 5 seconds
    DWORD receive_timeout = 5000; // 5 seconds
    InternetSetOption(hInternet, INTERNET_OPTION_CONNECT_TIMEOUT, &connect_timeout, sizeof(DWORD));
    InternetSetOption(hInternet, INTERNET_OPTION_SEND_TIMEOUT, &send_timeout, sizeof(DWORD));
    InternetSetOption(hInternet, INTERNET_OPTION_RECEIVE_TIMEOUT, &receive_timeout, sizeof(DWORD));

    // Parse server URL (reuse logic from send_data)
    char host[256] = SERVER_IP;
    INTERNET_PORT port = SERVER_PORT;
    char path[MAX_PATH] = "/api/ping"; // Specific ping path
    char scheme[16] = "http";

    if (strlen(config.server_url) > 0)
    {
        URL_COMPONENTS urlComp;
        memset(&urlComp, 0, sizeof(urlComp));
        urlComp.dwStructSize = sizeof(urlComp);
        urlComp.lpszScheme = scheme;
        urlComp.dwSchemeLength = sizeof(scheme);
        urlComp.lpszHostName = host;
        urlComp.dwHostNameLength = sizeof(host);
        // Path is fixed for ping, ignore path from main URL
        urlComp.lpszUrlPath = NULL;
        urlComp.dwUrlPathLength = 0;

        if (InternetCrackUrlA(config.server_url, 0, 0, &urlComp))
        {
            port = urlComp.nPort;
            // Use the fixed path "/api/ping"
            strcpy(path, "/api/ping");
            write_to_log(3, "Ping URL Parse: Scheme=%s, Host=%s, Port=%d, Path=%s", scheme, host, port, path);
        }
        else
        {
            write_to_log(1, "Ping: Failed to parse base server URL: %s, Error: %d. Using defaults.", config.server_url, GetLastError());
            // Defaults are already set
        }
    }

    hConnect = InternetConnectA(hInternet, host, port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect)
    {
        write_to_log(1, "Ping: Failed to connect to server %s:%d: %d", host, port, GetLastError());
        InternetCloseHandle(hInternet);
        return 0;
    }

    // Determine flags based on scheme
    DWORD requestFlags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_UI;
    if (_stricmp(scheme, "https") == 0)
    {
        requestFlags |= INTERNET_FLAG_SECURE;
    }

    hRequest = HttpOpenRequestA(hConnect, "POST", path, NULL, NULL, NULL, requestFlags, 0);
    if (!hRequest)
    {
        write_to_log(1, "Ping: Failed to create HTTP request: %d", GetLastError());
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return 0;
    }

    // Send the request with form-urlencoded data
    const char *headers = "Content-Type: application/x-www-form-urlencoded\r\n";
    result = HttpSendRequestA(hRequest, headers, (DWORD)strlen(headers), computer_info, (DWORD)strlen(computer_info));
    if (!result)
    {
        write_to_log(1, "Ping: Failed to send request (HttpSendRequestA): %d", GetLastError());
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return 0;
    }

    // Check response status
    if (!HttpQueryInfoA(hRequest, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
                        &statusCode, &statusCodeSize, NULL))
    {
        write_to_log(1, "Ping: Failed to get HTTP status: %d", GetLastError());
        result = FALSE; // Treat as failure
    }
    else
    {
        result = (statusCode >= 200 && statusCode < 300);
        if (result)
        {
            write_to_log(3, "Successfully pinged server at %s:%d. Status: %d", host, port, statusCode);
        }
        else
        {
            write_to_log(1, "Server ping failed with status code: %d", statusCode);
        }
    }

    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
    return result;
}

/* Rotate the output file */
void rotate_output_file(void)
{
    if (!output_fp)
        return;

    write_to_log(2, "Attempting to rotate output file: %s", config.output_file);
    fclose(output_fp);
    output_fp = NULL; // Set to NULL immediately after closing

    char backup_filename[MAX_PATH * 2]; // Extra space for timestamp etc.
    time_t now = time(NULL);
    struct tm *time_info = localtime(&now);
    char timestamp[64];

    if (time_info)
    {
        strftime(timestamp, sizeof(timestamp), "%Y%m%d_%H%M%S", time_info);
    }
    else
    {
        // Fallback if localtime fails
        sprintf(timestamp, "%lld", (long long)now);
    }

    char *dot = strrchr(config.output_file, '.');
    if (dot)
    {
        // Insert timestamp before the extension
        size_t base_len = dot - config.output_file;
        snprintf(backup_filename, sizeof(backup_filename), "%.*s_%s%s",
                 (int)base_len, config.output_file, // Base part
                 timestamp,                         // Timestamp
                 dot);                              // Extension
    }
    else
    {
        // Append timestamp if no extension
        snprintf(backup_filename, sizeof(backup_filename), "%s_%s",
                 config.output_file, timestamp);
    }

    // Rename the current file to the backup name
    if (MoveFileEx(config.output_file, backup_filename, MOVEFILE_REPLACE_EXISTING) == 0)
    {
        write_to_log(1, "Failed to rename %s to %s. Error: %d.", config.output_file, backup_filename, GetLastError());
        // Attempt to reopen the original file to continue logging if rename failed
        output_fp = fopen(config.output_file, "a");
        if (!output_fp)
        {
            write_to_log(1, "CRITICAL: Failed to reopen original log file %s after failed rotation.", config.output_file);
            // Logging is likely broken now.
        }
        else
        {
            write_to_log(1, "Reopened original log file %s after failed rotation.", config.output_file);
        }
    }
    else
    {
        write_to_log(2, "Successfully rotated output file to %s", backup_filename);
        // Open the new log file (original name) for continued logging
        output_fp = fopen(config.output_file, "w"); // Open new file in write mode
        if (!output_fp)
        {
            write_to_log(1, "CRITICAL: Failed to open new log file %s after rotation.", config.output_file);
            // Logging is likely broken.
        }
        else
        {
            write_to_log(2, "Opened new log file %s for writing.", config.output_file);
        }
    }
}

/* Cleanup old log files */
void cleanup_old_logs(void)
{
    WIN32_FIND_DATA find_data;
    HANDLE find_handle = INVALID_HANDLE_VALUE;
    time_t current_time;
    FILETIME cutoff_filetime;
    ULARGE_INTEGER cutoff_uli;
    char search_path[MAX_PATH];
    char base_filename[MAX_PATH];
    char file_dir[MAX_PATH];
    char current_log_filename_only[MAX_PATH];

    // Get directory and base filename pattern for rotated logs
    strncpy(file_dir, config.output_file, sizeof(file_dir) - 1);
    file_dir[sizeof(file_dir) - 1] = '\0';

    char *last_slash = strrchr(file_dir, '\\');
    if (last_slash)
    {
        *(last_slash + 1) = '\0'; // Keep the trailing slash for dir path
        strncpy(current_log_filename_only, last_slash + 1, sizeof(current_log_filename_only) - 1);
        current_log_filename_only[sizeof(current_log_filename_only) - 1] = '\0';

        // Create base filename pattern (e.g., "network_log3_*.json")
        char *dot = strrchr(current_log_filename_only, '.');
        if (dot)
        {
            size_t base_len = dot - current_log_filename_only;
            snprintf(base_filename, sizeof(base_filename), "%.*s_*%s", (int)base_len, current_log_filename_only, dot);
        }
        else
        {
            snprintf(base_filename, sizeof(base_filename), "%s_*", current_log_filename_only);
        }

        snprintf(search_path, sizeof(search_path), "%s%s", file_dir, base_filename);
    }
    else // Log file is in current directory
    {
        strcpy(file_dir, ".\\"); // Current directory
        strncpy(current_log_filename_only, config.output_file, sizeof(current_log_filename_only) - 1);
        current_log_filename_only[sizeof(current_log_filename_only) - 1] = '\0';

        char *dot = strrchr(current_log_filename_only, '.');
        if (dot)
        {
            size_t base_len = dot - current_log_filename_only;
            snprintf(base_filename, sizeof(base_filename), "%.*s_*%s", (int)base_len, current_log_filename_only, dot);
        }
        else
        {
            snprintf(base_filename, sizeof(base_filename), "%s_*", current_log_filename_only);
        }

        snprintf(search_path, sizeof(search_path), "%s%s", file_dir, base_filename);
    }

    // Calculate cutoff time
    time(&current_time);
    ULONGLONG cutoff_interval = (ULONGLONG)config.log_retention_hours * 3600 * 10000000; // hours to 100ns intervals
    GetSystemTimeAsFileTime((LPFILETIME)&cutoff_uli);                                    // Get current time as FILETIME
    cutoff_uli.QuadPart -= cutoff_interval;                                              // Subtract retention period
    cutoff_filetime.dwLowDateTime = cutoff_uli.LowPart;
    cutoff_filetime.dwHighDateTime = cutoff_uli.HighPart;

    write_to_log(2, "Starting cleanup of old logs in %s matching %s (older than %d hours)", file_dir, base_filename, config.log_retention_hours);

    find_handle = FindFirstFile(search_path, &find_data);
    if (find_handle == INVALID_HANDLE_VALUE)
    {
        if (GetLastError() != ERROR_FILE_NOT_FOUND)
        {
            write_to_log(1, "Error finding log files for cleanup: %d", GetLastError());
        }
        else
        {
            write_to_log(2, "No old log files found matching pattern %s", base_filename);
        }
        return;
    }

    do
    {
        // Skip directories and the active log file
        if ((find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
        {
            continue;
        }
        // Construct full path for deletion
        char full_path[MAX_PATH * 2];
        snprintf(full_path, sizeof(full_path), "%s%s", file_dir, find_data.cFileName);

        // Compare file's last write time with cutoff time
        if (CompareFileTime(&find_data.ftLastWriteTime, &cutoff_filetime) == -1) // -1 means file time is earlier
        {
            if (DeleteFile(full_path))
            {
                write_to_log(2, "Deleted old log file: %s", find_data.cFileName);
            }
            else
            {
                write_to_log(1, "Failed to delete old log file: %s (Error: %d)",
                             full_path, GetLastError());
            }
        }
    } while (FindNextFile(find_handle, &find_data));

    DWORD find_error = GetLastError();
    if (find_error != ERROR_NO_MORE_FILES)
    {
        write_to_log(1, "Error during log file cleanup iteration: %d", find_error);
    }

    FindClose(find_handle);
    write_to_log(2, "Log cleanup finished.");
}

/* Packet capture thread */
unsigned int __stdcall capture_thread(void *arg)
{
    write_to_log(2, "Packet capture thread started");

    unsigned char *buffer = (unsigned char *)malloc(MAX_PACKET_SIZE);
    if (!buffer)
    {
        write_to_log(1, "Failed to allocate packet buffer");
        running = 0; // Stop service if cannot allocate buffer
        return 1;
    }

    int bytes_received;
    struct sockaddr_in source; // Not strictly needed for SOCK_RAW recv, but recvfrom expects it
    int source_size = sizeof(source);
    int no_packet_count = 0;

    while (running)
    {
        // Receive a packet using recv (since we bound the socket)
        // bytes_received = recv(capture_socket, buffer, MAX_PACKET_SIZE, 0);

        // Using recvfrom just to maintain original structure, though source addr isn't used
        bytes_received = recvfrom(capture_socket, (char *)buffer, MAX_PACKET_SIZE, 0,
                                  (struct sockaddr *)&source, &source_size);

        if (bytes_received > 0)
        {
            no_packet_count = 0; // Reset counter on successful receive
            /* Process the packet */
            process_packet(buffer, bytes_received);
        }
        else if (bytes_received == SOCKET_ERROR)
        {
            DWORD error = WSAGetLastError();
            if (error == WSAEWOULDBLOCK) // Expected error for non-blocking socket
            {
                no_packet_count++;
                // Wait briefly if no packets received for a while to avoid busy-waiting
                if (no_packet_count > 1000)
                {                        // Adjust threshold as needed
                    Sleep(1);            // Sleep 1ms
                    no_packet_count = 0; // Reset counter after sleep
                }
            }
            else if (error == WSAEINTR)
            {
                // Interrupted system call, maybe shutting down?
                write_to_log(2, "recvfrom interrupted (WSAEINTR), checking running status.");
                continue; // Check running flag again
            }
            else if (error == WSAENETDOWN || error == WSAENETRESET || error == WSAECONNABORTED || error == WSAECONNRESET)
            {
                write_to_log(1, "Network error during recvfrom: %d. Interface might be down.", error);
                // Maybe try to re-initialize capture? For now, sleep and retry.
                Sleep(5000);
            }
            else
            {
                // Log other unexpected errors
                write_to_log(1, "Unexpected recvfrom error: %d", error);
                // Consider stopping or pausing on persistent errors
                Sleep(1000); // Prevent fast error loops
            }
        }
        else if (bytes_received == 0)
        {
            // According to MSDN, recv returning 0 means graceful closure for TCP,
            // but for raw sockets it might indicate an issue.
            write_to_log(1, "recvfrom returned 0 bytes, connection might be closed or issue occurred.");
            Sleep(100);
        }
    }

    free(buffer);
    write_to_log(2, "Packet capture thread exiting");
    return 0;
}

/* Data sender thread function */
unsigned int __stdcall sender_thread_func(void *arg)
{
    time_t now;
    int retry_count = 0;
    const int max_retries = 5;           // Max consecutive retries before longer pause
    const int base_retry_delay_sec = 10; // Initial retry delay
    const int max_retry_delay_sec = 60;  // Max retry delay

    write_to_log(2, "Data sender thread started, will check queue every second, send interval ~%d seconds", config.send_interval);

    // Perform initial send attempt shortly after start
    Sleep(5000); // Wait a bit for initial data collection
    if (config.send_enabled)
    {
        if (send_data_to_server())
        {
            write_to_log(2, "Initial data send successful");
            last_send_time = time(NULL);
        }
        else
        {
            write_to_log(1, "Initial data send failed - check server connectivity. Will retry.");
            retry_count = 1;                                                           // Start retry logic
            last_send_time = time(NULL) - config.send_interval + base_retry_delay_sec; // Schedule retry soon
        }
    }

    while (running)
    {
        if (!config.send_enabled)
        {
            Sleep(5000); // Sleep longer if sending is disabled
            continue;
        }

        now = time(NULL);
        int current_queue_size = 0;
        EnterCriticalSection(&log_queue_lock);
        current_queue_size = log_queue_size;
        LeaveCriticalSection(&log_queue_lock);

        // Check if time to send (interval passed or retrying) OR queue is large
        if ((current_queue_size > 0 && (now - last_send_time >= config.send_interval)) ||
            (current_queue_size >= 200) || // Send if queue gets large, regardless of time
            (retry_count > 0))             // Send immediately if in retry mode
        {
            if (current_queue_size > 0 || retry_count > 0) // Ensure there's something to send or we are retrying
            {
                write_to_log(3, "Attempting to send %d queued entries to server (Retry count: %d)", current_queue_size, retry_count);
                if (send_data_to_server())
                {
                    last_send_time = now;
                    retry_count = 0; // Reset retries on success
                    write_to_log(2, "Successfully sent network data batch to server.");
                }
                else
                {
                    retry_count++;
                    write_to_log(1, "Failed to send data batch (attempt %d).", retry_count);

                    if (retry_count > max_retries)
                    {
                        write_to_log(1, "Too many consecutive send failures (%d). Pausing send attempts for %d seconds.", max_retries, max_retry_delay_sec);
                        last_send_time = now; // Reset timer to wait full interval + extra delay
                        Sleep(max_retry_delay_sec * 1000);
                        retry_count = 0; // Reset retry count after long pause
                    }
                    else
                    {
                        // Exponential backoff (simple version)
                        int retry_delay = base_retry_delay_sec * (1 << (retry_count - 1));
                        if (retry_delay > max_retry_delay_sec)
                            retry_delay = max_retry_delay_sec;
                        write_to_log(1, "Will retry sending in %d seconds.", retry_delay);
                        last_send_time = now; // Update last attempt time
                        Sleep(retry_delay * 1000);
                        // Keep retry_count active for next iteration check
                    }
                    continue; // Skip to next loop iteration after handling failure
                }
            }
            else
            {
                // Interval passed, but queue is empty and not retrying. Reset timer.
                last_send_time = now;
            }
        }
        Sleep(1000); // Check queue/time every second
    }

    // --- Thread Exiting ---
    write_to_log(2, "Sender thread exiting. Attempting to send any remaining data...");
    if (config.send_enabled)
    {
        EnterCriticalSection(&log_queue_lock);
        int final_queue_size = log_queue_size;
        LeaveCriticalSection(&log_queue_lock);
        if (final_queue_size > 0)
        {
            if (send_data_to_server())
            {
                write_to_log(2, "Successfully sent final %d data entries.", final_queue_size);
            }
            else
            {
                write_to_log(1, "Failed to send final %d data entries on exit.", final_queue_size);
            }
        }
        else
        {
            write_to_log(2, "No remaining data in queue to send on exit.");
        }
    }
    return 0;
}

/* Server ping thread function */
unsigned int __stdcall ping_thread_func(void *arg)
{
    time_t now;
    int retry_count = 0;
    const int max_retries = 3;
    const int retry_delay_sec = 15;

    write_to_log(2, "Ping thread started, will ping server every %d seconds", config.ping_interval);

    // Perform initial ping shortly after start
    Sleep(10000); // Wait a bit longer than sender
    if (config.send_enabled)
    {
        if (ping_server())
        {
            write_to_log(2, "Initial server ping successful");
            last_ping_time = time(NULL);
        }
        else
        {
            write_to_log(1, "Initial server ping failed - will retry");
            retry_count = 1;
            // Schedule retry sooner than full interval
            last_ping_time = time(NULL) - config.ping_interval + retry_delay_sec;
        }
    }

    while (running)
    {
        if (!config.send_enabled)
        {
            Sleep(5000); // Sleep longer if sending/pinging disabled
            continue;
        }

        now = time(NULL);
        if (now - last_ping_time >= config.ping_interval || retry_count > 0)
        {
            if (ping_server())
            {
                last_ping_time = now;
                retry_count = 0; // Reset retries on success
                write_to_log(3, "Successfully pinged server");
            }
            else
            {
                retry_count++;
                write_to_log(1, "Failed to ping server (attempt %d).", retry_count);

                if (retry_count > max_retries)
                {
                    write_to_log(1, "Too many consecutive ping failures (%d). Will wait full interval.", max_retries);
                    last_ping_time = now; // Reset timer to wait full interval
                    retry_count = 0;      // Reset retry count
                }
                else
                {
                    write_to_log(1, "Will retry ping in %d seconds.", retry_delay_sec);
                    last_ping_time = now; // Update last attempt time
                    Sleep(retry_delay_sec * 1000);
                    // Keep retry_count active
                }
                continue; // Skip to next iteration
            }
        }
        Sleep(5000); // Check time every 5 seconds
    }
    write_to_log(2, "Ping thread exiting");
    return 0;
}

/* Log cleanup thread function */
unsigned int __stdcall cleanup_thread_func(void *arg)
{
    time_t last_cleanup_time = 0;
    time_t now;
    const long cleanup_check_interval_sec = 3600; // Check every hour

    write_to_log(2, "Log cleanup thread started, retention period: %d hours. Check interval: %ld seconds.",
                 config.log_retention_hours, cleanup_check_interval_sec);

    // Perform initial cleanup shortly after start
    Sleep(60000); // Wait 1 minute before first cleanup
    if (config.log_retention_hours > 0)
    {
        cleanup_old_logs();
        last_cleanup_time = time(NULL);
    }

    while (running)
    {
        // Only run cleanup if retention is enabled
        if (config.log_retention_hours <= 0)
        {
            Sleep(cleanup_check_interval_sec * 1000); // Still sleep, but don't clean
            continue;
        }

        now = time(NULL);
        if (now - last_cleanup_time >= cleanup_check_interval_sec)
        {
            write_to_log(2, "Running scheduled log cleanup...");
            cleanup_old_logs();
            last_cleanup_time = now;
        }
        Sleep(60000); // Check every minute if it's time to clean
    }
    write_to_log(2, "Log cleanup thread exiting");
    return 0;
}

// Placeholder for freeing a FLOW_DATA structure
void free_flow_data(void *data)
{
    if (data)
    {
        free(data);
    }
}

// Placeholder for freeing a HOST_DATA structure
void free_host_data(void *data)
{
    if (data)
    {
        free(data);
    }
}

// Callback function for hash_table_foreach to check flow timeout
void check_flow_timeout(void *item, void *user_data)
{
    FLOW_DATA *flow = (FLOW_DATA *)item;
    time_t *now_ptr = (time_t *)user_data;
    time_t now = *now_ptr;
    // Define timeout (e.g., 5 minutes = 300 seconds)
    // Use capture_interval * multiplier? e.g., 10 * 60s = 600s
    time_t timeout_seconds = config.capture_interval * 10;
    if (timeout_seconds < 300)
        timeout_seconds = 300; // Minimum 5 minutes

    if (flow && (now - flow->last_seen > timeout_seconds))
    {
        // Log flow before removing (optional, could be noisy)
        // update_flow_connection_stats(flow); // Update final stats?
        // write_flow_log(flow);

        // Mark for removal (cannot remove directly during iteration)
        // A better approach is needed: add to a removal list, remove after iteration.
        // For simplicity here, we'll just log it. Removal needs rework.
        write_to_log(3, "Flow timed out (inactive > %llds): %s:%d -> %s:%d",
                     (long long)timeout_seconds,
                     ip_to_string(flow->key.src_ip), flow->key.src_port,
                     ip_to_string(flow->key.dst_ip), flow->key.dst_port);
        // Actual removal should happen *after* hash_table_foreach completes.
    }
}

// Callback function for hash_table_foreach to check host timeout
void check_host_timeout(void *item, void *user_data)
{
    HOST_DATA *host = (HOST_DATA *)item;
    time_t *now_ptr = (time_t *)user_data;
    time_t now = *now_ptr;
    // Define timeout (e.g., 1 hour = 3600 seconds)
    time_t timeout_seconds = 3600;

    if (host && (now - host->last_seen > timeout_seconds))
    {
        // Mark for removal
        write_to_log(3, "Host timed out (inactive > %llds): %s",
                     (long long)timeout_seconds, ip_to_string(host->ip));
        // Actual removal should happen *after* hash_table_foreach completes.
    }
}

/* Statistics update and cleanup thread function */
unsigned int __stdcall stats_thread_func(void *arg)
{
    time_t last_stats_update = 0;
    time_t last_table_cleanup = 0;
    const long stats_interval_sec = 60;    // Update stats less frequently
    const long cleanup_interval_sec = 300; // Clean tables every 5 mins

    write_to_log(2, "Statistics and cleanup thread started. Stats interval: %lds, Cleanup interval: %lds",
                 stats_interval_sec, cleanup_interval_sec);

    while (running)
    {
        time_t now = time(NULL);

        // --- Periodic Table Cleanup ---
        if (now - last_table_cleanup >= cleanup_interval_sec)
        {
            write_to_log(2, "Running periodic hash table cleanup...");

            // ** Flow Table Cleanup **
            EnterCriticalSection(&flow_table_lock);
            size_t current_flow_count = flow_table->item_count;
            LeaveCriticalSection(&flow_table_lock);
            write_to_log(2, "Cleanup check: Current active flows: %zu", current_flow_count);
            // hash_table_foreach(flow_table, check_flow_timeout, &now);
            // --> Implement actual removal logic here <--

            // ** Host Table Cleanup **
            EnterCriticalSection(&host_table_lock);
            size_t current_host_count = host_table->item_count;
            LeaveCriticalSection(&host_table_lock);
            write_to_log(2, "Cleanup check: Current tracked hosts: %zu", current_host_count);
            // hash_table_foreach(host_table, check_host_timeout, &now);
            // --> Implement actual removal logic here <--

            last_table_cleanup = now;
            write_to_log(2, "Hash table cleanup check finished.");
        }

        // --- Periodic Stats Update (Example) ---
        // This is less critical than cleanup. Can be used to log overall stats.
        if (now - last_stats_update >= stats_interval_sec)
        {
            // Log current table sizes or other summary stats
            EnterCriticalSection(&flow_table_lock);
            size_t flow_count_now = flow_table->item_count;
            LeaveCriticalSection(&flow_table_lock);
            EnterCriticalSection(&host_table_lock);
            size_t host_count_now = host_table->item_count;
            LeaveCriticalSection(&host_table_lock);
            EnterCriticalSection(&log_queue_lock);
            int queue_size_now = log_queue_size;
            LeaveCriticalSection(&log_queue_lock);

            write_to_log(2, "Periodic Stats: ActiveFlows=%zu, TrackedHosts=%zu, SendQueue=%d",
                         flow_count_now, host_count_now, queue_size_now);

            last_stats_update = now;
        }

        Sleep(10000); // Check every 10 seconds
    }

    write_to_log(2, "Statistics and cleanup thread exiting");
    return 0;
}

/* Cleanup resources and exit */
void cleanup_and_exit(int exit_code)
{
    write_to_log(2, "Network Monitor Service shutting down (exit code: %d)...", exit_code);

    running = 0; // Signal all threads to stop

    // Disable promiscuous mode (best effort)
    if (capture_socket != INVALID_SOCKET)
    {
        u_long optval_promisc = RCVALL_OFF; // Turn off SIO_RCVALL
        DWORD bytesReturned = 0;
        WSAIoctl(capture_socket, SIO_RCVALL, &optval_promisc, sizeof(optval_promisc),
                 NULL, 0, &bytesReturned, NULL, NULL);
        closesocket(capture_socket);
        capture_socket = INVALID_SOCKET;
        write_to_log(2, "Capture socket closed.");
    }

    // Cleanup Winsock
    WSACleanup();
    write_to_log(2, "Winsock cleaned up.");

    // Close log files
    if (output_fp)
    {
        fclose(output_fp);
        output_fp = NULL;
        write_to_log(2, "Output file closed.");
    }

    if (log_fp)
    {
        // Last chance to write before closing log_fp itself
        write_to_log(2, "Closing main log file.");
        fclose(log_fp);
        log_fp = NULL;
    }

    // Free hash tables (use appropriate free functions)
    write_to_log(2, "Freeing hash tables...");
    if (flow_table)
    {
        hash_table_free(flow_table, free_flow_data); // Use specific free function
        flow_table = NULL;
        write_to_log(2, "Flow table freed.");
    }

    if (host_table)
    {
        hash_table_free(host_table, free_host_data); // Use specific free function
        host_table = NULL;
        write_to_log(2, "Host table freed.");
    }

    // Clean up remaining log queue
    write_to_log(2, "Cleaning up send queue...");
    EnterCriticalSection(&log_queue_lock);
    LogQueueNode *current = log_queue_head;
    int freed_count = 0;
    while (current)
    {
        LogQueueNode *next = current->next;
        if (current->json_data)
            free(current->json_data);
        free(current);
        current = next;
        freed_count++;
    }
    log_queue_head = log_queue_tail = NULL;
    log_queue_size = 0;
    LeaveCriticalSection(&log_queue_lock);
    write_to_log(2, "Freed %d remaining queue nodes.", freed_count);

    DeleteCriticalSection(&flow_table_lock);
    DeleteCriticalSection(&host_table_lock);
    write_to_log(2, "Critical sections deleted.");

    write_to_log(2, "Cleanup complete.");

    // Note: Handles (stop_event, threads) are closed in ServiceMain after waiting.
}

/* Service functions */
/* Service Control Functions */
void WINAPI ServiceMain(DWORD argc, LPTSTR *argv)
{
    // 1. Register the handler function.
    service_status_handle = RegisterServiceCtrlHandler(SERVICE_NAME, ServiceCtrlHandler);
    if (!service_status_handle)
    {
        // Cannot report status, log to event log maybe? Critical failure.
        // OutputDebugString("Failed to register service control handler.");
        return; // Cannot proceed
    }

    // 2. Initialize service status.
    service_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    service_status.dwServiceSpecificExitCode = 0;
    // Report START_PENDING immediately.
    set_service_status(SERVICE_START_PENDING, NO_ERROR, 3000); // 3 seconds hint

    // 3. Create stop event.
    stop_event = CreateEvent(NULL, TRUE, FALSE, NULL); // Manual reset, initially non-signaled
    if (!stop_event)
    {
        set_service_status(SERVICE_STOPPED, GetLastError(), 0);
        return;
    }

    // --- Service Initialization ---
    set_service_status(SERVICE_START_PENDING, NO_ERROR, 1000);

    // Initialize critical sections first
    InitializeCriticalSection(&log_queue_lock);
    InitializeCriticalSection(&flow_table_lock); // Needed by init_capture
    InitializeCriticalSection(&host_table_lock); // Needed by init_capture

    // Load configuration (needs to happen before logging/file ops)
    init_default_config(); // Set defaults first
    char config_path[MAX_PATH];
    GetModuleFileName(NULL, config_path, MAX_PATH);
    char *last_slash_conf = strrchr(config_path, '\\');
    if (last_slash_conf)
    {
        strcpy(last_slash_conf + 1, "nexlog.conf");
        parse_config_file(config_path); // Load from file if exists
    }
    else
    {
        parse_config_file("nexlog.conf"); // Try loading from current dir
    }

    // Open main log file (now that config is loaded)
    // Ensure log directory exists
    char log_dir[MAX_PATH];
    strncpy(log_dir, config.log_file, sizeof(log_dir) - 1);
    log_dir[sizeof(log_dir) - 1] = '\0';
    char *last_slash_log = strrchr(log_dir, '\\');
    if (last_slash_log)
    {
        *last_slash_log = '\0';
        CreateDirectory(log_dir, NULL); // Attempt to create log directory
    }
    // Open the log file
    log_fp = fopen(config.log_file, "a");
    if (!log_fp)
    {
        // Fallback if still fails (e.g., permissions)
        char fallback_log[MAX_PATH];
        sprintf(fallback_log, "%s\\NexLog\\nexlog_fallback.log", getenv("TEMP"));
        log_fp = fopen(fallback_log, "a");
        if (log_fp)
        {
            write_to_log(1, "Failed to open configured log file %s. Using fallback: %s", config.log_file, fallback_log);
            strcpy(config.log_file, fallback_log); // Update config to use fallback
        }
        else
        {
            // Absolute fallback - logging disabled
            // OutputDebugString("CRITICAL: Failed to open any log file.");
            // Cannot log the failure itself easily here.
        }
    }

    write_to_log(2, "--- %s Service Starting ---", SERVICE_DISPLAY_NAME);
    dump_config(); // Log the loaded config

    // Ensure output directory exists (for output_fp and rotated logs)
    char output_dir[MAX_PATH];
    strncpy(output_dir, config.output_file, sizeof(output_dir) - 1);
    output_dir[sizeof(output_dir) - 1] = '\0';
    char *last_slash_out = strrchr(output_dir, '\\');
    if (last_slash_out)
    {
        *last_slash_out = '\0';
        CreateDirectory(output_dir, NULL);
    }

    set_service_status(SERVICE_START_PENDING, NO_ERROR, 2000);

    // Perform initial cleanup of old rotated logs
    if (config.log_retention_hours > 0)
    {
        cleanup_old_logs();
    }

    // Initialize network capture subsystem
    if (!init_capture()) // This opens output_fp
    {
        write_to_log(1, "CRITICAL: Failed to initialize network capture.");
        set_service_status(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR, 0);
        // Perform basic cleanup before exiting
        if (stop_event)
            CloseHandle(stop_event);
        DeleteCriticalSection(&log_queue_lock);
        DeleteCriticalSection(&flow_table_lock);
        DeleteCriticalSection(&host_table_lock);
        if (log_fp)
            fclose(log_fp);
        return;
    }

    set_service_status(SERVICE_START_PENDING, NO_ERROR, 1000);

    // --- Start Worker Threads ---
    running = 1; // Set running flag *before* starting threads

    // 1. Capture Thread
    worker_thread = (HANDLE)_beginthreadex(NULL, 0, capture_thread, NULL, 0, NULL);
    if (!worker_thread)
    {
        write_to_log(1, "CRITICAL: Error creating capture thread: %d", GetLastError());
        cleanup_and_exit(1); // Perform full cleanup
        set_service_status(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR, 0);
        CloseHandle(stop_event);
        return;
    }
    else
    {
        write_to_log(2, "Capture thread started.");
    }

    // 2. Sender/Ping Threads (if enabled)
    if (config.send_enabled)
    {
        sender_thread = (HANDLE)_beginthreadex(NULL, 0, sender_thread_func, NULL, 0, NULL);
        if (!sender_thread)
        {
            write_to_log(1, "Error creating sender thread: %d. Data sending disabled.", GetLastError());
        }
        else
        {
            write_to_log(2, "Data sender thread started (interval: %d seconds)", config.send_interval);
        }

        ping_thread = (HANDLE)_beginthreadex(NULL, 0, ping_thread_func, NULL, 0, NULL);
        if (!ping_thread)
        {
            write_to_log(1, "Error creating ping thread: %d. Server pinging disabled.", GetLastError());
        }
        else
        {
            write_to_log(2, "Server ping thread started (interval: %d seconds)", config.ping_interval);
        }
    }
    else
    {
        write_to_log(2, "Data sending and pinging disabled by configuration.");
    }

    // 3. Log Cleanup Thread (if retention enabled)
    if (config.log_retention_hours > 0)
    {
        cleanup_thread = (HANDLE)_beginthreadex(NULL, 0, cleanup_thread_func, NULL, 0, NULL);
        if (!cleanup_thread)
        {
            write_to_log(1, "Error creating log cleanup thread: %d. Automatic log rotation disabled.", GetLastError());
        }
        else
        {
            write_to_log(2, "Log cleanup thread started (retention: %d hours)", config.log_retention_hours);
        }
    }
    else
    {
        write_to_log(2, "Log retention disabled by configuration.");
    }

    // 4. Statistics / Table Maintenance Thread
    stats_thread = (HANDLE)_beginthreadex(NULL, 0, stats_thread_func, NULL, 0, NULL);
    if (!stats_thread)
    {
        write_to_log(1, "Error creating statistics/cleanup thread: %d.", GetLastError());
    }
    else
    {
        write_to_log(2, "Statistics/cleanup thread started.");
    }

    // --- Service Running ---
    set_service_status(SERVICE_RUNNING, NO_ERROR, 0);
    write_to_log(2, "Service successfully started and running.");

    // --- Wait for Stop Signal ---
    WaitForSingleObject(stop_event, INFINITE);
    write_to_log(2, "Stop signal received.");

    // --- Service Stopping ---
    set_service_status(SERVICE_STOP_PENDING, NO_ERROR, 5000); // Give 5s hint for shutdown
    running = 0;                                              // Signal threads to stop (redundant, but good practice)

    // --- Wait for Threads to Exit ---
    DWORD wait_timeout = 5000; // 5 seconds per thread wait
    write_to_log(2, "Waiting for worker threads to exit...");

    if (worker_thread)
    {
        write_to_log(3, "Waiting for capture thread...");
        if (WaitForSingleObject(worker_thread, wait_timeout) == WAIT_TIMEOUT)
        {
            write_to_log(1, "Capture thread did not exit gracefully, terminating.");
            TerminateThread(worker_thread, 1); // Force terminate if stuck
        }
        CloseHandle(worker_thread);
        write_to_log(3, "Capture thread handle closed.");
    }
    if (sender_thread)
    {
        write_to_log(3, "Waiting for sender thread...");
        if (WaitForSingleObject(sender_thread, wait_timeout) == WAIT_TIMEOUT)
        {
            write_to_log(1, "Sender thread did not exit gracefully, terminating.");
            TerminateThread(sender_thread, 1);
        }
        CloseHandle(sender_thread);
        write_to_log(3, "Sender thread handle closed.");
    }
    if (ping_thread)
    {
        write_to_log(3, "Waiting for ping thread...");
        if (WaitForSingleObject(ping_thread, wait_timeout) == WAIT_TIMEOUT)
        {
            write_to_log(1, "Ping thread did not exit gracefully, terminating.");
            TerminateThread(ping_thread, 1);
        }
        CloseHandle(ping_thread);
        write_to_log(3, "Ping thread handle closed.");
    }
    if (cleanup_thread)
    {
        write_to_log(3, "Waiting for cleanup thread...");
        if (WaitForSingleObject(cleanup_thread, wait_timeout) == WAIT_TIMEOUT)
        {
            write_to_log(1, "Cleanup thread did not exit gracefully, terminating.");
            TerminateThread(cleanup_thread, 1);
        }
        CloseHandle(cleanup_thread);
        write_to_log(3, "Cleanup thread handle closed.");
    }
    if (stats_thread)
    {
        write_to_log(3, "Waiting for stats thread...");
        if (WaitForSingleObject(stats_thread, wait_timeout) == WAIT_TIMEOUT)
        {
            write_to_log(1, "Stats thread did not exit gracefully, terminating.");
            TerminateThread(stats_thread, 1);
        }
        CloseHandle(stats_thread);
        write_to_log(3, "Stats thread handle closed.");
    }
    write_to_log(2, "All worker threads stopped.");

    set_service_status(SERVICE_STOP_PENDING, NO_ERROR, 1000); // Update hint

    // --- Perform Final Cleanup ---
    cleanup_and_exit(0); // Calls WSACleanup, frees tables, closes files etc.

    // Close the stop event handle
    CloseHandle(stop_event);
    stop_event = NULL;

    // --- Report Service Stopped ---
    set_service_status(SERVICE_STOPPED, NO_ERROR, 0);
}

void WINAPI ServiceCtrlHandler(DWORD control)
{
    switch (control)
    {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN: // Treat shutdown like stop
        write_to_log(2, "Received Service Control Stop/Shutdown signal.");
        // Update status immediately
        if (service_status.dwCurrentState == SERVICE_RUNNING)
        {
            set_service_status(SERVICE_STOP_PENDING, NO_ERROR, 5000); // 5s hint initially
        }
        // Signal the main service loop to stop
        if (stop_event)
        {
            SetEvent(stop_event);
        }
        running = 0; // Ensure running flag is clear
        break;

    case SERVICE_CONTROL_INTERROGATE:
        // SCM is asking for status, just report current status.
        // set_service_status already does this.
        write_to_log(3, "Received Service Control Interrogate signal.");
        break;

        // Add handlers for other controls if needed (e.g., PAUSE, CONTINUE)
        // case SERVICE_CONTROL_PAUSE:
        //    set_service_status(SERVICE_PAUSE_PENDING, NO_ERROR, 1000);
        //    // Suspend threads or set pause flag
        //    set_service_status(SERVICE_PAUSED, NO_ERROR, 0);
        //    break;
        // case SERVICE_CONTROL_CONTINUE:
        //    set_service_status(SERVICE_CONTINUE_PENDING, NO_ERROR, 1000);
        //    // Resume threads or clear pause flag
        //    set_service_status(SERVICE_RUNNING, NO_ERROR, 0);
        //    break;

    default:
        // Ignore unknown control codes, but log them
        write_to_log(2, "Received unknown Service Control signal: %lu", control);
        break;
    }

    // Report the current status back to the SCM.
    // This is important after handling any control code.
    set_service_status(service_status.dwCurrentState, NO_ERROR, 0);
}

void set_service_status(DWORD current_state, DWORD win32_exit_code, DWORD wait_hint)
{
    static DWORD check_point = 1;

    // Ensure the handle is valid before using it
    if (!service_status_handle)
    {
        // Cannot report status if handle is invalid (e.g., RegisterServiceCtrlHandler failed)
        return;
    }

    // Fill in the SERVICE_STATUS structure.
    service_status.dwCurrentState = current_state;
    service_status.dwWin32ExitCode = win32_exit_code;
    service_status.dwWaitHint = wait_hint;

    // Accept stop controls ONLY when running or paused.
    if (current_state == SERVICE_RUNNING || current_state == SERVICE_PAUSED)
        service_status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    else
        service_status.dwControlsAccepted = 0; // Not stoppable during start/stop pending

    // Increment the checkpoint for pending states.
    if (current_state == SERVICE_START_PENDING ||
        current_state == SERVICE_STOP_PENDING ||
        current_state == SERVICE_PAUSE_PENDING ||
        current_state == SERVICE_CONTINUE_PENDING)
        service_status.dwCheckPoint = check_point++;
    else
        service_status.dwCheckPoint = 0; // Reset checkpoint when not pending

    // Report the status of the service to the SCM.
    if (!SetServiceStatus(service_status_handle, &service_status))
    {
        write_to_log(1, "SetServiceStatus failed: %d", GetLastError());
    }
}

int install_service(void)
{
    SC_HANDLE sc_manager = NULL;
    SC_HANDLE service = NULL;
    char path[MAX_PATH];
    char service_path_cmd[MAX_PATH + 10]; // Space for executable path and quotes

    // Get the executable's full path
    if (!GetModuleFileName(NULL, path, MAX_PATH))
    {
        printf("ERROR: Could not get module file name: %lu\n", GetLastError());
        return 1;
    }

    // Construct the command line for the service (path enclosed in quotes)
    sprintf(service_path_cmd, "\"%s\"", path);

    // Create necessary directories (e.g., for logs, config)
    char program_data[MAX_PATH];
    if (GetEnvironmentVariable("ProgramData", program_data, MAX_PATH) == 0)
    {
        printf("ERROR: Could not get ProgramData environment variable: %lu\n", GetLastError());
        // Might proceed but logging/config defaults might fail later
    }
    else
    {
        char dir_path[MAX_PATH];
        sprintf(dir_path, "%s\\NexLog", program_data);
        if (!CreateDirectory(dir_path, NULL))
        {
            if (GetLastError() != ERROR_ALREADY_EXISTS)
            {
                printf("WARNING: Could not create directory '%s': %lu\n", dir_path, GetLastError());
            }
        }
        else
        {
            printf("INFO: Ensured directory exists: %s\n", dir_path);
        }
    }

    // Open the Service Control Manager
    sc_manager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!sc_manager)
    {
        printf("ERROR: Could not open Service Control Manager: %lu\n", GetLastError());
        printf("       Make sure you are running this command as Administrator.\n");
        return 1;
    }

    printf("INFO: Creating service '%s'...\n", SERVICE_NAME);

    // Create the service
    service = CreateService(
        sc_manager,                // SCM database
        SERVICE_NAME,              // Name of service
        SERVICE_DISPLAY_NAME,      // Service name to display
        SERVICE_ALL_ACCESS,        // Desired access
        SERVICE_WIN32_OWN_PROCESS, // Service type
        SERVICE_AUTO_START,        // Start type (AUTO_START, DEMAND_START)
        SERVICE_ERROR_NORMAL,      // Error control type
        service_path_cmd,          // Path to service's binary
        NULL,                      // No load ordering group
        NULL,                      // No tag identifier
        NULL,                      // No dependencies (e.g., "Tcpip\0\0")
        NULL,                      // LocalSystem account (default)
        NULL);                     // No password

    if (!service)
    {
        DWORD error = GetLastError();
        printf("ERROR: Could not create service '%s': %lu\n", SERVICE_NAME, error);
        if (error == ERROR_SERVICE_EXISTS)
        {
            printf("       The service might already be installed.\n");
        }
        CloseServiceHandle(sc_manager);
        return 1;
    }
    else
    {
        printf("INFO: Service '%s' created successfully.\n", SERVICE_NAME);

        // Set the service description (optional but recommended)
        SERVICE_DESCRIPTION sd;
        sd.lpDescription = TEXT(SERVICE_DESC); // TEXT() macro handles Unicode/ANSI
        if (!ChangeServiceConfig2(service, SERVICE_CONFIG_DESCRIPTION, &sd))
        {
            printf("WARNING: Could not set service description: %lu\n", GetLastError());
        }
        else
        {
            printf("INFO: Service description set.\n");
        }

        // Create default configuration file if it doesn't exist
        char config_path[MAX_PATH];
        strncpy(config_path, path, sizeof(config_path) - 1);
        config_path[sizeof(config_path) - 1] = '\0';

        char *last_slash = strrchr(config_path, '\\');
        if (last_slash)
        {
            strcpy(last_slash + 1, "nexlog.conf");
        }
        else
        {
            strcpy(config_path, "nexlog.conf"); // Config in same dir as exe
        }

        FILE *config_file_test = fopen(config_path, "r");
        if (config_file_test)
        {
            printf("INFO: Configuration file already exists: %s\n", config_path);
            fclose(config_file_test);
        }
        else
        {
            printf("INFO: Creating default configuration file: %s\n", config_path);
            FILE *config_file = fopen(config_path, "w");
            if (config_file)
            {
                // Get default paths using ProgramData
                char default_output[MAX_PATH];
                char default_log[MAX_PATH];
                if (program_data[0] != '\0')
                {
                    sprintf(default_output, "%s\\NexLog\\network_log3.json", program_data);
                    sprintf(default_log, "%s\\NexLog\\nexlog.log", program_data);
                }
                else
                {
                    // Fallback if ProgramData failed
                    strcpy(default_output, "network_log3.json");
                    strcpy(default_log, "nexlog.log");
                }

                fprintf(config_file, "# %s Configuration File\n\n", SERVICE_DISPLAY_NAME);
                fprintf(config_file, "# --- File Paths ---\n");
                fprintf(config_file, "output_file=%s\n", default_output);
                fprintf(config_file, "log_file=%s\n", default_log);
                fprintf(config_file, "\n# --- Logging & Rotation ---\n");
                fprintf(config_file, "log_level=2 # 1=ERROR, 2=INFO, 3=DEBUG\n");
                fprintf(config_file, "file_rotation_size=10 # Max size in MB before rotation\n");
                fprintf(config_file, "log_retention_hours=%d # Hours to keep rotated logs (0=disabled)\n", LOG_RETENTION_HOURS);
                fprintf(config_file, "\n# --- Capture Settings ---\n");
                fprintf(config_file, "capture_interval=60 # Default interval for logging flow summary (seconds)\n");
                fprintf(config_file, "bind_interface=0.0.0.0 # IP of interface to bind to (0.0.0.0 for auto-detect)\n");
                fprintf(config_file, "\n# --- Data Transmission ---\n");
                fprintf(config_file, "send_enabled=1 # 1=Enable, 0=Disable sending data to server\n");
                fprintf(config_file, "server_url=http://%s:%d/api/network_data\n", SERVER_IP, SERVER_PORT);
                fprintf(config_file, "send_interval=%d # Interval to send data batch (seconds)\n", SEND_INTERVAL);
                fprintf(config_file, "ping_interval=%d # Interval to ping server (seconds)\n", PING_INTERVAL);
                fprintf(config_file, "\n# --- Advanced Features ---\n");
                fprintf(config_file, "enable_advanced_stats=1 # 1=Enable KDD-style stats, 0=Disable\n");
                fprintf(config_file, "enable_anomaly_detection=1 # 1=Enable basic anomaly checks, 0=Disable\n");
                fprintf(config_file, "connection_window=%d # Time window for connection stats (seconds)\n", CONNECTION_WINDOW);
                fprintf(config_file, "max_host_memory=%d # Max hosts to track in memory\n", MAX_HOSTS_TRACKED);
                fprintf(config_file, "anomaly_threshold=0.90 # Threshold (0.0-1.0) for error/diff_srv rate anomalies\n");

                fclose(config_file);
                printf("INFO: Default configuration file created successfully.\n");
            }
            else
            {
                printf("ERROR: Could not create configuration file '%s'. Check permissions.\n", config_path);
            }
        }

        CloseServiceHandle(service);
    }

    CloseServiceHandle(sc_manager);
    return 0; // Success
}

/* Remove the service */
int remove_service(void)
{
    SC_HANDLE sc_manager = NULL;
    SC_HANDLE service = NULL;
    SERVICE_STATUS status = {0};

    sc_manager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!sc_manager)
    {
        printf("ERROR: Could not open Service Control Manager: %lu\n", GetLastError());
        printf("       Make sure you are running this command as Administrator.\n");
        return 1;
    }

    service = OpenService(sc_manager, SERVICE_NAME, SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
    if (!service)
    {
        DWORD error = GetLastError();
        if (error == ERROR_SERVICE_DOES_NOT_EXIST)
        {
            printf("INFO: Service '%s' is not installed.\n", SERVICE_NAME);
            CloseServiceHandle(sc_manager);
            return 0; // Not an error if it doesn't exist
        }
        else
        {
            printf("ERROR: Could not open service '%s': %lu\n", SERVICE_NAME, error);
        }
        CloseServiceHandle(sc_manager);
        return 1;
    }

    printf("INFO: Stopping service '%s' (if running)...\n", SERVICE_NAME);

    // Query status first
    if (QueryServiceStatus(service, &status))
    {
        if (status.dwCurrentState == SERVICE_RUNNING || status.dwCurrentState == SERVICE_PAUSED)
        {
            // Try to stop the service
            if (!ControlService(service, SERVICE_CONTROL_STOP, &status))
            {
                printf("WARNING: Could not send stop control to service: %lu. Trying to delete anyway.\n", GetLastError());
            }
            else
            {
                printf("INFO: Stop control sent. Waiting briefly...\n");
                Sleep(1000); // Give it a moment to react

                // Wait for the service to stop
                for (int i = 0; i < 10; ++i)
                { // Wait up to 10 seconds
                    if (!QueryServiceStatus(service, &status))
                        break; // Error querying
                    if (status.dwCurrentState == SERVICE_STOPPED)
                    {
                        printf("INFO: Service stopped.\n");
                        break;
                    }
                    Sleep(1000);
                }
                if (status.dwCurrentState != SERVICE_STOPPED)
                {
                    printf("WARNING: Service did not stop within timeout. Trying to delete anyway.\n");
                }
            }
        }
        else
        {
            printf("INFO: Service was not running.\n");
        }
    }
    else
    {
        printf("WARNING: Could not query service status before stopping: %lu\n", GetLastError());
    }

    printf("INFO: Deleting service '%s'...\n", SERVICE_NAME);
    if (!DeleteService(service))
    {
        printf("ERROR: Could not delete service '%s': %lu\n", SERVICE_NAME, GetLastError());
        // Common error: ERROR_SERVICE_MARKED_FOR_DELETE (1072)
        if (GetLastError() == ERROR_SERVICE_MARKED_FOR_DELETE)
        {
            printf("       Service is marked for deletion. It will be removed after restart or when handles are closed.\n");
        }
        CloseServiceHandle(service);
        CloseServiceHandle(sc_manager);
        return 1;
    }

    printf("INFO: Service '%s' removed successfully.\n", SERVICE_NAME);
    CloseServiceHandle(service);
    CloseServiceHandle(sc_manager);
    return 0;
}

/* Start the service */
int start_service(void)
{
    SC_HANDLE sc_manager = NULL;
    SC_HANDLE service = NULL;
    SERVICE_STATUS_PROCESS status; // Use this for more detailed status
    DWORD bytesNeeded;

    sc_manager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (!sc_manager)
    {
        printf("ERROR: Could not open Service Control Manager: %lu\n", GetLastError());
        printf("       Make sure you are running this command as Administrator.\n");
        return 1;
    }

    service = OpenService(sc_manager, SERVICE_NAME, SERVICE_START | SERVICE_QUERY_STATUS);
    if (!service)
    {
        DWORD error = GetLastError();
        if (error == ERROR_SERVICE_DOES_NOT_EXIST)
        {
            printf("ERROR: Service '%s' is not installed. Use -install first.\n", SERVICE_NAME);
        }
        else
        {
            printf("ERROR: Could not open service '%s': %lu\n", SERVICE_NAME, error);
        }
        CloseServiceHandle(sc_manager);
        return 1;
    }

    // Check current status before attempting start
    if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (LPBYTE)&status, sizeof(status), &bytesNeeded))
    {
        printf("WARNING: Could not query service status before starting: %lu\n", GetLastError());
    }
    else
    {
        if (status.dwCurrentState != SERVICE_STOPPED && status.dwCurrentState != SERVICE_STOP_PENDING)
        {
            printf("INFO: Service '%s' is already running or in a non-stopped state (State: %lu).\n", SERVICE_NAME, status.dwCurrentState);
            CloseServiceHandle(service);
            CloseServiceHandle(sc_manager);
            return 0; // Not an error if already running
        }
    }

    printf("INFO: Attempting to start service '%s'...\n", SERVICE_NAME);
    if (!StartService(service, 0, NULL)) // No arguments passed to ServiceMain
    {
        DWORD error = GetLastError();
        if (error == ERROR_SERVICE_ALREADY_RUNNING)
        {
            printf("INFO: Service is already running.\n");
            // This case should have been caught by QueryServiceStatusEx, but handle defensively
        }
        else if (error == ERROR_SERVICE_DISABLED)
        {
            printf("ERROR: Service '%s' is disabled. Enable it via services.msc or 'sc config %s start= auto' (or demand).\n", SERVICE_NAME, SERVICE_NAME);
        }
        else if (error == ERROR_SERVICE_LOGON_FAILED)
        {
            printf("ERROR: Service '%s' failed to log on. Check service account configuration.\n", SERVICE_NAME);
        }
        else
        {
            printf("ERROR: Could not start service '%s': %lu\n", SERVICE_NAME, error);
        }
        CloseServiceHandle(service);
        CloseServiceHandle(sc_manager);
        return 1;
    }
    else
    {
        // Wait for service to enter running state
        printf("INFO: Start command sent. Waiting for service to enter RUNNING state...\n");
        Sleep(1000); // Wait a second before first check
        for (int i = 0; i < 15; ++i)
        { // Wait up to 15 seconds
            if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (LPBYTE)&status, sizeof(status), &bytesNeeded))
            {
                printf("WARNING: Could not query service status after starting: %lu\n", GetLastError());
                break; // Stop waiting if status query fails
            }
            if (status.dwCurrentState == SERVICE_RUNNING)
            {
                printf("INFO: Service '%s' started successfully and is RUNNING.\n", SERVICE_NAME);
                goto cleanup; // Exit loop on success
            }
            if (status.dwCurrentState == SERVICE_STOPPED || status.dwCurrentState == SERVICE_STOP_PENDING)
            {
                printf("ERROR: Service '%s' entered STOPPED state shortly after start command. Check service logs/event viewer.\n", SERVICE_NAME);
                goto cleanup_fail; // Exit loop on failure
            }
            // Still START_PENDING, wait longer
            Sleep(1000);
        }
        // If loop finishes without reaching RUNNING state
        printf("WARNING: Service '%s' did not reach RUNNING state within timeout. Current state: %lu. Check logs.\n", SERVICE_NAME, status.dwCurrentState);
    }

cleanup:
    CloseServiceHandle(service);
    CloseServiceHandle(sc_manager);
    return 0; // Success or already running

cleanup_fail:
    CloseServiceHandle(service);
    CloseServiceHandle(sc_manager);
    return 1; // Failure
}

/* Stop the service */
int stop_service(void)
{
    SC_HANDLE sc_manager = NULL;
    SC_HANDLE service = NULL;
    SERVICE_STATUS status = {0}; // Can use basic status here

    sc_manager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (!sc_manager)
    {
        printf("ERROR: Could not open Service Control Manager: %lu\n", GetLastError());
        printf("       Make sure you are running this command as Administrator.\n");
        return 1;
    }

    service = OpenService(sc_manager, SERVICE_NAME, SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!service)
    {
        DWORD error = GetLastError();
        if (error == ERROR_SERVICE_DOES_NOT_EXIST)
        {
            printf("INFO: Service '%s' is not installed.\n", SERVICE_NAME);
        }
        else
        {
            printf("ERROR: Could not open service '%s': %lu\n", SERVICE_NAME, error);
        }
        CloseServiceHandle(sc_manager);
        return (error == ERROR_SERVICE_DOES_NOT_EXIST) ? 0 : 1;
    }

    // Check if already stopped
    if (!QueryServiceStatus(service, &status))
    {
        printf("WARNING: Could not query service status before stopping: %lu\n", GetLastError());
    }
    else
    {
        if (status.dwCurrentState == SERVICE_STOPPED)
        {
            printf("INFO: Service '%s' is already stopped.\n", SERVICE_NAME);
            CloseServiceHandle(service);
            CloseServiceHandle(sc_manager);
            return 0; // Success
        }
        if (status.dwCurrentState == SERVICE_STOP_PENDING)
        {
            printf("INFO: Service '%s' is already stopping.\n", SERVICE_NAME);
            // Optionally wait here for it to fully stop
            CloseServiceHandle(service);
            CloseServiceHandle(sc_manager);
            return 0;
        }
    }

    printf("INFO: Attempting to stop service '%s'...\n", SERVICE_NAME);
    if (!ControlService(service, SERVICE_CONTROL_STOP, &status))
    {
        printf("ERROR: Could not send stop control to service '%s': %lu\n", SERVICE_NAME, GetLastError());
        CloseServiceHandle(service);
        CloseServiceHandle(sc_manager);
        return 1;
    }

    // Wait for service to enter stopped state
    printf("INFO: Stop command sent. Waiting for service to enter STOPPED state...\n");
    for (int i = 0; i < 15; ++i)
    { // Wait up to 15 seconds
        if (!QueryServiceStatus(service, &status))
        {
            printf("WARNING: Could not query service status after stopping: %lu\n", GetLastError());
            break; // Stop waiting if query fails
        }
        if (status.dwCurrentState == SERVICE_STOPPED)
        {
            printf("INFO: Service '%s' stopped successfully.\n", SERVICE_NAME);
            goto cleanup_stop;
        }
        // Still STOP_PENDING, wait longer
        Sleep(1000);
    }
    // If loop finishes without reaching STOPPED state
    printf("WARNING: Service '%s' did not reach STOPPED state within timeout. Current state: %lu.\n", SERVICE_NAME, status.dwCurrentState);

cleanup_stop:
    CloseServiceHandle(service);
    CloseServiceHandle(sc_manager);
    return (status.dwCurrentState == SERVICE_STOPPED) ? 0 : 1; // Return success only if verified stopped
}

/* Print usage instructions */
void print_usage(void)
{
    printf("%s\n", SERVICE_DISPLAY_NAME);
    printf("Description: %s\n", SERVICE_DESC);
    printf("Service Name: %s\n\n", SERVICE_NAME);
    printf("Usage:\n");
    printf("  nexlog.exe [command]\n\n");
    printf("Commands:\n");
    printf("  -install   Install the service (requires Administrator privileges).\n");
    printf("             Creates a default config file if not found.\n");
    printf("  -remove    Remove the service (requires Administrator privileges).\n");
    printf("             Stops the service if running before removing.\n");
    printf("  -start     Start the installed service.\n");
    printf("  -stop      Stop the running service.\n");
    printf("  -test      Perform basic tests (WinSock init, socket creation, server ping/send).\n");
    printf("             Reads config for server URL. Does not run capture.\n");
    printf("  -capture   Run packet capture in console mode (for testing/debugging).\n");
    printf("             Reads config file. Press Ctrl+C to stop.\n");
    printf("  -help      Show this help message.\n\n");
    printf("Configuration:\n");
    printf("  The service reads settings from 'nexlog.conf' located in the\n");
    printf("  same directory as the executable.\n");
    printf("  If run via SCM, ensure the config file is accessible by the service account.\n");
    printf("  See the default generated config file for available options.\n");
}

/* Main function - Entry point for both command line and service */
int main(int argc, char *argv[])
{
    // --- Handle Command Line Arguments ---
    if (argc > 1)
    {
        if (_stricmp(argv[1], "-install") == 0)
            return install_service();
        else if (_stricmp(argv[1], "-remove") == 0)
            return remove_service();
        else if (_stricmp(argv[1], "-start") == 0)
            return start_service();
        else if (_stricmp(argv[1], "-stop") == 0)
            return stop_service();
        else if (_stricmp(argv[1], "-test") == 0)
        {
            printf("--- Running Basic Tests ---\n");
            // Initialize config first to get server URL etc.
            init_default_config();
            char config_path[MAX_PATH];
            GetModuleFileName(NULL, config_path, MAX_PATH);
            char *last_slash = strrchr(config_path, '\\');
            if (last_slash)
                strcpy(last_slash + 1, "nexlog.conf");
            else
                strcpy(config_path, "nexlog.conf");
            parse_config_file(config_path);
            dump_config(); // Show config being used for test

            printf("\nTesting WinSock Initialization...\n");
            if (init_winsock())
            {
                printf("  [OK] Winsock initialized successfully.\n");

                printf("\nTesting Raw Socket Creation (requires Admin)...\n");
                if (create_raw_socket()) // Tries to bind and set promiscuous
                {
                    printf("  [OK] Raw socket created and configured successfully.\n");
                    // Clean up socket immediately after test
                    u_long optval_promisc = RCVALL_OFF;
                    DWORD bytesReturned = 0;
                    WSAIoctl(capture_socket, SIO_RCVALL, &optval_promisc, sizeof(optval_promisc), NULL, 0, &bytesReturned, NULL, NULL);
                    closesocket(capture_socket);
                    capture_socket = INVALID_SOCKET;
                    printf("  [INFO] Socket closed after test.\n");
                }
                else
                {
                    printf("  [FAIL] Failed to create/configure raw socket. Check logs/permissions.\n");
                }

                printf("\nTesting Server Ping (%s)...\n", config.server_url);
                if (ping_server())
                {
                    printf("  [OK] Successfully pinged server.\n");
                }
                else
                {
                    printf("  [FAIL] Failed to ping server. Check URL/network/server status.\n");
                }

                printf("\nTesting Server Send (sending dummy data to %s)...\n", config.server_url);
                // Add a dummy entry to the queue for sending
                InitializeCriticalSection(&log_queue_lock); // Init lock for test
                add_to_send_queue("{\"test_event\":\"dummy data from -test command\"}");
                if (send_data_to_server())
                { // Tries to send the dummy data
                    printf("  [OK] Successfully sent test data to server.\n");
                }
                else
                {
                    printf("  [FAIL] Failed to send test data to server. Check URL/network/server status.\n");
                }
                DeleteCriticalSection(&log_queue_lock); // Clean up lock

                WSACleanup();
                printf("\nWinsock cleaned up.\n");
            }
            else
            {
                printf("  [FAIL] Failed to initialize Winsock.\n");
            }
            printf("\n--- Basic Tests Complete ---\n");
            return 0;
        }
        else if (_stricmp(argv[1], "-capture") == 0)
        {
            printf("--- Starting Enhanced Packet Capture (Console Mode) ---\n");
            printf("    Reading config from nexlog.conf...\n");
            printf("    Press Ctrl+C to stop.\n\n");

            // Initialize config
            init_default_config();
            char config_path[MAX_PATH];
            GetModuleFileName(NULL, config_path, MAX_PATH);
            char *last_slash = strrchr(config_path, '\\');
            if (last_slash)
                strcpy(last_slash + 1, "nexlog.conf");
            else
                strcpy(config_path, "nexlog.conf");
            parse_config_file(config_path);

            // Open log file (use stdout if file fails)
            log_fp = fopen(config.log_file, "a");
            if (!log_fp)
            {
                printf("WARNING: Could not open log file %s. Logging to console instead.\n", config.log_file);
                log_fp = stdout; // Log to console if file fails
            }
            dump_config(); // Log config being used

            // Initialize locks and tables needed for capture
            InitializeCriticalSection(&log_queue_lock);
            InitializeCriticalSection(&flow_table_lock);
            InitializeCriticalSection(&host_table_lock);

            // Initialize capture system (creates tables, socket, opens output file)
            if (!init_capture())
            {
                printf("ERROR: Failed to initialize capture system. Exiting.\n");
                if (log_fp != stdout)
                    fclose(log_fp);
                DeleteCriticalSection(&log_queue_lock);
                DeleteCriticalSection(&flow_table_lock);
                DeleteCriticalSection(&host_table_lock);
                return 1;
            }

            // Run capture loop directly in this thread
            running = 1;
            printf("\n--- Capture Started ---\n");
            capture_thread(NULL); // Run the capture logic

            // --- Cleanup after Ctrl+C (capture_thread exits when running=0) ---
            printf("\n--- Capture Stopped ---\n");
            printf("Cleaning up resources...\n");

            // Note: capture_thread frees its buffer, but we need to close socket etc.
            if (capture_socket != INVALID_SOCKET)
            {
                u_long optval_promisc = RCVALL_OFF;
                DWORD bytesReturned = 0;
                WSAIoctl(capture_socket, SIO_RCVALL, &optval_promisc, sizeof(optval_promisc), NULL, 0, &bytesReturned, NULL, NULL);
                closesocket(capture_socket);
                capture_socket = INVALID_SOCKET;
            }
            WSACleanup();
            if (output_fp)
                fclose(output_fp);
            if (log_fp != stdout)
                fclose(log_fp); // Close log file unless it's stdout

            // Free tables
            if (flow_table)
                hash_table_free(flow_table, free_flow_data);
            if (host_table)
                hash_table_free(host_table, free_host_data);

            // Free queue
            EnterCriticalSection(&log_queue_lock);
            LogQueueNode *curr = log_queue_head;
            while (curr)
            {
                LogQueueNode *next = curr->next;
                if (curr->json_data)
                    free(curr->json_data);
                free(curr);
                curr = next;
            }
            log_queue_head = log_queue_tail = NULL;
            LeaveCriticalSection(&log_queue_lock);

            // Delete locks
            DeleteCriticalSection(&log_queue_lock);
            DeleteCriticalSection(&flow_table_lock);
            DeleteCriticalSection(&host_table_lock);

            printf("Cleanup complete.\n");
            return 0;
        }
        else if (_stricmp(argv[1], "-help") == 0 || strcmp(argv[1], "/?") == 0)
        {
            print_usage();
            return 0;
        }
        else
        {
            printf("ERROR: Unknown command line argument: %s\n", argv[1]);
            print_usage();
            return 1;
        }
    }

    // --- No Command Line Args: Run as Service ---

    // Define the service table entry
    SERVICE_TABLE_ENTRY dispatch_table[] = {
        {SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION)ServiceMain},
        {NULL, NULL} // End of table marker
    };

    if (!StartServiceCtrlDispatcher(dispatch_table))
    {
        DWORD error = GetLastError();
        // ERROR_FAILED_SERVICE_CONTROLLER_CONNECT (1063) usually means not run by SCM
        if (error == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
        {
            printf("INFO: This program can be run with command line arguments (e.g., -install, -capture)\n");
            printf("      or run as a Windows service (which requires installation first).\n");
            printf("      Use -help for command line options.\n");
            // Don't treat this specific error as a fatal return code unless debugging
            return 0;
        }
        else
        {

            printf("FATAL: StartServiceCtrlDispatcher failed with error code %lu\n", error);
            // OutputDebugString("FATAL: StartServiceCtrlDispatcher failed.\n");
            return 1; // Indicate failure
        }
    }

    return 0;
}

/* Parse TCP packet */
void parse_tcp_packet(unsigned char *buffer, int size, IP_HEADER *ip_header)
{
    if (size < sizeof(TCP_HEADER)) // Basic check for header size
    {
        write_to_log(3, "TCP packet too small for header: %d bytes", size);
        return;
    }

    TCP_HEADER *tcp_header = (TCP_HEADER *)buffer;

    // Calculate TCP header length (offset * 4 bytes)
    int tcp_header_len = tcp_header->th_off * 4;
    if (tcp_header_len < 20 || tcp_header_len > size) // Min 20 bytes, max is remaining packet size
    {
        write_to_log(3, "Invalid TCP header length: %d bytes (Packet size: %d)", tcp_header_len, size);
        return;
    }

    // Create flow key
    FLOW_KEY key;
    key.src_ip = ip_header->ip_src; // Already in network byte order
    key.dst_ip = ip_header->ip_dst; // Already in network byte order
    key.src_port = ntohs(tcp_header->th_sport);
    key.dst_port = ntohs(tcp_header->th_dport);
    key.protocol = PROTO_TCP;

    // Calculate payload size and pointer
    int payload_size = size - tcp_header_len;
    unsigned char *payload = buffer + tcp_header_len;
    if (payload_size < 0)
        payload_size = 0; // Ensure non-negative

    // Find or create flow record
    FLOW_DATA *flow = find_or_create_flow(&key);
    if (!flow)
    {
        // Failed to get/create flow (e.g., memory limit), stop processing packet for this flow
        return;
    }

    int ip_fragment_offset = ntohs(ip_header->ip_off) & 0x1FFF;
    int ip_more_fragments = ntohs(ip_header->ip_off) & 0x2000;
    if ((ip_fragment_offset > 0 || ip_more_fragments) && size < 40) // Heuristic: fragment smaller than typical header+options
        flow->wrong_fragment = 1;

    // Check for urgent flag
    if (tcp_header->th_flags & TCP_URG)
        flow->urgent = 1;

    // Update basic flow statistics (packet counts, byte counts, flags)
    update_flow_stats(flow, 1, size, tcp_header->th_flags); // Pass TCP payload size + header

    // Calculate payload entropy if payload exists
    if (payload_size > 0 && config.enable_advanced_stats) // Only if needed
    {
        flow->entropy = calculate_entropy(payload, payload_size);
    }
    else if (payload_size == 0)
    {
        flow->entropy = 0.0; // No payload, entropy is zero
    }

    // --- Update Host Tracking ---
    HOST_DATA *src_host = find_or_create_host(ip_header->ip_src);
    if (src_host)
        update_host_stats(src_host, flow, 1); // 1 indicates host is source

    HOST_DATA *dst_host = find_or_create_host(ip_header->ip_dst);
    if (dst_host)
        update_host_stats(dst_host, flow, 0); // 0 indicates host is destination

    // --- Log Flow Periodically or on Completion ---
    // Determine if flow should be logged now.
    // Conditions: First packet, periodic interval, maybe on FIN/RST flags?
    time_t now = time(NULL);
    int log_now = 0;

    if (flow->packets == 1)
    {
        log_now = 1; // Log on first packet
    }
    else if (now - flow->last_log_time >= config.capture_interval)
    {
        log_now = 1; // Log if interval passed since last log
    }
    // Optionally log on connection termination flags
    // else if ((tcp_header->th_flags & TCP_FIN) || (tcp_header->th_flags & TCP_RST)) {
    //    log_now = 1;
    // }

    if (log_now)
    {
        if (config.enable_advanced_stats)
        {
            update_flow_connection_stats(flow); // Calculate KDD stats just before logging
        }
        write_flow_log(flow);
        flow->last_log_time = now; // Record time of this log event
    }
}

/* Parse UDP packet */
void parse_udp_packet(unsigned char *buffer, int size, IP_HEADER *ip_header)
{
    if (size < sizeof(UDP_HEADER))
    {
        write_to_log(3, "UDP packet too small for header: %d bytes", size);
        return;
    }

    UDP_HEADER *udp_header = (UDP_HEADER *)buffer;

    // Validate UDP length field
    int udp_len = ntohs(udp_header->uh_len);
    if (udp_len < sizeof(UDP_HEADER) || udp_len > size)
    {
        write_to_log(3, "Invalid UDP length field: %d bytes (Packet size: %d)", udp_len, size);
        // Trust the smaller of the two lengths, if udp_len is >= header size
        if (udp_len < sizeof(UDP_HEADER))
            return;     // Cannot proceed if length less than header
        size = udp_len; // Use length from UDP header if valid and smaller than IP payload size
    }

    // Create flow key
    FLOW_KEY key;
    key.src_ip = ip_header->ip_src;
    key.dst_ip = ip_header->ip_dst;
    key.src_port = ntohs(udp_header->uh_sport);
    key.dst_port = ntohs(udp_header->uh_dport);
    key.protocol = PROTO_UDP;

    // Calculate payload size and pointer
    int udp_header_len = sizeof(UDP_HEADER);
    int payload_size = size - udp_header_len; // Use potentially adjusted 'size'
    unsigned char *payload = buffer + udp_header_len;
    if (payload_size < 0)
        payload_size = 0;

    // Find or create flow record
    FLOW_DATA *flow = find_or_create_flow(&key);
    if (!flow)
    {
        return; // Failed to get/create flow
    }

    // --- Update Flow ---
    // Update basic flow statistics (no flags for UDP)
    update_flow_stats(flow, 1, size, 0); // Pass UDP payload size + header

    // Calculate entropy and check DNS pattern if payload exists
    if (payload_size > 0 && config.enable_advanced_stats)
    {
        flow->entropy = calculate_entropy(payload, payload_size);

        // Check for DNS patterns (standard port 53)
        if ((key.dst_port == 53 || key.src_port == 53))
        {
            if (!has_dns_pattern(payload, payload_size, flow->dns_query, sizeof(flow->dns_query)))
            {
                // Clear query field if pattern not found this time (optional)
                // flow->dns_query[0] = '\0';
            }
        }
    }
    else if (payload_size == 0)
    {
        flow->entropy = 0.0;
    }

    // --- Update Host Tracking ---
    HOST_DATA *src_host = find_or_create_host(ip_header->ip_src);
    if (src_host)
        update_host_stats(src_host, flow, 1);

    HOST_DATA *dst_host = find_or_create_host(ip_header->ip_dst);
    if (dst_host)
        update_host_stats(dst_host, flow, 0);

    // --- Log Flow Periodically ---
    time_t now = time(NULL);
    if (flow->packets == 1 || (now - flow->last_log_time >= config.capture_interval))
    {
        if (config.enable_advanced_stats)
        {
            update_flow_connection_stats(flow);
        }
        write_flow_log(flow);
        flow->last_log_time = now;
    }
}

/* Parse ICMP packet */
void parse_icmp_packet(unsigned char *buffer, int size, IP_HEADER *ip_header)
{
    // ICMP header is variable, but base is 8 bytes (Type, Code, Checksum, Rest of Header)
    if (size < 4) // Need at least Type, Code, Checksum
    {
        write_to_log(3, "ICMP packet too small for base header: %d bytes", size);
        return;
    }

    ICMP_HEADER *icmp_header = (ICMP_HEADER *)buffer;

    // Create flow key - Use Type/Code as "ports" for flow identification
    // Note: For Echo Request/Reply (Type 8/0), the Identifier and Sequence Number
    // in the "Rest of Header" are often better for matching pairs, but Type/Code
    // works as a general flow key.
    FLOW_KEY key;
    key.src_ip = ip_header->ip_src;
    key.dst_ip = ip_header->ip_dst;
    key.src_port = icmp_header->type; // Use ICMP type as source "port"
    key.dst_port = icmp_header->code; // Use ICMP code as dest "port"
    key.protocol = PROTO_ICMP;

    // Find or create flow record
    FLOW_DATA *flow = find_or_create_flow(&key);
    if (!flow)
    {
        return; // Failed to get/create flow
    }

    // --- Update Flow ---
    // Update basic stats (no flags for ICMP)
    update_flow_stats(flow, 1, size, 0); // Pass full ICMP size

    // Calculate entropy on ICMP payload if it exists and needed
    // Payload starts after base 8-byte header for many types
    int icmp_payload_offset = 8; // Default offset
    // Adjust offset based on type if needed (e.g., Timestamp has different structure)
    if (size > icmp_payload_offset && config.enable_advanced_stats)
    {
        int payload_size = size - icmp_payload_offset;
        unsigned char *payload = buffer + icmp_payload_offset;
        flow->entropy = calculate_entropy(payload, payload_size);
    }
    else
    {
        flow->entropy = 0.0;
    }

    // --- Update Host Tracking ---
    HOST_DATA *src_host = find_or_create_host(ip_header->ip_src);
    if (src_host)
        update_host_stats(src_host, flow, 1);

    HOST_DATA *dst_host = find_or_create_host(ip_header->ip_dst);
    if (dst_host)
        update_host_stats(dst_host, flow, 0);

    // --- Log Flow Periodically ---
    time_t now = time(NULL);
    if (flow->packets == 1 || (now - flow->last_log_time >= config.capture_interval))
    {
        if (config.enable_advanced_stats)
        {
            update_flow_connection_stats(flow); // Calculate stats before logging
        }
        write_flow_log(flow);
        flow->last_log_time = now;
    }
}