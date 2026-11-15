/*
 * ICSS - decentralized online circulating storage for always-on clusters.
 *
 * Project scope
 * -------------
 * The system keeps data alive by circulating it: shards travel through a
 * closed TCP ring and are never written to a node disk. The only persistent
 * local state is a hash metadata index that never contains shard content.
 *
 * Permanence premise and limits
 * -----------------------------
 * Permanence holds only while every node and link of the ring stays online.
 * A full cluster power loss, a crashing process or a network partition loses
 * the in-flight data. This is an ONLINE permanent storage layer, not a
 * durable or backed up storage system. Erasure coding lets a group survive the
 * loss of up to m of its k + m shards, but it is not a replica mechanism and
 * cannot cover the case where the whole circulation disappears at once.
 *
 * Module layout
 * -------------
 *   frame codec      wire header encode/decode, SHA-256, AES-256-GCM
 *   erasure coder    GF(256) arithmetic, Cauchy matrix, recovery
 *   discovery        UDP heartbeat, peer table, ring topology
 *   relay            queue, writer/reader threads, backpressure, topology
 *   metadata index   hash only catalogue, persisted on exit
 *   commands         node, inject, fetch, status and the test helpers
 *
 * The relay path never touches keys or plaintext. Encryption happens only at
 * the injection side, decryption only at the read side.
 */
#define _POSIX_C_SOURCE 200809L
#define _FILE_OFFSET_BITS 64
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <io.h>
#include <windows.h>
typedef SOCKET icss_socket_t;
#define ICSS_INVALID_SOCKET INVALID_SOCKET
#define icss_socket_close closesocket
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/select.h>
#include <unistd.h>
typedef int icss_socket_t;
#define ICSS_INVALID_SOCKET (-1)
#define icss_socket_close close
#endif

#define ICSS_VERSION "0.3.0-prototype"
#define ICSS_DEFAULT_CHUNK_SIZE (16U * 1024U * 1024U)
#define ICSS_HEADER_SIZE 240U
#define ICSS_MAGIC "ICSS"
#define ICSS_CONTROL_MAGIC "ICSF"
#define ICSS_FRAME_VERSION 2U
#define ICSS_FLAG_ENCRYPTED 0x01U
#define ICSS_CONTROL_SIZE 8U
#define ICSS_MAX_CHUNKS 1000000U
#define ICSS_MAX_CHUNK_SIZE (256U * 1024U * 1024U)
#define ICSS_DISCOVERY_SIZE 36U
#define ICSS_MAX_PEERS 256U
#define ICSS_HEARTBEAT_SECONDS 5
#define ICSS_PEER_TIMEOUT 30
#define ICSS_MAX_SHARDS 64U
#define ICSS_DEFAULT_QUEUE_DEPTH 32U
#define ICSS_QUEUE_MAX_FRAMES 65536U
#define ICSS_PAUSE_HIGH_PERCENT 80U
#define ICSS_RESUME_LOW_PERCENT 30U
#define ICSS_DEDUP_WINDOW 4096U
#define ICSS_FETCH_PENDING_SLOTS 64U
#define ICSS_FETCH_TIMEOUT_SECONDS 120
#define ICSS_SUBSCRIBER_POLL_SECONDS 5
/*
 * The original file name travels with every frame. It is the human readable
 * part of the catalogue that "icss ls" prints; the content hash stays the
 * authoritative identity of a dataset.
 */
#define ICSS_NAME_SIZE 64U
/* Length of the key fingerprint: SHA-256 over the raw 32 byte AES key. */
#define ICSS_KEY_ID_SIZE 32U

typedef struct icss_subscriber {
    icss_socket_t socket;
    uint16_t ring_id;
    unsigned char file_hash[32];
    struct icss_subscriber *next;
} icss_subscriber;

typedef struct icss_index_entry {
    unsigned char file_hash[32];
    uint32_t total_chunks;
    uint64_t first_seen;
    uint64_t last_seen;
    unsigned char **chunk_hashes;
    unsigned char *chunk_seen;
    /*
     * Catalogue metadata. The name is the label of the dataset and the key id
     * identifies the AES key that protects it, so that "icss ls --key" can
     * report exactly which datasets the given key is able to decrypt.
     */
    unsigned char key_id[ICSS_KEY_ID_SIZE];
    char name[ICSS_NAME_SIZE];
    int encrypted;
    struct icss_index_entry *next;
} icss_index_entry;

typedef struct {
    icss_socket_t socket;
} icss_connection;

typedef struct {
    uint32_t ip_address;
    uint16_t tcp_port;
    uint16_t ring_id;
    time_t last_seen;
    unsigned char node_id[16];
} icss_peer;

/*
 * Size of the AES-GCM additional authenticated data.
 *
 * The layout is:
 *   0   4   magic
 *   4   1   version
 *   5   1   flags
 *   6   2   ring id
 *   8   4   chunk id
 *  12   4   total chunks
 *  16   8   file size
 *  24   4   chunk size
 *  28   4   payload size
 *  32  32   file hash
 *  64  32   key id
 *  96  64   file name
 * = 160 bytes
 *
 * The catalogue fields are part of the authenticated data, so a relay cannot
 * rename a dataset or claim a different key without breaking the tag.
 */
#define ICSS_AAD_SIZE 160U

/*
 * Wire frame header.
 *
 * The immutable identity fields (ring, chunk index, file hash, sizes) are
 * bound into the AES-GCM additional authenticated data, so a relay cannot
 * rewrite them without breaking the authentication tag. The mutable fields
 * (hop counter, TTL) are rewritten by every relay and therefore excluded.
 */
typedef struct {
    uint8_t version;
    uint8_t flags;
    uint16_t ring_id;
    uint64_t sequence;        /* circulation hop counter, incremented per relay */
    uint32_t chunk_id;        /* data chunk index inside the file */
    uint32_t total_chunks;    /* padded data chunk count (group_count * k) */
    uint64_t file_size;       /* true original file length in bytes */
    uint32_t ttl;             /* remaining hops before the TTL reset */
    uint32_t chunk_size;
    uint32_t payload_size;
    unsigned char file_hash[32];
    unsigned char payload_hash[32];
    unsigned char iv[12];
    unsigned char tag[16];
    uint8_t data_shards;      /* k: data shards per erasure group */
    uint8_t parity_shards;    /* m: parity shards per erasure group */
    uint8_t shard_pos;        /* position inside the erasure group, 0..k+m-1 */
    uint8_t reserved;
    uint32_t shard_group;     /* erasure group index */
    /*
     * Catalogue fields. The name is the human readable label of the dataset and
     * the key id identifies the AES key that protects it, so that a reader can
     * tell with a single key which datasets it is able to decrypt.
     */
    unsigned char key_id[ICSS_KEY_ID_SIZE];
    char name[ICSS_NAME_SIZE];
} icss_frame_header;

/*
 * One queued frame on its way to the downstream neighbour. The queue only
 * smooths the rate difference between the upstream link and the downstream
 * link; it is never a storage location. Every entry is released as soon as it
 * has been written to the downstream socket.
 */
typedef struct {
    icss_frame_header header;
    unsigned char *payload;
} icss_queue_item;

typedef struct {
    icss_queue_item *items;
    uint32_t capacity;
    uint32_t head;
    uint32_t count;
    int paused;               /* downstream neighbour has been asked to pause */
} icss_downstream_queue;

static icss_socket_t node_listener = ICSS_INVALID_SOCKET;
static icss_socket_t discovery_socket = ICSS_INVALID_SOCKET;
static icss_socket_t downstream_socket = ICSS_INVALID_SOCKET;
static icss_socket_t upstream_socket = ICSS_INVALID_SOCKET;
static pthread_mutex_t downstream_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t subscribers_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t stats_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t index_mutex = PTHREAD_MUTEX_INITIALIZER;
static icss_subscriber *subscribers;
static icss_index_entry *index_entries;

/* Forward declaration for the bounded string copy helper. */
static void copy_bounded(char *destination, size_t capacity, const char *source);

static volatile sig_atomic_t node_running = 1;
static volatile sig_atomic_t node_status_requested;
static uint16_t node_ring_id;
static uint32_t node_chunk_size = ICSS_DEFAULT_CHUNK_SIZE;
static uint64_t node_forwarded;
static uint32_t node_permanent_files;
static time_t node_started;
static char node_next_host[256] = "127.0.0.1";
static char node_next_port[16];
static char node_index_path[1024] = "./icss_index.dat";
static uint16_t node_discovery_port = 7777U;
static uint32_t node_advertise_ip;
static char node_listen_port[16];
static icss_peer node_peers[ICSS_MAX_PEERS];
static size_t node_peer_count;
static int node_manual_next;
static time_t node_last_heartbeat;
static uint32_t node_queue_depth = ICSS_DEFAULT_QUEUE_DEPTH;
static icss_downstream_queue node_queue;
static pthread_t node_writer_thread;
static int node_writer_started;
static uint64_t node_dropped_frames;
static uint64_t node_pause_events;
static uint64_t node_resume_events;
/* Set when the next hop asked this node to slow down. */
static volatile int node_outbound_paused;

/* Control frame operations used between neighbouring nodes. */
#define ICSS_OP_INJECT 'I'
#define ICSS_OP_FETCH 'F'
#define ICSS_OP_STATUS 'S'
#define ICSS_OP_PAUSE 'P'
#define ICSS_OP_RESUME 'R'
#define ICSS_OP_LIST 'L'

/* FETCH control frame flags */
#define ICSS_FETCH_FLAG_NAME   0x01U  /* body contains name instead of hash */
#define ICSS_FETCH_FLAG_KEYID  0x02U  /* body contains key_id for ownership check */

/* FETCH control frame operation codes */
#define ICSS_OP_ERROR 'E'             /* error reply to a fetch/list request */

/* Forward declarations for functions used before their definition. */
static int lookup_hash_by_name(const char *name,
    const unsigned char key_id[ICSS_KEY_ID_SIZE], int have_key_id,
    unsigned char out_hash[32]);
static int send_control(icss_socket_t socket, char operation, uint16_t ring_id,
    uint8_t flags);
static int parse_catalogue_record(const char *record,
    char *name, size_t name_cap,
    char *hash, size_t hash_cap,
    char *key_id_text, size_t key_id_cap,
    int *encrypted);

static int sha256_buffer(const unsigned char *data, size_t size,
    unsigned char digest[32]);
static int parse_u32(const char *text, uint32_t minimum, uint32_t maximum,
    uint32_t *value);

/*
 * Erasure coding parameters. A group of k data shards is protected by m parity
 * shards. k + 1 data shards are required for recovery, so up to m shards may be
 * missing. k = 1 and m = 0 degenerates into plain chunk circulation.
 */
#define ICSS_MAX_ERASURE_GROUPS 65536U

static void put_u16(unsigned char *out, uint16_t value)
{
    out[0] = (unsigned char)(value >> 8);
    out[1] = (unsigned char)value;
}

static uint16_t get_u16(const unsigned char *in)
{
    return (uint16_t)(((uint16_t)in[0] << 8) | in[1]);
}

static void put_u32(unsigned char *out, uint32_t value)
{
    out[0] = (unsigned char)(value >> 24);
    out[1] = (unsigned char)(value >> 16);
    out[2] = (unsigned char)(value >> 8);
    out[3] = (unsigned char)value;
}

static uint32_t get_u32(const unsigned char *in)
{
    return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) |
        ((uint32_t)in[2] << 8) | (uint32_t)in[3];
}

static void put_u64(unsigned char *out, uint64_t value)
{
    unsigned int index;
    for (index = 0; index < 8U; ++index) {
        out[index] = (unsigned char)(value >> (56U - index * 8U));
    }
}

static uint64_t get_u64(const unsigned char *in)
{
    uint64_t value = 0;
    unsigned int index;
    for (index = 0; index < 8U; ++index) {
        value = (value << 8) | in[index];
    }
    return value;
}

static void make_node_id(uint32_t ip_address, uint16_t tcp_port,
    unsigned char node_id[16])
{
    unsigned char identity[6];
    unsigned char digest[32];
    memcpy(identity, &ip_address, 4);
    put_u16(identity + 4, tcp_port);
    if (sha256_buffer(identity, sizeof(identity), digest)) {
        memcpy(node_id, digest, 16);
    } else {
        memset(node_id, 0, 16);
    }
    OPENSSL_cleanse(identity, sizeof(identity));
    OPENSSL_cleanse(digest, sizeof(digest));
}

static int sha256_buffer(const unsigned char *data, size_t size,
    unsigned char digest[32])
{
    unsigned int digest_size = 0;
    return EVP_Digest(data, size, digest, &digest_size, EVP_sha256(), NULL) == 1 &&
        digest_size == 32U;
}

static int encode_frame_header(const icss_frame_header *header,
    unsigned char output[ICSS_HEADER_SIZE])
{
    if (header->payload_size > INT32_MAX || header->chunk_size == 0U ||
        header->total_chunks == 0U ||
        header->chunk_id >= header->total_chunks) {
        return 0;
    }
    memcpy(output, ICSS_MAGIC, 4);
    output[4] = header->version;
    output[5] = header->flags;
    put_u16(output + 6, header->ring_id);
    put_u64(output + 8, header->sequence);
    put_u32(output + 16, header->chunk_id);
    put_u32(output + 20, header->total_chunks);
    put_u64(output + 24, header->file_size);
    put_u32(output + 32, header->ttl);
    put_u32(output + 36, header->chunk_size);
    put_u32(output + 40, header->payload_size);
    memcpy(output + 44, header->file_hash, 32);
    memcpy(output + 76, header->payload_hash, 32);
    memcpy(output + 108, header->iv, 12);
    memcpy(output + 120, header->tag, 16);
    output[136] = header->data_shards;
    output[137] = header->parity_shards;
    output[138] = header->shard_pos;
    output[139] = header->reserved;
    put_u32(output + 140, header->shard_group);
    memcpy(output + 144, header->key_id, ICSS_KEY_ID_SIZE);
    memcpy(output + 176, header->name, ICSS_NAME_SIZE);
    return 1;
}

static int decode_frame_header(const unsigned char input[ICSS_HEADER_SIZE],
    icss_frame_header *header, uint32_t maximum_payload)
{
    if (memcmp(input, ICSS_MAGIC, 4) != 0 || input[4] != ICSS_FRAME_VERSION ||
        (input[5] & (unsigned char)~ICSS_FLAG_ENCRYPTED) != 0U) {
        return 0;
    }
    header->version = input[4];
    header->flags = input[5];
    header->ring_id = get_u16(input + 6);
    header->sequence = get_u64(input + 8);
    header->chunk_id = get_u32(input + 16);
    header->total_chunks = get_u32(input + 20);
    header->file_size = get_u64(input + 24);
    header->ttl = get_u32(input + 32);
    header->chunk_size = get_u32(input + 36);
    header->payload_size = get_u32(input + 40);
    memcpy(header->file_hash, input + 44, 32);
    memcpy(header->payload_hash, input + 76, 32);
    memcpy(header->iv, input + 108, 12);
    memcpy(header->tag, input + 120, 16);
    header->data_shards = input[136];
    header->parity_shards = input[137];
    header->shard_pos = input[138];
    header->reserved = input[139];
    header->shard_group = get_u32(input + 140);
    memcpy(header->key_id, input + 144, ICSS_KEY_ID_SIZE);
    memcpy(header->name, input + 176, ICSS_NAME_SIZE);
    header->name[ICSS_NAME_SIZE - 1U] = '\0';
    if (header->data_shards == 0U ||
        header->data_shards + header->parity_shards > ICSS_MAX_SHARDS ||
        header->shard_pos >= header->data_shards + header->parity_shards) {
        return 0;
    }
    return header->chunk_size != 0U && header->chunk_size <= maximum_payload &&
        header->payload_size <= header->chunk_size &&
        header->total_chunks != 0U &&
        header->chunk_id < header->total_chunks &&
        header->payload_size <= maximum_payload;
}

/* Decode a frame header whose first four magic bytes were already consumed. */
static int decode_frame_header_prefix(const unsigned char magic[4],
    const unsigned char rest[ICSS_HEADER_SIZE - 4U], icss_frame_header *header,
    uint32_t maximum_payload)
{
    unsigned char wire[ICSS_HEADER_SIZE];
    memcpy(wire, magic, 4);
    memcpy(wire + 4, rest, ICSS_HEADER_SIZE - 4U);
    return decode_frame_header(wire, header, maximum_payload);
}

/*
 * Additional authenticated data for AES-256-GCM. Only immutable identity
 * fields are bound, so a relay may freely rewrite the hop counter and TTL
 * without invalidating the authentication tag.
 */
static void build_frame_aad(const icss_frame_header *header,
    unsigned char aad[ICSS_AAD_SIZE])
{
    memset(aad, 0, ICSS_AAD_SIZE);
    memcpy(aad, ICSS_MAGIC, 4);
    aad[4] = header->version;
    aad[5] = header->flags;
    put_u16(aad + 6, header->ring_id);
    put_u32(aad + 8, header->chunk_id);
    put_u32(aad + 12, header->total_chunks);
    put_u64(aad + 16, header->file_size);
    put_u32(aad + 24, header->chunk_size);
    put_u32(aad + 28, header->payload_size);
    memcpy(aad + 32, header->file_hash, 32);
    memcpy(aad + 64, header->key_id, ICSS_KEY_ID_SIZE);
    memcpy(aad + 96, header->name, ICSS_NAME_SIZE);
}

/*
 * Look up the catalogue entry of one concrete dataset layout.
 *
 * A dataset is identified by its content hash *and* by the number of frames it
 * was split into. The chunk indices only carry a meaning inside one erasure
 * layout, so the same file injected with different parameters describes a
 * different set of chunks. Keying the catalogue by both values lets several
 * layouts of the same file coexist instead of colliding.
 */
static icss_index_entry *find_index_entry_layout(const unsigned char file_hash[32],
    uint32_t total_chunks)
{
    icss_index_entry *entry;
    for (entry = index_entries; entry != NULL; entry = entry->next) {
        if (entry->total_chunks == total_chunks &&
            memcmp(entry->file_hash, file_hash, 32) == 0) {
            return entry;
        }
    }
    return NULL;
}

/*
 * Report whether any layout of the given file has already been seen.
 *
 * The read side only knows the content hash, so it accepts the subscription as
 * soon as one chunk of one of the layouts is available.
 */
static int index_has_seen_chunks(const unsigned char file_hash[32])
{
    icss_index_entry *entry;
    for (entry = index_entries; entry != NULL; entry = entry->next) {
        uint32_t index;
        if (memcmp(entry->file_hash, file_hash, 32) != 0) {
            continue;
        }
        if (entry->chunk_seen == NULL) {
            continue;
        }
        for (index = 0; index < entry->total_chunks; ++index) {
            if (entry->chunk_seen[index]) {
                return 1;
            }
        }
    }
    return 0;
}

static void free_index_entries(void)
{
    icss_index_entry *entry = index_entries;
    while (entry != NULL) {
        icss_index_entry *next = entry->next;
        free(entry->chunk_hashes);
        free(entry->chunk_seen);
        free(entry);
        entry = next;
    }
    index_entries = NULL;
}

static int save_index(void)
{
    FILE *file;
    icss_index_entry *entry;
    uint32_t count = 0;
    /* Format version 2 adds the catalogue metadata to every record. */
    unsigned char header[12] = {'I','C','I','X',0,2,0,0,0,0,0,0};
    char temporary[1100];
    snprintf(temporary, sizeof(temporary), "%s.tmp", node_index_path);
    pthread_mutex_lock(&index_mutex);
    put_u16(header + 6, node_ring_id);
    for (entry = index_entries; entry != NULL; entry = entry->next) {
        if (entry->chunk_seen != NULL) {
            uint32_t index;
            int complete = 1;
            for (index = 0; index < entry->total_chunks; ++index) {
                if (!entry->chunk_seen[index]) {
                    complete = 0;
                    break;
                }
            }
            if (complete) ++count;
        }
    }
    put_u32(header + 8, count);
    file = fopen(temporary, "wb");
    if (file == NULL || fwrite(header, 1, sizeof(header), file) != sizeof(header)) {
        if (file != NULL) fclose(file);
        pthread_mutex_unlock(&index_mutex);
        remove(temporary);
        return 0;
    }
    for (entry = index_entries; entry != NULL; entry = entry->next) {
        uint32_t index;
        int complete = 1;
        /*
         * Record layout (version 2):
         *   0  32  file hash
         *  32   4  total chunks
         *  36   8  first seen
         *  44   8  last seen
         *  52   1  encrypted flag
         *  53  32  key id
         *  85  63  file name (NUL padded)
         * = 148 bytes
         */
        unsigned char record[148];
        if (entry->chunk_seen == NULL) continue;
        for (index = 0; index < entry->total_chunks; ++index) {
            if (!entry->chunk_seen[index]) {
                complete = 0;
                break;
            }
        }
        if (!complete) continue;
        memset(record, 0, sizeof(record));
        memcpy(record, entry->file_hash, 32);
        put_u32(record + 32, entry->total_chunks);
        put_u64(record + 36, entry->first_seen);
        put_u64(record + 44, entry->last_seen);
        record[52] = (unsigned char)(entry->encrypted ? 1U : 0U);
        memcpy(record + 53, entry->key_id, ICSS_KEY_ID_SIZE);
        /*
         * The name is copied field by field: the record area is already zeroed
         * above, so a NUL padded copy is enough and avoids the truncation
         * warning of strncpy.
         */
        {
            /* The length is found without relying on strnlen, which is not
               available on every supported compiler. */
            size_t length = 0;
            while (length < ICSS_NAME_SIZE - 1U && entry->name[length] != '\0') {
                ++length;
            }
            memcpy(record + 85, entry->name, length);
            record[85 + length] = 0U;
        }
        if (fwrite(record, 1, sizeof(record), file) != sizeof(record)) {
            fclose(file);
            pthread_mutex_unlock(&index_mutex);
            remove(temporary);
            return 0;
        }
        for (index = 0; index < entry->total_chunks; ++index) {
            if (fwrite(entry->chunk_hashes[index], 1, 32, file) != 32U) {
                fclose(file);
                pthread_mutex_unlock(&index_mutex);
                remove(temporary);
                return 0;
            }
        }
    }
    if (fflush(file) != 0 || fclose(file) != 0) {
        pthread_mutex_unlock(&index_mutex);
        remove(temporary);
        return 0;
    }
#ifdef _WIN32
    if (!MoveFileExA(temporary, node_index_path,
        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
#else
    if (rename(temporary, node_index_path) != 0) {
#endif
        pthread_mutex_unlock(&index_mutex);
        remove(temporary);
        return 0;
    }
    node_permanent_files = count;
    pthread_mutex_unlock(&index_mutex);
    return 1;
}

static int load_index(void)
{
    FILE *file = fopen(node_index_path, "rb");
    unsigned char header[12];
    uint32_t count;
    uint32_t file_number;
    uint16_t version;
    if (file == NULL) return errno == ENOENT;
    if (fread(header, 1, sizeof(header), file) != sizeof(header) ||
        memcmp(header, "ICIX", 4) != 0 ||
        get_u16(header + 6) != node_ring_id) {
        fclose(file);
        fprintf(stderr, "icss: index header invalid or ring mismatch\n");
        return 0;
    }
    version = get_u16(header + 4);
    /* Version 1 has no catalogue metadata; version 2 adds it to the records. */
    if (version != 1U && version != 2U) {
        fclose(file);
        fprintf(stderr, "icss: unsupported index version %u\n", (unsigned int)version);
        return 0;
    }
    count = get_u32(header + 8);
    if (count > ICSS_MAX_CHUNKS) {
        fclose(file);
        fprintf(stderr, "icss: index entry count exceeds limit\n");
        return 0;
    }
    for (file_number = 0; file_number < count; ++file_number) {
        unsigned char record[148];
        unsigned char legacy[52];
        icss_index_entry *entry;
        uint32_t index;
        if (version == 1U) {
            if (fread(legacy, 1, sizeof(legacy), file) != sizeof(legacy)) goto invalid;
            memset(record, 0, sizeof(record));
            memcpy(record, legacy, 32);
            put_u32(record + 32, get_u32(legacy + 32));
            put_u64(record + 36, get_u64(legacy + 36));
            put_u64(record + 44, get_u64(legacy + 44));
        } else {
            if (fread(record, 1, sizeof(record), file) != sizeof(record)) goto invalid;
        }
        entry = (icss_index_entry *)calloc(1, sizeof(*entry));
        if (entry == NULL) goto invalid;
        memcpy(entry->file_hash, record, 32);
        entry->total_chunks = get_u32(record + 32);
        entry->first_seen = get_u64(record + 36);
        entry->last_seen = get_u64(record + 44);
        entry->encrypted = record[52] != 0U;
        memcpy(entry->key_id, record + 53, ICSS_KEY_ID_SIZE);
        {
            size_t length = 0;
            while (length < ICSS_NAME_SIZE - 1U &&
                   ((const char *)record)[85 + length] != '\0') {
                ++length;
            }
            memcpy(entry->name, (const char *)record + 85, length);
            entry->name[length] = '\0';
        }
        if (entry->total_chunks == 0U || entry->total_chunks > ICSS_MAX_CHUNKS) {
            free(entry);
            goto invalid;
        }
        entry->chunk_hashes = (unsigned char **)calloc(entry->total_chunks,
            sizeof(*entry->chunk_hashes));
        entry->chunk_seen = (unsigned char *)malloc(entry->total_chunks);
        if (entry->chunk_hashes == NULL || entry->chunk_seen == NULL) {
            free(entry->chunk_hashes);
            free(entry->chunk_seen);
            free(entry);
            goto invalid;
        }
        memset(entry->chunk_seen, 1, entry->total_chunks);
        for (index = 0; index < entry->total_chunks; ++index) {
            entry->chunk_hashes[index] = (unsigned char *)malloc(32);
            if (entry->chunk_hashes[index] == NULL ||
                fread(entry->chunk_hashes[index], 1, 32, file) != 32U) {
                free(entry->chunk_hashes[index]);
                free(entry->chunk_hashes);
                free(entry->chunk_seen);
                free(entry);
                goto invalid;
            }
        }
        entry->next = index_entries;
        index_entries = entry;
    }
    fclose(file);
    node_permanent_files = count;
    return 1;
invalid:
    fclose(file);
    free_index_entries();
    fprintf(stderr, "icss: truncated or invalid index file\n");
    return 0;
}

static int record_frame_metadata(const icss_frame_header *header)
{
    icss_index_entry *entry;
    unsigned char *chunk_hash;
    uint32_t index;
    int changed = 0;
    pthread_mutex_lock(&index_mutex);
    /*
     * The catalogue is keyed by content hash *and* frame count. Injecting the
     * same file again with a different erasure layout produces a different set
     * of chunk indices, and those must not overwrite the entries of the layout
     * that is already circulating.
     */
    entry = find_index_entry_layout(header->file_hash, header->total_chunks);
    if (entry == NULL) {
        entry = (icss_index_entry *)calloc(1, sizeof(*entry));
        if (entry == NULL) {
            pthread_mutex_unlock(&index_mutex);
            return 0;
        }
        memcpy(entry->file_hash, header->file_hash, 32);
        entry->total_chunks = header->total_chunks;
        entry->first_seen = (uint64_t)time(NULL);
        entry->chunk_hashes = (unsigned char **)calloc(entry->total_chunks,
            sizeof(*entry->chunk_hashes));
        entry->chunk_seen = (unsigned char *)calloc(entry->total_chunks, 1);
        if (entry->chunk_hashes == NULL || entry->chunk_seen == NULL) {
            free(entry->chunk_hashes);
            free(entry->chunk_seen);
            free(entry);
            pthread_mutex_unlock(&index_mutex);
            return 0;
        }
        entry->next = index_entries;
        index_entries = entry;
    }
    if (header->chunk_id >= entry->total_chunks) {
        pthread_mutex_unlock(&index_mutex);
        return 0;
    }
    /* Keep the catalogue metadata in sync with the frames that arrive. */
    if (memcmp(entry->key_id, header->key_id, ICSS_KEY_ID_SIZE) != 0) {
        memcpy(entry->key_id, header->key_id, ICSS_KEY_ID_SIZE);
        changed = 1;
    }
    if (entry->encrypted != ((header->flags & ICSS_FLAG_ENCRYPTED) != 0U)) {
        entry->encrypted = (header->flags & ICSS_FLAG_ENCRYPTED) != 0U;
        changed = 1;
    }
    if (strncmp(entry->name, header->name, ICSS_NAME_SIZE) != 0) {
        copy_bounded(entry->name, ICSS_NAME_SIZE, header->name);
        changed = 1;
    }
    chunk_hash = entry->chunk_hashes[header->chunk_id];
    if (chunk_hash == NULL) {
        chunk_hash = (unsigned char *)malloc(32);
        if (chunk_hash == NULL) {
            pthread_mutex_unlock(&index_mutex);
            return 0;
        }
        entry->chunk_hashes[header->chunk_id] = chunk_hash;
        changed = 1;
    } else if (memcmp(chunk_hash, header->payload_hash, 32) != 0) {
        changed = 1;
    }
    memcpy(chunk_hash, header->payload_hash, 32);
    if (!entry->chunk_seen[header->chunk_id]) changed = 1;
    entry->chunk_seen[header->chunk_id] = 1;
    entry->last_seen = (uint64_t)time(NULL);
    for (index = 0; index < entry->total_chunks; ++index) {
        if (!entry->chunk_seen[index]) break;
    }
    pthread_mutex_unlock(&index_mutex);
    return index == entry->total_chunks && changed ? save_index() : 1;
}

/*
 * Copy a string into a fixed size field and terminate it.
 *
 * The helper exists because strncpy does not terminate the destination when
 * the source is longer than the field, which would leave an unterminated
 * string in the frame header.
 */
static void copy_bounded(char *destination, size_t capacity, const char *source)
{
    size_t length = 0;
    if (capacity == 0U) {
        return;
    }
    while (length + 1U < capacity && source[length] != '\0') {
        ++length;
    }
    memcpy(destination, source, length);
    destination[length] = '\0';
}

/*
 * Fingerprint of an AES key: SHA-256 over the raw 32 key bytes.
 *
 * The fingerprint travels with every frame. A reader that is given a key can
 * therefore decide with a cheap comparison whether it is able to decrypt a
 * dataset, without having to try the key against the data itself. The
 * fingerprint is never a secret: knowing it does not help to decrypt anything.
 */
static int compute_key_id(const unsigned char key[32],
    unsigned char key_id[ICSS_KEY_ID_SIZE])
{
    return sha256_buffer(key, 32U, key_id);
}

static int load_aes256_key(const char *path, unsigned char key[32])
{
    FILE *file = fopen(path, "rb");
    int extra;
    int failed;
    size_t read_size;
    if (file == NULL) {
        fprintf(stderr, "icss: cannot open key file '%s': %s\n", path,
            strerror(errno));
        return 0;
    }
    read_size = fread(key, 1, 32, file);
    extra = fgetc(file);
    failed = ferror(file);
    if (fclose(file) != 0) failed = 1;
    if (failed || read_size != 32U || extra != EOF) {
        OPENSSL_cleanse(key, 32);
        fprintf(stderr, "icss: key file must contain exactly 32 bytes\n");
        return 0;
    }
    return 1;
}

static int aes256_gcm_encrypt(const unsigned char key[32],
    icss_frame_header *header, unsigned char *payload, size_t payload_size)
{
    EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
    unsigned char aad[ICSS_AAD_SIZE];
    int written = 0;
    int final_written = 0;
    int success = 0;
    build_frame_aad(header, aad);
    if (context == NULL || payload_size > INT32_MAX ||
        RAND_bytes(header->iv, (int)sizeof(header->iv)) != 1 ||
        EVP_EncryptInit_ex(context, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN,
            (int)sizeof(header->iv), NULL) != 1 ||
        EVP_EncryptInit_ex(context, NULL, NULL, key, header->iv) != 1 ||
        EVP_EncryptUpdate(context, NULL, &written, aad, (int)sizeof(aad)) != 1 ||
        EVP_EncryptUpdate(context, payload, &written, payload,
            (int)payload_size) != 1 ||
        EVP_EncryptFinal_ex(context, payload + written, &final_written) != 1 ||
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_GET_TAG,
            (int)sizeof(header->tag), header->tag) != 1) {
        goto cleanup;
    }
    success = (size_t)(written + final_written) == payload_size;
cleanup:
    OPENSSL_cleanse(aad, sizeof(aad));
    EVP_CIPHER_CTX_free(context);
    return success;
}

static int aes256_gcm_decrypt(const unsigned char key[32],
    const icss_frame_header *header, unsigned char *payload, size_t payload_size)
{
    EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
    unsigned char aad[ICSS_AAD_SIZE];
    int written = 0;
    int final_written = 0;
    int success = 0;
    build_frame_aad(header, aad);
    if (context == NULL || payload_size > INT32_MAX ||
        EVP_DecryptInit_ex(context, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN,
            (int)sizeof(header->iv), NULL) != 1 ||
        EVP_DecryptInit_ex(context, NULL, NULL, key, header->iv) != 1 ||
        EVP_DecryptUpdate(context, NULL, &written, aad, (int)sizeof(aad)) != 1 ||
        EVP_DecryptUpdate(context, payload, &written, payload,
            (int)payload_size) != 1 ||
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_TAG,
            (int)sizeof(header->tag), (void *)header->tag) != 1 ||
        EVP_DecryptFinal_ex(context, payload + written, &final_written) != 1) {
        goto cleanup;
    }
    success = (size_t)(written + final_written) == payload_size;
cleanup:
    OPENSSL_cleanse(aad, sizeof(aad));
    EVP_CIPHER_CTX_free(context);
    return success;
}

/*
 * Reed-Solomon erasure coding over GF(256).
 *
 * A Cauchy matrix is used as the generator: for k data shards and m parity
 * shards the matrix rows are built from two disjoint sets of field elements,
 * which guarantees that any k rows form an invertible submatrix. That means
 * recovery works for any k surviving shards, not only for a fixed subset.
 *
 * The relay nodes never execute any of this code: encoding happens at the
 * injection side, decoding at the read side.
 */

static unsigned char gf_exp[512];
static unsigned char gf_log[256];
static int gf_tables_ready;

static unsigned char gf_mul(unsigned char a, unsigned char b)
{
    if (a == 0U || b == 0U) return 0U;
    return gf_exp[(size_t)gf_log[a] + (size_t)gf_log[b]];
}

static unsigned char gf_div(unsigned char a, unsigned char b)
{
    if (b == 0U || a == 0U) return 0U;
    /* a / b == a * b^-1 == a * b^(255 - log(b)). */
    return gf_exp[(size_t)gf_log[a] + 255U - (size_t)gf_log[b]];
}

static unsigned char gf_inv(unsigned char a)
{
    if (a == 0U) return 0U;
    /* a^255 == 1 in GF(2^8), so a^-1 == a^(255 - log(a)). */
    return gf_exp[255U - (size_t)gf_log[a]];
}

static int gf_init(void)
{
    unsigned int value = 1U;
    unsigned int index;
    unsigned int generator = 0x11dU;
    if (gf_tables_ready) return 1;
    for (index = 0; index < 255U; ++index) {
        gf_exp[index] = (unsigned char)value;
        gf_log[value] = (unsigned char)index;
        value <<= 1U;
        if (value & 0x100U) value ^= generator;
    }
    for (index = 255U; index < 512U; ++index) {
        gf_exp[index] = gf_exp[index - 255U];
    }
    gf_log[0] = 0U;
    gf_tables_ready = 1;
    return 1;
}

/*
 * Build the (k+m) x k generator matrix. Rows [0, k) form the identity matrix,
 * rows [k, k+m) are the Cauchy rows.
 */
static int rs_build_matrix(uint8_t data_shards, uint8_t parity_shards,
    unsigned char *matrix)
{
    uint8_t total;
    uint8_t row;
    uint8_t column;
    if (!gf_init() || data_shards == 0U || parity_shards == 0U ||
        data_shards + parity_shards > ICSS_MAX_SHARDS ||
        (unsigned int)parity_shards + data_shards > 255U) {
        return 0;
    }
    total = (uint8_t)(data_shards + parity_shards);
    for (row = 0; row < data_shards; ++row) {
        for (column = 0; column < data_shards; ++column) {
            matrix[(size_t)row * data_shards + column] =
                row == column ? 1U : 0U;
        }
    }
    /*
     * Cauchy rows: C[i][j] = 1 / (x_i - y_j). Over GF(2^8) subtraction is
     * XOR. The element sets X = {1..m} and Y = {m+1..m+k} never overlap, so
     * every square submatrix of C is invertible and any k shards recover the
     * data.
     */
    for (row = data_shards; row < total; ++row) {
        unsigned char x = (unsigned char)(row - data_shards + 1U);
        for (column = 0; column < data_shards; ++column) {
            unsigned char y = (unsigned char)(parity_shards + column + 1U);
            matrix[(size_t)row * data_shards + column] = gf_inv(x ^ y);
        }
    }
    return 1;
}

/*
 * Recover the k data shards of one erasure group.
 *
 * 'matrix' is the full (k+m) x k generator matrix, 'rows' selects the k
 * surviving generator rows, and 'contents' holds the payload of those rows in
 * the same order. The reconstructed data shards are written to 'data'.
 *
 * The system shard_i = sum_j G[rows[i]][j] * data[j] is solved with
 * Gauss-Jordan elimination on the augmented matrix [G_rows | I], which yields
 * M^-1 on the right half. The data shards follow from
 * data[j] = sum_i M^-1[j][i] * contents[i].
 */
static int rs_recover_group(uint8_t data_shards, const unsigned char *matrix,
    const uint8_t *rows, const unsigned char *contents, size_t shard_size,
    unsigned char *data)
{
    unsigned char augmented[ICSS_MAX_SHARDS * ICSS_MAX_SHARDS * 2U];
    uint8_t column;
    uint8_t row;
    uint8_t pivot;
    uint16_t offset;
    if (data_shards == 0U) return 0;
    for (row = 0; row < data_shards; ++row) {
        unsigned char *augmented_row = augmented + (size_t)row * data_shards * 2U;
        memcpy(augmented_row, matrix + (size_t)rows[row] * data_shards,
            data_shards);
        memset(augmented_row + data_shards, 0, data_shards);
        augmented_row[data_shards + row] = 1U;
    }
    for (column = 0; column < data_shards; ++column) {
        pivot = column;
        while (pivot < data_shards &&
               augmented[(size_t)pivot * data_shards * 2U + column] == 0U) {
            ++pivot;
        }
        if (pivot >= data_shards) return 0;
        if (pivot != column) {
            unsigned char *first = augmented + (size_t)column * data_shards * 2U;
            unsigned char *second = augmented + (size_t)pivot * data_shards * 2U;
            for (offset = 0; offset < (uint16_t)(data_shards * 2U); ++offset) {
                unsigned char temporary = first[offset];
                first[offset] = second[offset];
                second[offset] = temporary;
            }
        }
        {
            unsigned char *pivot_row = augmented + (size_t)column * data_shards * 2U;
            unsigned char scale = gf_inv(pivot_row[column]);
            for (offset = 0; offset < (uint16_t)(data_shards * 2U); ++offset) {
                pivot_row[offset] = gf_mul(pivot_row[offset], scale);
            }
        }
        for (row = 0; row < data_shards; ++row) {
            unsigned char *target = augmented + (size_t)row * data_shards * 2U;
            unsigned char factor;
            if (row == column) continue;
            factor = target[column];
            if (factor == 0U) continue;
            for (offset = 0; offset < (uint16_t)(data_shards * 2U); ++offset) {
                target[offset] ^= gf_mul(factor,
                    augmented[(size_t)column * data_shards * 2U + offset]);
            }
        }
    }
    for (column = 0; column < data_shards; ++column) {
        size_t position;
        for (position = 0; position < shard_size; ++position) {
            unsigned char value = 0U;
            uint8_t source;
            for (source = 0; source < data_shards; ++source) {
                unsigned char factor =
                    augmented[(size_t)column * data_shards * 2U + data_shards + source];
                if (factor == 0U) continue;
                value ^= gf_mul(factor,
                    contents[(size_t)source * shard_size + position]);
            }
            data[(size_t)column * shard_size + position] = value;
        }
    }
    return 1;
}
/*
 * Verify the erasure coder: encode k data shards, drop m of them, and rebuild
 * the original data from the remaining k shards. Several drop patterns are
 * exercised because a Cauchy matrix must survive every subset.
 */
static int run_erasure_self_test(void)
{
    static const uint8_t k = 4U;
    static const uint8_t m = 2U;
    static const size_t shard_size = 64U;
    unsigned char matrix[ICSS_MAX_SHARDS * ICSS_MAX_SHARDS];
    unsigned char data[4U * 64U];
    unsigned char encoded[6U * 64U];
    unsigned char contents[4U * 64U];
    unsigned char recovered[4U * 64U];
    uint8_t rows[4];
    uint8_t pattern;
    size_t index;
    if (!gf_init()) return 0;
    /* Field sanity: a * (a^-1) == 1 and a / b == a * b^-1 for every element. */
    for (index = 1; index < 256U; ++index) {
        unsigned char element = (unsigned char)index;
        if (gf_mul(element, gf_inv(element)) != 1U) return 0;
        if (gf_div(element, element) != 1U) return 0;
    }
    if (!rs_build_matrix(k, m, matrix)) return 0;
    for (index = 0; index < sizeof(data); ++index) {
        data[index] = (unsigned char)(index * 7U + 3U);
    }
    for (index = 0; index < k; ++index) {
        memcpy(encoded + index * shard_size, data + index * shard_size,
            shard_size);
    }
    for (index = k; index < k + m; ++index) {
        size_t position;
        for (position = 0; position < shard_size; ++position) {
            unsigned char value = 0U;
            uint8_t column;
            for (column = 0; column < k; ++column) {
                value ^= gf_mul(matrix[index * k + column],
                    data[column * shard_size + position]);
            }
            encoded[index * shard_size + position] = value;
        }
    }
    /* Drop the first m shards, then the last m shards, then an interleaved set. */
    for (pattern = 0; pattern < 3U; ++pattern) {
        uint8_t available = 0;
        uint8_t candidate;
        for (candidate = 0; candidate < k + m; ++candidate) {
            int skip;
            if (pattern == 0U) skip = candidate < m;
            else if (pattern == 1U) skip = candidate >= k;
            else skip = (candidate == 1U || candidate == 4U);
            if (skip) continue;
            rows[available] = candidate;
            memcpy(contents + (size_t)available * shard_size,
                encoded + (size_t)candidate * shard_size, shard_size);
            ++available;
        }
        if (available != k) return 0;
        memset(recovered, 0, sizeof(recovered));
        if (!rs_recover_group(k, matrix, rows, contents, shard_size, recovered)) {
            return 0;
        }
        if (memcmp(recovered, data, sizeof(data)) != 0) {
            return 0;
        }
    }
    return 1;
}

static int run_self_test(void)
{
    static const unsigned char sample[] = "icss-frame-self-test";
    unsigned char key[32];
    unsigned char payload[sizeof(sample)];
    unsigned char encrypted[sizeof(sample)];
    unsigned char digest[32];
    unsigned char wire[ICSS_HEADER_SIZE];
    icss_frame_header source;
    icss_frame_header decoded;
    int success = 0;

    memset(&source, 0, sizeof(source));
    source.version = ICSS_FRAME_VERSION;
    source.flags = ICSS_FLAG_ENCRYPTED;
    source.ring_id = 0x1234U;
    source.sequence = UINT64_C(0x0102030405060708);
    source.chunk_id = 1U;
    source.total_chunks = 2U;
    source.file_size = UINT64_C(0x0102030405060708);
    source.ttl = 7U;
    source.chunk_size = (uint32_t)sizeof(sample);
    source.payload_size = (uint32_t)sizeof(sample);
    source.data_shards = 1U;
    source.parity_shards = 0U;
    source.shard_pos = 0U;
    source.shard_group = 3U;
    /* The catalogue fields must survive the header round-trip as well. */
    memcpy(source.key_id, (const unsigned char *)"0123456789abcdef0123456789abcdef", 32);
    strcpy(source.name, "sample.bin");
    if (!encode_frame_header(&source, wire) ||
        !decode_frame_header(wire, &decoded, (uint32_t)sizeof(sample)) ||
        decoded.ring_id != source.ring_id || decoded.sequence != source.sequence ||
        decoded.file_size != source.file_size || decoded.chunk_id != source.chunk_id ||
        decoded.chunk_size != source.chunk_size ||
        decoded.data_shards != source.data_shards ||
        decoded.parity_shards != source.parity_shards ||
        decoded.shard_pos != source.shard_pos ||
        decoded.shard_group != source.shard_group ||
        memcmp(decoded.key_id, source.key_id, ICSS_KEY_ID_SIZE) != 0 ||
        strcmp(decoded.name, source.name) != 0 ||
        RAND_bytes(key, (int)sizeof(key)) != 1) {
        fprintf(stderr, "selftest: frame header round-trip failed\n");
        goto cleanup;
    }
    memcpy(payload, sample, sizeof(sample));
    if (!aes256_gcm_encrypt(key, &source, payload, sizeof(payload)) ||
        !sha256_buffer(payload, sizeof(payload), digest)) {
        goto cleanup;
    }
    memcpy(encrypted, payload, sizeof(payload));
    if (!aes256_gcm_decrypt(key, &source, payload, sizeof(payload)) ||
        memcmp(payload, sample, sizeof(sample)) != 0) {
        goto cleanup;
    }
    memcpy(payload, encrypted, sizeof(payload));
    source.tag[0] ^= 0x01U;
    if (aes256_gcm_decrypt(key, &source, payload, sizeof(payload))) {
        goto cleanup;
    }
    /* The AAD binds the identity fields, so a relay cannot silently rewrite the
       chunk index or the file hash without breaking authentication. */
    source.tag[0] ^= 0x01U;
    memcpy(payload, encrypted, sizeof(payload));
    source.chunk_id = 0U;
    if (aes256_gcm_decrypt(key, &source, payload, sizeof(payload))) {
        fprintf(stderr, "selftest: AAD binding not enforced\n");
        goto cleanup;
    }
    /* The catalogue fields are part of the AAD as well, so a relay cannot
       rename a dataset or claim another key without breaking the tag. */
    source.chunk_id = 1U;
    memcpy(payload, encrypted, sizeof(payload));
    source.name[0] = 'X';
    if (aes256_gcm_decrypt(key, &source, payload, sizeof(payload))) {
        fprintf(stderr, "selftest: name is not protected by the AAD\n");
        goto cleanup;
    }
    source.name[0] = 's';
    memcpy(payload, encrypted, sizeof(payload));
    source.key_id[0] ^= 0x01U;
    if (aes256_gcm_decrypt(key, &source, payload, sizeof(payload))) {
        fprintf(stderr, "selftest: key id is not protected by the AAD\n");
        goto cleanup;
    }
    source.key_id[0] ^= 0x01U;
    if (!run_erasure_self_test()) {
        fprintf(stderr, "selftest: erasure coding self-test failed\n");
        goto cleanup;
    }
    puts("selftest: frame encoding, SHA-256, AES-256-GCM, AAD binding, "
        "catalogue protection, erasure coding and tamper rejection passed");
    success = 1;

cleanup:
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(payload, sizeof(payload));
    OPENSSL_cleanse(encrypted, sizeof(encrypted));
    OPENSSL_cleanse(digest, sizeof(digest));
    OPENSSL_cleanse(wire, sizeof(wire));
    return success;
}

static int check_key_file(const char *path)
{
    unsigned char key[32];
    if (!load_aes256_key(path, key)) {
        return 2;
    }
    OPENSSL_cleanse(key, sizeof(key));
    puts("key: valid 32-byte AES-256 key");
    return 0;
}

static int socket_error_is_transient(void)
{
#ifdef _WIN32
    int code = WSAGetLastError();
    return code == WSAETIMEDOUT || code == WSAEWOULDBLOCK ||
        code == WSAEINPROGRESS || code == WSAEINTR;
#else
    return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR;
#endif
}

/*
 * Limit how long a write may block. This is used for the subscriber sockets:
 * a reader that stops consuming must not be able to stall the relay path of
 * the whole ring.
 */
static void set_socket_send_timeout(icss_socket_t socket, int seconds)
{
#ifdef _WIN32
    DWORD timeout = (DWORD)seconds * 1000U;
    setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO,
        (const char *)&timeout, (int)sizeof(timeout));
#else
    struct timeval timeout;
    timeout.tv_sec = seconds;
    timeout.tv_usec = 0;
    setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
#endif
}

static int socket_send_all(icss_socket_t socket, const unsigned char *data,
    size_t size)
{
    while (size != 0U) {
        int sent = send(socket, (const char *)data,
            size > INT_MAX ? INT_MAX : (int)size, 0);
        if (sent <= 0) {
            /*
             * A timed out write is not necessarily fatal. The subscriber path
             * uses a send timeout so that a slow reader cannot stall the ring,
             * and in that case the write has to be resumed.
             */
            if (sent < 0 && socket_error_is_transient()) {
                continue;
            }
            return 0;
        }
        data += (size_t)sent;
        size -= (size_t)sent;
    }
    return 1;
}

static int socket_recv_all(icss_socket_t socket, unsigned char *data, size_t size)
{
    while (size != 0U) {
        int received = recv(socket, (char *)data,
            size > INT_MAX ? INT_MAX : (int)size, 0);
        if (received <= 0) {
            return 0;
        }
        data += (size_t)received;
        size -= (size_t)received;
    }
    return 1;
}

static void set_socket_timeout(icss_socket_t socket, int seconds)
{
#ifdef _WIN32
    DWORD timeout = (DWORD)seconds * 1000U;
    setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO,
        (const char *)&timeout, (int)sizeof(timeout));
#else
    struct timeval timeout;
    timeout.tv_sec = seconds;
    timeout.tv_usec = 0;
    setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
#endif
}

/*
 * Limit how long a write may block. This is used for the subscriber sockets:
 * a reader that stops consuming must not be able to stall the relay path of
 * the whole ring.
 */
static int parse_endpoint(const char *text, char *host, size_t host_capacity,
    char *port, size_t port_capacity)
{
    const char *separator = strrchr(text, ':');
    size_t host_size;
    if (separator == NULL || separator == text || separator[1] == '\0') {
        return 0;
    }
    host_size = (size_t)(separator - text);
    if (host_size >= host_capacity || strlen(separator + 1) >= port_capacity) {
        return 0;
    }
    memcpy(host, text, host_size);
    host[host_size] = '\0';
    strcpy(port, separator + 1);
    return 1;
}

static icss_socket_t connect_to(const char *host, const char *port)
{
    struct addrinfo hints;
    struct addrinfo *addresses = NULL;
    struct addrinfo *address;
    icss_socket_t result = ICSS_INVALID_SOCKET;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &addresses) != 0) {
        return ICSS_INVALID_SOCKET;
    }
    for (address = addresses; address != NULL; address = address->ai_next) {
        icss_socket_t candidate = socket(address->ai_family,
            address->ai_socktype, address->ai_protocol);
        if (candidate == ICSS_INVALID_SOCKET) {
            continue;
        }
        if (connect(candidate, address->ai_addr,
            (int)address->ai_addrlen) == 0) {
            result = candidate;
            break;
        }
        icss_socket_close(candidate);
    }
    freeaddrinfo(addresses);
    return result;
}

static int read_wire_frame(icss_socket_t socket, icss_frame_header *header,
    uint32_t maximum_payload, unsigned char **payload)
{
    unsigned char wire[ICSS_HEADER_SIZE];
    if (!socket_recv_all(socket, wire, sizeof(wire)) ||
        !decode_frame_header(wire, header, maximum_payload)) {
        return 0;
    }
    *payload = (unsigned char *)malloc(header->payload_size == 0U ? 1U :
        header->payload_size);
    if (*payload == NULL) {
        return 0;
    }
    if (!socket_recv_all(socket, *payload, header->payload_size)) {
        OPENSSL_cleanse(*payload, header->payload_size);
        free(*payload);
        *payload = NULL;
        return 0;
    }
    return 1;
}

static int write_wire_frame(icss_socket_t socket,
    const icss_frame_header *header, const unsigned char *payload)
{
    unsigned char wire[ICSS_HEADER_SIZE];
    return encode_frame_header(header, wire) &&
        socket_send_all(socket, wire, sizeof(wire)) &&
        socket_send_all(socket, payload, header->payload_size);
}

static void notify_subscribers(const icss_frame_header *header,
    const unsigned char *payload)
{
    icss_subscriber **cursor;
    pthread_mutex_lock(&subscribers_mutex);
    cursor = &subscribers;
    while (*cursor != NULL) {
        icss_subscriber *subscriber = *cursor;
        if (subscriber->ring_id == header->ring_id &&
            memcmp(subscriber->file_hash, header->file_hash, 32) == 0) {
            if (!write_wire_frame(subscriber->socket, header, payload)) {
                *cursor = subscriber->next;
                icss_socket_close(subscriber->socket);
                free(subscriber);
                continue;
            }
        }
        cursor = &subscriber->next;
    }
    pthread_mutex_unlock(&subscribers_mutex);
}

/*
 * Backpressure signalling.
 *
 * Direction: the node whose queue is filling up is the one that *receives* the
 * frames, so it has to ask its upstream neighbour - the peer that feeds it -
 * to stop sending. The upstream then stops writing into this node and, once
 * this node has drained, is told to continue. The signal therefore travels
 * backwards along the ring, hop by hop, so a slow node throttles the whole
 * circulation instead of overflowing a single buffer.
 */
static void send_backpressure_signal(icss_socket_t socket, char operation)
{
    unsigned char control[ICSS_CONTROL_SIZE] = {'I','C','S','F',0,0,0,0};
    control[4] = (unsigned char)operation;
    put_u16(control + 6, node_ring_id);
    (void)socket_send_all(socket, control, sizeof(control));
}

/*
 * Evaluate the local queue watermarks. When the queue is too full this node
 * asks its upstream neighbour to pause, and once the queue drains it lets the
 * upstream continue.
 */
static void update_backpressure(void)
{
    uint32_t used;
    uint32_t high;
    uint32_t low;
    int should_pause;
    int was_paused;
    icss_socket_t upstream;
    pthread_mutex_lock(&queue_mutex);
    used = node_queue.count;
    was_paused = node_queue.paused;
    high = (node_queue.capacity * ICSS_PAUSE_HIGH_PERCENT) / 100U;
    low = (node_queue.capacity * ICSS_RESUME_LOW_PERCENT) / 100U;
    if (!was_paused && used >= high) {
        node_queue.paused = 1;
        should_pause = 1;
    } else if (was_paused && used <= low) {
        node_queue.paused = 0;
        should_pause = 0;
    } else {
        should_pause = -1;
    }
    pthread_mutex_unlock(&queue_mutex);
    if (should_pause == -1) return;
    pthread_mutex_lock(&downstream_mutex);
    upstream = upstream_socket;
    pthread_mutex_unlock(&downstream_mutex);
    if (upstream == ICSS_INVALID_SOCKET) return;
    send_backpressure_signal(upstream, should_pause ? ICSS_OP_PAUSE : ICSS_OP_RESUME);
    pthread_mutex_lock(&stats_mutex);
    if (should_pause) ++node_pause_events;
    else ++node_resume_events;
    pthread_mutex_unlock(&stats_mutex);
    fprintf(stderr, "icss: backpressure %s (queue %u/%u)\n",
        should_pause ? "pause" : "resume", (unsigned int)used,
        (unsigned int)node_queue.capacity);
}

/*
 * Enqueue a frame for the downstream neighbour.
 *
 * The queue holds every frame that is currently in flight. A dataset that is
 * larger than the initial queue depth therefore has to be able to grow the
 * queue, otherwise the frames that do not fit would be dropped and the read
 * side could never assemble the dataset. The queue is therefore resized on
 * demand, up to a hard limit. Blocking instead of growing is not an option:
 * a stalled relay would stall the whole ring.
 */
static int queue_grow_locked(void)
{
    uint32_t new_capacity;
    icss_queue_item *items;
    uint32_t index;
    if (node_queue.capacity >= ICSS_QUEUE_MAX_FRAMES) {
        return 0;
    }
    new_capacity = node_queue.capacity < 2U ? 2U : node_queue.capacity * 2U;
    if (new_capacity > ICSS_QUEUE_MAX_FRAMES) {
        new_capacity = ICSS_QUEUE_MAX_FRAMES;
    }
    items = (icss_queue_item *)calloc(new_capacity, sizeof(*items));
    if (items == NULL) {
        return 0;
    }
    /* Re-linearise the ring buffer so that the head ends up at index 0. */
    for (index = 0; index < node_queue.count; ++index) {
        uint32_t slot = (node_queue.head + index) % node_queue.capacity;
        items[index] = node_queue.items[slot];
    }
    free(node_queue.items);
    node_queue.items = items;
    node_queue.capacity = new_capacity;
    node_queue.head = 0;
    return 1;
}

static int queue_downstream_frame(const icss_frame_header *header,
    unsigned char *payload)
{
    int queued = 0;
    int attempt;
    /*
     * The queue has to absorb the frames that are in flight. If it is full the
     * frame is retried for a while instead of being dropped, because a dropped
     * frame would leave a hole in the dataset that the read side can never
     * fill. The backpressure signal tells the upstream to stop sending, so the
     * queue drains again shortly.
     */
    for (attempt = 0; attempt < 100; ++attempt) {
        pthread_mutex_lock(&queue_mutex);
        if (node_queue.count == node_queue.capacity) {
            (void)queue_grow_locked();
        }
        if (node_queue.count < node_queue.capacity) {
            uint32_t tail = (node_queue.head + node_queue.count) % node_queue.capacity;
            node_queue.items[tail].header = *header;
            node_queue.items[tail].payload = payload;
            ++node_queue.count;
            queued = 1;
        }
        pthread_mutex_unlock(&queue_mutex);
        if (queued) {
            return 1;
        }
        {
            struct timespec pause;
            pause.tv_sec = 0;
            pause.tv_nsec = 50000000L;
            nanosleep(&pause, NULL);
        }
    }
    pthread_mutex_lock(&stats_mutex);
    ++node_dropped_frames;
    pthread_mutex_unlock(&stats_mutex);
    fprintf(stderr, "icss: downstream queue full, frame dropped\n");
    return 0;
}

/*
 * Reader thread on the downstream socket. The next hop answers with PAUS and
 * RESU control frames when its own queue fills up, so this node can slow down
 * before its own queue overflows.
 */
static void *downstream_reader(void *argument)
{
    (void)argument;
    while (node_running) {
        icss_socket_t current;
        unsigned char magic[4];
        pthread_mutex_lock(&downstream_mutex);
        current = downstream_socket;
        pthread_mutex_unlock(&downstream_mutex);
        if (current == ICSS_INVALID_SOCKET) {
            struct timespec pause;
            pause.tv_sec = 0;
            pause.tv_nsec = 5000000L;
            nanosleep(&pause, NULL);
            continue;
        }
        if (!socket_recv_all(current, magic, sizeof(magic))) {
            pthread_mutex_lock(&downstream_mutex);
            if (downstream_socket == current) {
                icss_socket_close(downstream_socket);
                downstream_socket = ICSS_INVALID_SOCKET;
            }
            pthread_mutex_unlock(&downstream_mutex);
            continue;
        }
        if (memcmp(magic, ICSS_CONTROL_MAGIC, 4) == 0) {
            unsigned char body[4];
            if (!socket_recv_all(current, body, sizeof(body))) {
                continue;
            }
            if (body[0] == ICSS_OP_PAUSE) {
                node_outbound_paused = 1;
            } else if (body[0] == ICSS_OP_RESUME) {
                node_outbound_paused = 0;
            }
        }
    }
    return NULL;
}

/*
 * Writer thread: moves queued frames to the downstream socket and releases the
 * buffer immediately afterwards. This keeps the relay path non-blocking.
 */
static void *downstream_writer(void *argument)
{
    (void)argument;
    while (node_running) {
        icss_queue_item item;
        int have_item = 0;
        pthread_mutex_lock(&queue_mutex);
        if (node_queue.count > 0U) {
            item = node_queue.items[node_queue.head];
            node_queue.items[node_queue.head].payload = NULL;
            node_queue.head = (node_queue.head + 1U) % node_queue.capacity;
            --node_queue.count;
            have_item = 1;
        }
        pthread_mutex_unlock(&queue_mutex);
        if (have_item) {
            int sent = 0;
            /* Respect a pause requested by the next hop. */
            while (node_running && node_outbound_paused) {
                struct timespec pause;
                pause.tv_sec = 0;
                pause.tv_nsec = 5000000L;
                nanosleep(&pause, NULL);
            }
            pthread_mutex_lock(&downstream_mutex);
            if (downstream_socket != ICSS_INVALID_SOCKET) {
                sent = write_wire_frame(downstream_socket, &item.header,
                    item.payload);
                if (!sent) {
                    icss_socket_close(downstream_socket);
                    downstream_socket = ICSS_INVALID_SOCKET;
                }
            }
            pthread_mutex_unlock(&downstream_mutex);
            if (sent) {
                pthread_mutex_lock(&stats_mutex);
                ++node_forwarded;
                pthread_mutex_unlock(&stats_mutex);
            }
            OPENSSL_cleanse(item.payload, item.header.payload_size);
            free(item.payload);
            update_backpressure();
        } else {
            struct timespec pause;
            pause.tv_sec = 0;
            pause.tv_nsec = 1000000L;
            nanosleep(&pause, NULL);
        }
    }
    return NULL;
}

/*
 * Relay one frame towards the downstream neighbour.
 *
 * Ownership of the payload buffer is transferred to the queue on success: the
 * caller must not free it in that case, because the writer thread still owns
 * the buffer until it has been written to the downstream socket. On failure
 * the caller keeps the ownership and releases the buffer.
 */
static int forward_frame(icss_frame_header *header, unsigned char *payload)
{
    unsigned char digest[32];
    int result;
    if (header->ring_id != node_ring_id ||
        !sha256_buffer(payload, header->payload_size, digest) ||
        memcmp(digest, header->payload_hash, sizeof(digest)) != 0) {
        fprintf(stderr, "icss: dropped frame with invalid ring or payload hash\n");
        OPENSSL_cleanse(digest, sizeof(digest));
        return 0;
    }
    OPENSSL_cleanse(digest, sizeof(digest));
    if (!record_frame_metadata(header)) {
        fprintf(stderr, "icss: unable to update hash metadata index\n");
        return 0;
    }
    notify_subscribers(header, payload);
    /* Advance the hop counter and refresh the TTL so the frame keeps looping
       forever as long as the ring is alive. */
    ++header->sequence;
    if (header->ttl > 1U) {
        --header->ttl;
    } else {
        header->ttl = 1U;
    }
    result = queue_downstream_frame(header, payload);
    if (!result) {
        fprintf(stderr, "icss: downstream queue full, frame dropped\n");
    }
    return result;
}

static void remove_subscriber(icss_socket_t socket)
{
    icss_subscriber **cursor;
    pthread_mutex_lock(&subscribers_mutex);
    cursor = &subscribers;
    while (*cursor != NULL) {
        if ((*cursor)->socket == socket) {
            icss_subscriber *removed = *cursor;
            *cursor = removed->next;
            free(removed);
            break;
        }
        cursor = &(*cursor)->next;
    }
    pthread_mutex_unlock(&subscribers_mutex);
}

/*
 * Read the next item from a peer connection. Data frames and backpressure
 * control frames share the same byte stream, so the 4 byte magic decides how
 * the remainder is interpreted.
 */
static int read_frame_or_control(icss_socket_t socket, icss_frame_header *header,
    unsigned char **payload, unsigned char *control)
{
    unsigned char magic[4];
    if (!socket_recv_all(socket, magic, sizeof(magic))) {
        return 0;
    }
    if (memcmp(magic, ICSS_MAGIC, 4) == 0) {
        unsigned char rest[ICSS_HEADER_SIZE - 4U];
        if (!socket_recv_all(socket, rest, sizeof(rest)) ||
            !decode_frame_header_prefix(magic, rest, header, node_chunk_size)) {
            return 0;
        }
        *payload = (unsigned char *)malloc(header->payload_size == 0U ? 1U :
            header->payload_size);
        if (*payload == NULL) {
            return 0;
        }
        if (!socket_recv_all(socket, *payload, header->payload_size)) {
            OPENSSL_cleanse(*payload, header->payload_size);
            free(*payload);
            *payload = NULL;
            return 0;
        }
        return 1;
    }
    if (memcmp(magic, ICSS_CONTROL_MAGIC, 4) == 0) {
        if (!socket_recv_all(socket, control + 4, 4U)) {
            return 0;
        }
        return 2;
    }
    return 0;
}

static void *connection_worker(void *argument)
{
    icss_connection *connection = (icss_connection *)argument;
    icss_socket_t client = connection->socket;
    unsigned char control[ICSS_CONTROL_SIZE];
    free(connection);
    if (!socket_recv_all(client, control, sizeof(control))) {
        icss_socket_close(client);
        return NULL;
    }
    if (memcmp(control, "ICSP", 4) == 0) {
        /* This peer is the upstream neighbour: it feeds us with frames. */
        int inbound_paused = 0;
        pthread_mutex_lock(&downstream_mutex);
        upstream_socket = client;
        pthread_mutex_unlock(&downstream_mutex);
        while (node_running) {
            icss_frame_header header;
            unsigned char *payload = NULL;
            unsigned char peer_control[ICSS_CONTROL_SIZE];
            int kind;
            if (inbound_paused) {
                struct timespec pause;
                pause.tv_sec = 0;
                pause.tv_nsec = 5000000L;
                nanosleep(&pause, NULL);
                continue;
            }
            memset(peer_control, 0, sizeof(peer_control));
            kind = read_frame_or_control(client, &header, &payload, peer_control);
            if (kind == 0) {
                break;
            }
            if (kind == 2) {
                if (peer_control[4] == ICSS_OP_PAUSE) {
                    inbound_paused = 1;
                } else if (peer_control[4] == ICSS_OP_RESUME) {
                    inbound_paused = 0;
                }
                continue;
            }
            if (!forward_frame(&header, payload)) {
                OPENSSL_cleanse(payload, header.payload_size);
                free(payload);
                break;
            }
            /* On success the queue owns the buffer and releases it. */
        }
        pthread_mutex_lock(&downstream_mutex);
        if (upstream_socket == client) {
            upstream_socket = ICSS_INVALID_SOCKET;
        }
        pthread_mutex_unlock(&downstream_mutex);
        icss_socket_close(client);
        return NULL;
    }
    if (memcmp(control, "ICSC", 4) != 0) {
        icss_socket_close(client);
        return NULL;
    }
    if (control[4] == ICSS_OP_INJECT) {
        uint16_t ring_id = get_u16(control + 6);
        if (ring_id != node_ring_id) {
            icss_socket_close(client);
            return NULL;
        }
        while (node_running) {
            icss_frame_header header;
            unsigned char *payload = NULL;
            int ok = read_wire_frame(client, &header, node_chunk_size, &payload);
            if (!ok) {
                break;
            }
            if (!forward_frame(&header, payload)) {
                OPENSSL_cleanse(payload, header.payload_size);
                free(payload);
                break;
            }
            /* On success the queue owns the buffer and releases it. */
        }
    } else if (control[4] == ICSS_OP_FETCH) {
        unsigned char file_hash[32];
        unsigned char name[ICSS_NAME_SIZE];
        unsigned char key_id[ICSS_KEY_ID_SIZE];
        unsigned char control_flags = control[5];
        int use_name = (control_flags & ICSS_FETCH_FLAG_NAME) != 0;
        int have_key_id = (control_flags & ICSS_FETCH_FLAG_KEYID) != 0;
        icss_subscriber *subscriber = NULL;

        if (use_name) {
            if (!socket_recv_all(client, name, ICSS_NAME_SIZE) ||
                (have_key_id && !socket_recv_all(client, key_id, ICSS_KEY_ID_SIZE))) {
                icss_socket_close(client);
                return NULL;
            }
            name[ICSS_NAME_SIZE - 1] = '\0';
            if (!lookup_hash_by_name((const char *)name,
                have_key_id ? key_id : NULL, have_key_id, file_hash)) {
                send_control(client, ICSS_OP_ERROR, node_ring_id, 0U);
                icss_socket_close(client);
                return NULL;
            }
        } else {
            if (!socket_recv_all(client, file_hash, sizeof(file_hash))) {
                icss_socket_close(client);
                return NULL;
            }
        }
        if (get_u16(control + 6) != node_ring_id) {
            icss_socket_close(client);
            return NULL;
        }
        pthread_mutex_lock(&index_mutex);
        {
            /*
             * The index is a pure hash catalogue: it answers whether this node
             * has seen the dataset at all. The reader decides on its own how
             * many shards it needs, because with erasure coding a group can be
             * reconstructed from k of its k + m shards. The lookup has to accept
             * every layout of the file, because the reader does not know the
             * frame count yet.
             */
            int complete = index_has_seen_chunks(file_hash);
            pthread_mutex_unlock(&index_mutex);
            if (!complete) {
                (void)socket_send_all(client, (const unsigned char *)"MISS", 4U);
                OPENSSL_cleanse(file_hash, sizeof(file_hash));
                icss_socket_close(client);
                return NULL;
            }
        }
        subscriber = (icss_subscriber *)calloc(1, sizeof(*subscriber));
        if (subscriber == NULL) {
            icss_socket_close(client);
            return NULL;
        }
        subscriber->socket = client;
        subscriber->ring_id = node_ring_id;
        memcpy(subscriber->file_hash, file_hash, sizeof(file_hash));
        pthread_mutex_lock(&subscribers_mutex);
        subscriber->next = subscribers;
        subscribers = subscriber;
        pthread_mutex_unlock(&subscribers_mutex);
        set_socket_timeout(client, ICSS_SUBSCRIBER_POLL_SECONDS);
        set_socket_send_timeout(client, ICSS_SUBSCRIBER_POLL_SECONDS);
        if (!socket_send_all(client, (const unsigned char *)"ACKF", 4U)) {
            remove_subscriber(client);
            icss_socket_close(client);
            return NULL;
        }
        /*
         * The subscriber socket is polled to detect a closed reader. A read
         * timeout is not a disconnect, so the subscription stays active until
         * the peer really goes away. This matters because the shards of a
         * large dataset may need more time to circulate than the poll
         * interval.
         */
        while (node_running) {
            unsigned char byte;
            int received = recv(client, (char *)&byte, 1, 0);
            if (received == 0) {
                break;
            }
            if (received < 0) {
                /* A timeout only means the reader is idle, not that it left. */
                if (socket_error_is_transient()) {
                    continue;
                }
                break;
            }
        }
        remove_subscriber(client);
        OPENSSL_cleanse(file_hash, sizeof(file_hash));
    } else if (control[4] == ICSS_OP_STATUS) {
        char *response;
        size_t response_capacity = 512U;
        size_t response_used = 0U;
        uint64_t forwarded;
        uint64_t dropped;
        uint32_t queued;
        uint32_t queue_capacity;
        uint32_t online_nodes;
        unsigned long long uptime;
        uint32_t permanent_files;
        char upstream_text[300] = "unknown";
        pthread_mutex_lock(&stats_mutex);
        forwarded = node_forwarded;
        dropped = node_dropped_frames;
        pthread_mutex_unlock(&stats_mutex);
        pthread_mutex_lock(&queue_mutex);
        queued = node_queue.count;
        queue_capacity = node_queue.capacity;
        pthread_mutex_unlock(&queue_mutex);
        pthread_mutex_lock(&index_mutex);
        permanent_files = node_permanent_files;
        if (control[5] != 0U && permanent_files <= 100000U) {
            response_capacity += (size_t)permanent_files * 110U;
        }
        pthread_mutex_unlock(&index_mutex);
        online_nodes = (uint32_t)(node_peer_count == 0U ? 1U : node_peer_count);
        {
            /* Report the peer that feeds this node, derived from the sorted
               peer table so the value matches the ring topology. */
            size_t index;
            uint32_t self_port = (uint32_t)strtoul(node_listen_port, NULL, 10);
            for (index = 0; index < node_peer_count; ++index) {
                if (node_peers[index].ip_address == node_advertise_ip &&
                    node_peers[index].tcp_port == (uint16_t)self_port) {
                    size_t previous = (index + node_peer_count - 1U) % node_peer_count;
                    struct in_addr address;
                    address.s_addr = node_peers[previous].ip_address;
                    snprintf(upstream_text, sizeof(upstream_text), "%s:%u",
                        inet_ntoa(address), (unsigned int)node_peers[previous].tcp_port);
                    break;
                }
            }
        }
        uptime = (unsigned long long)(time(NULL) - node_started);
        response = (char *)malloc(response_capacity);
        if (response != NULL) {
            int count = snprintf(response, response_capacity,
                "{\"online_nodes\":%u,\"upstream\":\"%s\","
                "\"downstream\":\"%s:%s\",\"ring_id\":%u,"
                "\"chunk_size\":%u,\"queue_usage\":%u,\"queue_capacity\":%u,"
                "\"total_forwarded\":%llu,\"dropped_frames\":%llu,"
                "\"permanent_files\":%u",
                online_nodes, upstream_text,
                node_next_host, node_next_port, (unsigned int)node_ring_id,
                (unsigned int)node_chunk_size, (unsigned int)queued,
                (unsigned int)queue_capacity, (unsigned long long)forwarded,
                (unsigned long long)dropped, (unsigned int)permanent_files);
            if (count > 0) response_used = (size_t)count;
            if (control[5] != 0U && response_used < response_capacity) {
                FILE *index_file = fopen(node_index_path, "rb");
                unsigned char index_header[12];
                uint32_t count_files = 0;
                uint32_t file_number;
                response_used += (size_t)snprintf(response + response_used,
                    response_capacity - response_used, ",\"files\":[");
                if (index_file != NULL &&
                    fread(index_header, 1, sizeof(index_header), index_file) == sizeof(index_header) &&
                    memcmp(index_header, "ICIX", 4) == 0 &&
                    get_u16(index_header + 6) == node_ring_id) {
                    count_files = get_u32(index_header + 8);
                    for (file_number = 0; file_number < count_files; ++file_number) {
                        unsigned char record[52];
                        uint32_t chunk_index;
                        if (fread(record, 1, sizeof(record), index_file) != sizeof(record)) break;
                        if (file_number != 0U) {
                            response_used += (size_t)snprintf(response + response_used,
                                response_capacity - response_used, ",");
                        }
                        response_used += (size_t)snprintf(response + response_used,
                            response_capacity - response_used,
                            "{\"sha256\":\"");
                        for (chunk_index = 0; chunk_index < 32U; ++chunk_index) {
                            response_used += (size_t)snprintf(response + response_used,
                                response_capacity - response_used, "%02x", record[chunk_index]);
                        }
                        response_used += (size_t)snprintf(response + response_used,
                            response_capacity - response_used,
                            "\",\"total_chunks\":%u}", get_u32(record + 32));
                        for (chunk_index = 0; chunk_index < get_u32(record + 32); ++chunk_index) {
                            unsigned char hash[32];
                            if (fread(hash, 1, sizeof(hash), index_file) != sizeof(hash)) break;
                        }
                        if (response_used + 128U >= response_capacity) break;
                    }
                }
                if (index_file != NULL) fclose(index_file);
                if (response_used < response_capacity) {
                    response_used += (size_t)snprintf(response + response_used,
                        response_capacity - response_used, "]");
                }
            }
            if (response_used < response_capacity) {
                response_used += (size_t)snprintf(response + response_used,
                    response_capacity - response_used,
                    ",\"uptime\":%llu}\n", uptime);
                (void)socket_send_all(client, (const unsigned char *)response,
                    response_used);
            }
            free(response);
        }
    } else if (control[4] == ICSS_OP_LIST) {
        /*
         * Catalogue query. The node answers with every dataset it knows about,
         * including the human readable name, the content hash and the key
         * fingerprint. A client that holds a key can compare the fingerprint
         * and thereby learn which datasets it is actually able to decrypt.
         */
        char *response;
        size_t response_capacity;
        size_t response_used = 0;
        icss_index_entry *entry;
        uint32_t entries = 0;
        pthread_mutex_lock(&index_mutex);
        for (entry = index_entries; entry != NULL; entry = entry->next) {
            if (entry->chunk_seen != NULL) ++entries;
        }
        response_capacity = 256U + (size_t)entries * 320U;
        pthread_mutex_unlock(&index_mutex);
        response = (char *)malloc(response_capacity);
        if (response != NULL) {
            int count = snprintf(response, response_capacity, "{\"ring_id\":%u,\"files\":[",
                (unsigned int)node_ring_id);
            if (count > 0) response_used = (size_t)count;
            pthread_mutex_lock(&index_mutex);
            for (entry = index_entries; entry != NULL; entry = entry->next) {
                uint32_t index;
                int complete = 1;
                if (entry->chunk_seen == NULL) continue;
                for (index = 0; index < entry->total_chunks; ++index) {
                    if (!entry->chunk_seen[index]) {
                        complete = 0;
                        break;
                    }
                }
                if (!complete) continue;
                if (response_used + 320U >= response_capacity) break;
                if (response_used > 24U) {
                    response_used += (size_t)snprintf(response + response_used,
                        response_capacity - response_used, ",");
                }
                response_used += (size_t)snprintf(response + response_used,
                    response_capacity - response_used, "{\"name\":\"%s\",\"sha256\":\"",
                    entry->name);
                for (index = 0; index < 32U; ++index) {
                    response_used += (size_t)snprintf(response + response_used,
                        response_capacity - response_used, "%02x", entry->file_hash[index]);
                }
                response_used += (size_t)snprintf(response + response_used,
                    response_capacity - response_used, "\",\"encrypted\":%s,\"key_id\":\"",
                    entry->encrypted ? "true" : "false");
                for (index = 0; index < ICSS_KEY_ID_SIZE; ++index) {
                    response_used += (size_t)snprintf(response + response_used,
                        response_capacity - response_used, "%02x", entry->key_id[index]);
                }
                response_used += (size_t)snprintf(response + response_used,
                    response_capacity - response_used,
                    "\",\"total_chunks\":%u,\"first_seen\":%llu,\"last_seen\":%llu}",
                    entry->total_chunks,
                    (unsigned long long)entry->first_seen,
                    (unsigned long long)entry->last_seen);
            }
            pthread_mutex_unlock(&index_mutex);
            if (response_used + 32U < response_capacity) {
                response_used += (size_t)snprintf(response + response_used,
                    response_capacity - response_used, "]}\n");
                (void)socket_send_all(client, (const unsigned char *)response,
                    response_used);
            }
            free(response);
        }
    }
    icss_socket_close(client);
    return NULL;
}

static int socket_runtime_start(void)
{
#ifdef _WIN32
    WSADATA data;
    return WSAStartup(MAKEWORD(2, 2), &data) == 0;
#else
    return 1;
#endif
}

static void socket_runtime_stop(void)
{
#ifdef _WIN32
    WSACleanup();
#endif
}

static icss_socket_t create_listener(const char *port)
{
    struct addrinfo hints;
    struct addrinfo *addresses = NULL;
    struct addrinfo *address;
    icss_socket_t result = ICSS_INVALID_SOCKET;
    int option = 1;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    if (getaddrinfo(NULL, port, &hints, &addresses) != 0) {
        return ICSS_INVALID_SOCKET;
    }
    for (address = addresses; address != NULL; address = address->ai_next) {
        icss_socket_t candidate = socket(address->ai_family,
            address->ai_socktype, address->ai_protocol);
        if (candidate == ICSS_INVALID_SOCKET) {
            continue;
        }
        setsockopt(candidate, SOL_SOCKET, SO_REUSEADDR,
            (const char *)&option, (int)sizeof(option));
        if (bind(candidate, address->ai_addr, (int)address->ai_addrlen) == 0 &&
            listen(candidate, 128) == 0) {
            result = candidate;
            break;
        }
        icss_socket_close(candidate);
    }
    freeaddrinfo(addresses);
    return result;
}

static int compare_peers(const void *left, const void *right)
{
    const icss_peer *a = (const icss_peer *)left;
    const icss_peer *b = (const icss_peer *)right;
    uint32_t ip_a = ntohl(a->ip_address);
    uint32_t ip_b = ntohl(b->ip_address);
    if (ip_a != ip_b) return ip_a < ip_b ? -1 : 1;
    if (a->tcp_port != b->tcp_port) return a->tcp_port < b->tcp_port ? -1 : 1;
    return 0;
}

static int setup_discovery_socket(uint16_t port)
{
    struct sockaddr_in local_address;
    int option = 1;
    discovery_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (discovery_socket == ICSS_INVALID_SOCKET) return 0;
    setsockopt(discovery_socket, SOL_SOCKET, SO_REUSEADDR,
        (const char *)&option, (int)sizeof(option));
    setsockopt(discovery_socket, SOL_SOCKET, SO_BROADCAST,
        (const char *)&option, (int)sizeof(option));
    memset(&local_address, 0, sizeof(local_address));
    local_address.sin_family = AF_INET;
    local_address.sin_addr.s_addr = htonl(INADDR_ANY);
    local_address.sin_port = htons(port);
    if (bind(discovery_socket, (struct sockaddr *)&local_address,
        (int)sizeof(local_address)) != 0) {
        icss_socket_close(discovery_socket);
        discovery_socket = ICSS_INVALID_SOCKET;
        return 0;
    }
    return 1;
}

static uint32_t determine_advertise_ip(uint16_t discovery_port)
{
    icss_socket_t probe;
    struct sockaddr_in target;
    struct sockaddr_in local;
    socklen_t local_size = (socklen_t)sizeof(local);
    probe = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (probe == ICSS_INVALID_SOCKET) return htonl(INADDR_LOOPBACK);
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    target.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    target.sin_port = htons(discovery_port);
    if (connect(probe, (struct sockaddr *)&target, (int)sizeof(target)) != 0 ||
        getsockname(probe, (struct sockaddr *)&local, &local_size) != 0 ||
        local.sin_addr.s_addr == htonl(INADDR_ANY)) {
        target.sin_addr.s_addr = inet_addr("8.8.8.8");
        target.sin_port = htons(53U);
        if (connect(probe, (struct sockaddr *)&target, (int)sizeof(target)) != 0 ||
            getsockname(probe, (struct sockaddr *)&local, &local_size) != 0) {
            icss_socket_close(probe);
            return htonl(INADDR_LOOPBACK);
        }
    }
    icss_socket_close(probe);
    return local.sin_addr.s_addr;
}

static void upsert_peer(uint32_t ip_address, uint16_t tcp_port,
    uint16_t ring_id, const unsigned char node_id[16])
{
    size_t index;
    icss_peer *peer = NULL;
    for (index = 0; index < node_peer_count; ++index) {
        if (node_peers[index].ip_address == ip_address &&
            node_peers[index].tcp_port == tcp_port &&
            node_peers[index].ring_id == ring_id) {
            peer = &node_peers[index];
            break;
        }
    }
    if (peer == NULL) {
        if (node_peer_count < ICSS_MAX_PEERS) {
            peer = &node_peers[node_peer_count++];
        } else {
            size_t oldest = 0;
            for (index = 1; index < node_peer_count; ++index) {
                if (node_peers[index].last_seen < node_peers[oldest].last_seen) {
                    oldest = index;
                }
            }
            peer = &node_peers[oldest];
        }
    }
    peer->ip_address = ip_address;
    peer->tcp_port = tcp_port;
    peer->ring_id = ring_id;
    peer->last_seen = time(NULL);
    memcpy(peer->node_id, node_id, sizeof(peer->node_id));
}

static void announce_node(void)
{
    unsigned char packet[ICSS_DISCOVERY_SIZE];
    struct sockaddr_in broadcast_address;
    unsigned short tcp_port = (unsigned short)strtoul(node_listen_port, NULL, 10);
    unsigned char node_id[16];
    if (tcp_port == 0U || discovery_socket == ICSS_INVALID_SOCKET) return;
    memcpy(packet, "ICSD", 4);
    make_node_id(node_advertise_ip, tcp_port, node_id);
    memcpy(packet + 4, node_id, sizeof(node_id));
    memcpy(packet + 20, &node_advertise_ip, 4);
    put_u16(packet + 24, tcp_port);
    put_u16(packet + 26, node_ring_id);
    put_u64(packet + 28, (uint64_t)time(NULL));
    memset(&broadcast_address, 0, sizeof(broadcast_address));
    broadcast_address.sin_family = AF_INET;
    broadcast_address.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    broadcast_address.sin_port = htons(node_discovery_port);
    (void)sendto(discovery_socket, (const char *)packet, sizeof(packet), 0,
        (struct sockaddr *)&broadcast_address, (int)sizeof(broadcast_address));
    upsert_peer(node_advertise_ip, tcp_port, node_ring_id, node_id);
    node_last_heartbeat = time(NULL);
    OPENSSL_cleanse(node_id, sizeof(node_id));
}

static void receive_discovery(void)
{
    unsigned char packet[ICSS_DISCOVERY_SIZE];
    struct sockaddr_in source;
    socklen_t source_size = (socklen_t)sizeof(source);
    int received = recvfrom(discovery_socket, (char *)packet, sizeof(packet), 0,
        (struct sockaddr *)&source, &source_size);
    unsigned char expected_id[16];
    uint32_t advertised_ip;
    uint16_t tcp_port;
    uint16_t ring_id;
    uint64_t timestamp;
    uint64_t now = (uint64_t)time(NULL);
    if (received != (int)sizeof(packet) || memcmp(packet, "ICSD", 4) != 0) return;
    memcpy(&advertised_ip, packet + 20, 4);
    tcp_port = get_u16(packet + 24);
    ring_id = get_u16(packet + 26);
    timestamp = get_u64(packet + 28);
    if (ring_id != node_ring_id || tcp_port == 0U ||
        advertised_ip != source.sin_addr.s_addr ||
        (timestamp > now ? timestamp - now : now - timestamp) > ICSS_PEER_TIMEOUT) {
        return;
    }
    make_node_id(advertised_ip, tcp_port, expected_id);
    if (memcmp(expected_id, packet + 4, sizeof(expected_id)) != 0) {
        OPENSSL_cleanse(expected_id, sizeof(expected_id));
        return;
    }
    upsert_peer(advertised_ip, tcp_port, ring_id, packet + 4);
    OPENSSL_cleanse(expected_id, sizeof(expected_id));

    /*
     * Reply to the discovery requester with our own heartbeat so that
     * discover_ring_peers (which does not know our address yet) can learn
     * about this node and add it to the peer list.
     */
    {
        unsigned char response[ICSS_DISCOVERY_SIZE];
        unsigned char self_id[16];
        struct sockaddr_in target;
        memset(&target, 0, sizeof(target));
        target.sin_family = AF_INET;
        target.sin_addr = source.sin_addr;
        target.sin_port = source.sin_port;

        make_node_id(node_advertise_ip,
            (uint16_t)strtoul(node_listen_port, NULL, 10), self_id);
        memcpy(response, "ICSD", 4);
        memcpy(response + 4, self_id, sizeof(self_id));
        memcpy(response + 20, &node_advertise_ip, 4);
        put_u16(response + 24, (uint16_t)strtoul(node_listen_port, NULL, 10));
        put_u16(response + 26, node_ring_id);
        put_u64(response + 28, (uint64_t)time(NULL));
        OPENSSL_cleanse(self_id, sizeof(self_id));
        (void)sendto(discovery_socket, (const char *)response, sizeof(response), 0,
            (struct sockaddr *)&target, (int)sizeof(target));
    }
}

static void update_topology(void)
{
    size_t read_index;
    size_t write_index = 0;
    size_t self_index = 0;
    icss_peer self;
    icss_peer next_peer;
    char next_host[INET_ADDRSTRLEN];
    char next_port[16];
    time_t now = time(NULL);
    for (read_index = 0; read_index < node_peer_count; ++read_index) {
        if (now - node_peers[read_index].last_seen <= ICSS_PEER_TIMEOUT &&
            node_peers[read_index].ring_id == node_ring_id) {
            node_peers[write_index] = node_peers[read_index];
            ++write_index;
        }
    }
    node_peer_count = write_index;
    memset(&self, 0, sizeof(self));
    self.ip_address = node_advertise_ip;
    self.tcp_port = (uint16_t)strtoul(node_listen_port, NULL, 10);
    self.ring_id = node_ring_id;
    self.last_seen = now;
    make_node_id(self.ip_address, self.tcp_port, self.node_id);
    upsert_peer(self.ip_address, self.tcp_port, self.ring_id, self.node_id);
    qsort(node_peers, node_peer_count, sizeof(node_peers[0]), compare_peers);
    for (read_index = 0; read_index < node_peer_count; ++read_index) {
        if (node_peers[read_index].ip_address == self.ip_address &&
            node_peers[read_index].tcp_port == self.tcp_port) {
            self_index = read_index;
            break;
        }
    }
    if (node_peer_count == 0U) return;
    next_peer = node_peers[(self_index + 1U) % node_peer_count];
    {
        struct in_addr address;
        address.s_addr = next_peer.ip_address;
        if (inet_ntop(AF_INET, &address, next_host, sizeof(next_host)) == NULL) return;
    }
    snprintf(next_port, sizeof(next_port), "%u", (unsigned int)next_peer.tcp_port);
    if (strcmp(node_next_host, next_host) == 0 && strcmp(node_next_port, next_port) == 0) {
        return;
    }
    /*
     * Build before break: the connection to the new downstream neighbour is
     * established first. Only when it succeeds is the old connection closed.
     * This keeps the ring uninterrupted during a topology change, because the
     * window in which no downstream link exists is avoided.
     */
    {
        unsigned char handshake[ICSS_CONTROL_SIZE] = {'I','C','S','P',0,0,0,0};
        icss_socket_t candidate = connect_to(next_host, next_port);
        icss_socket_t previous = ICSS_INVALID_SOCKET;
        if (candidate == ICSS_INVALID_SOCKET ||
            !socket_send_all(candidate, handshake, sizeof(handshake))) {
            if (candidate != ICSS_INVALID_SOCKET) {
                icss_socket_close(candidate);
            }
            fprintf(stderr, "icss: cannot reach new downstream %s:%s, keeping old link\n",
                next_host, next_port);
            return;
        }
        pthread_mutex_lock(&downstream_mutex);
        previous = downstream_socket;
        downstream_socket = candidate;
        pthread_mutex_unlock(&downstream_mutex);
        if (previous != ICSS_INVALID_SOCKET) {
            icss_socket_close(previous);
        }
        strcpy(node_next_host, next_host);
        strcpy(node_next_port, next_port);
        fprintf(stderr, "icss: topology updated, downstream %s:%s, peers=%u\n",
            node_next_host, node_next_port, (unsigned int)node_peer_count);
    }
}

static void node_signal_handler(int signal_number)
{
    if (signal_number == SIGINT || signal_number == SIGTERM) {
        node_running = 0;
    }
#ifdef SIGUSR1
    else if (signal_number == SIGUSR1) {
        node_status_requested = 1;
    }
#endif
}

static void reconnect_downstream(void)
{
    icss_socket_t candidate;
    unsigned char control[ICSS_CONTROL_SIZE] = {'I','C','S','P',0,0,0,0};
    pthread_mutex_lock(&downstream_mutex);
    if (downstream_socket != ICSS_INVALID_SOCKET) {
        pthread_mutex_unlock(&downstream_mutex);
        return;
    }
    pthread_mutex_unlock(&downstream_mutex);
    candidate = connect_to(node_next_host, node_next_port);
    if (candidate == ICSS_INVALID_SOCKET ||
        !socket_send_all(candidate, control, sizeof(control))) {
        if (candidate != ICSS_INVALID_SOCKET) {
            icss_socket_close(candidate);
        }
        return;
    }
    pthread_mutex_lock(&downstream_mutex);
    if (downstream_socket == ICSS_INVALID_SOCKET && node_running) {
        downstream_socket = candidate;
        candidate = ICSS_INVALID_SOCKET;
    }
    pthread_mutex_unlock(&downstream_mutex);
    if (candidate != ICSS_INVALID_SOCKET) {
        icss_socket_close(candidate);
    }
}

static int node_run(const char *listen_port, const char *next_endpoint,
    uint16_t ring_id, uint32_t chunk_size, const char *index_path,
    uint16_t discovery_port, uint32_t queue_depth)
{
    char next_host[256];
    char next_port[16];
    if (!socket_runtime_start()) {
        fprintf(stderr, "icss: socket initialization failed\n");
        return 2;
    }
    node_ring_id = ring_id;
    node_chunk_size = chunk_size;
    node_discovery_port = discovery_port;
    node_started = time(NULL);
    if (index_path != NULL) {
        if (strlen(index_path) >= sizeof(node_index_path)) {
            fprintf(stderr, "icss: index path is too long\n");
            socket_runtime_stop();
            return 1;
        }
        strcpy(node_index_path, index_path);
    }
    if (!load_index()) {
        socket_runtime_stop();
        return 2;
    }
    if (strlen(listen_port) >= sizeof(node_listen_port)) {
        fprintf(stderr, "icss: listen port string is too long\n");
        socket_runtime_stop();
        return 1;
    }
    strcpy(node_listen_port, listen_port);
    node_manual_next = next_endpoint != NULL;
    if (next_endpoint == NULL) {
        next_host[0] = '\0';
        next_port[0] = '\0';
    } else if (!parse_endpoint(next_endpoint, next_host, sizeof(next_host),
        next_port, sizeof(next_port))) {
        fprintf(stderr, "icss: invalid --next endpoint\n");
        socket_runtime_stop();
        return 1;
    }
    node_next_host[0] = '\0';
    node_next_port[0] = '\0';
    if (node_manual_next) {
        strcpy(node_next_host, next_host);
        strcpy(node_next_port, next_port);
    }
    node_listener = create_listener(listen_port);
    if (node_listener == ICSS_INVALID_SOCKET) {
        fprintf(stderr, "icss: cannot listen on port %s\n", listen_port);
        socket_runtime_stop();
        return 2;
    }
    /* Allocate the bounded downstream queue up front so the relay path does
       not allocate memory while frames are circulating. */
    node_queue_depth = queue_depth;
    node_queue.items = (icss_queue_item *)calloc(node_queue_depth,
        sizeof(icss_queue_item));
    if (node_queue.items == NULL) {
        fprintf(stderr, "icss: cannot allocate downstream queue\n");
        icss_socket_close(node_listener);
        node_listener = ICSS_INVALID_SOCKET;
        socket_runtime_stop();
        return 2;
    }
    node_queue.capacity = node_queue_depth;
    node_queue.head = 0U;
    node_queue.count = 0U;
    node_queue.paused = 0;
    if (!setup_discovery_socket(node_discovery_port)) {
        fprintf(stderr, "icss: cannot bind UDP discovery port %u\n",
            (unsigned int)node_discovery_port);
        icss_socket_close(node_listener);
        node_listener = ICSS_INVALID_SOCKET;
        free(node_queue.items);
        node_queue.items = NULL;
        socket_runtime_stop();
        return 2;
    }
    node_advertise_ip = determine_advertise_ip(node_discovery_port);
    node_running = 1;
    signal(SIGINT, node_signal_handler);
    signal(SIGTERM, node_signal_handler);
#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);
#endif
#ifdef SIGUSR1
    signal(SIGUSR1, node_signal_handler);
#endif
    if (pthread_create(&node_writer_thread, NULL, downstream_writer, NULL) == 0) {
        node_writer_started = 1;
    } else {
        fprintf(stderr, "icss: cannot start downstream writer thread\n");
        icss_socket_close(node_listener);
        node_listener = ICSS_INVALID_SOCKET;
        free(node_queue.items);
        node_queue.items = NULL;
        socket_runtime_stop();
        return 2;
    }
    {
        pthread_t reader_thread;
        if (pthread_create(&reader_thread, NULL, downstream_reader, NULL) == 0) {
            pthread_detach(reader_thread);
        }
    }
    fprintf(stderr, "icss: node listening on %s, ring %u, UDP discovery %u, "
        "queue depth %u%s\n",
        listen_port, (unsigned int)node_ring_id,
        (unsigned int)node_discovery_port, (unsigned int)node_queue_depth,
        node_manual_next ? " (manual next)" : "");
    while (node_running) {
        fd_set read_set;
        struct timeval timeout;
        int ready;
        FD_ZERO(&read_set);
        FD_SET(node_listener, &read_set);
        FD_SET(discovery_socket, &read_set);
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
#ifdef _WIN32
        ready = select(0, &read_set, NULL, NULL, &timeout);
#else
        ready = select(node_listener > discovery_socket ? node_listener + 1 :
            discovery_socket + 1, &read_set, NULL, NULL, &timeout);
#endif
        if (ready > 0 && FD_ISSET(discovery_socket, &read_set)) {
            receive_discovery();
        }
        if (ready > 0 && FD_ISSET(node_listener, &read_set)) {
            icss_socket_t client = accept(node_listener, NULL, NULL);
            if (client != ICSS_INVALID_SOCKET) {
                pthread_t thread;
                icss_connection *connection =
                    (icss_connection *)malloc(sizeof(*connection));
                if (connection == NULL) {
                    icss_socket_close(client);
                    continue;
                }
                connection->socket = client;
                if (pthread_create(&thread, NULL, connection_worker,
                    connection) != 0) {
                    free(connection);
                    icss_socket_close(client);
                } else {
                    pthread_detach(thread);
                }
            }
        }
        if (time(NULL) - node_last_heartbeat >= ICSS_HEARTBEAT_SECONDS) {
            announce_node();
            if (!node_manual_next) update_topology();
        }
        if (node_status_requested) {
            uint64_t forwarded;
            uint32_t queued;
            pthread_mutex_lock(&stats_mutex);
            forwarded = node_forwarded;
            pthread_mutex_unlock(&stats_mutex);
            pthread_mutex_lock(&queue_mutex);
            queued = node_queue.count;
            pthread_mutex_unlock(&queue_mutex);
            fprintf(stderr, "icss: ring=%u chunk_size=%u forwarded=%llu queued=%u "
                "uptime=%llu\n",
                (unsigned int)node_ring_id, (unsigned int)node_chunk_size,
                (unsigned long long)forwarded, (unsigned int)queued,
                (unsigned long long)(time(NULL) - node_started));
            node_status_requested = 0;
        }
        reconnect_downstream();
    }
    /* Stop the relay threads before the sockets are closed so they cannot
       touch a half torn down connection. */
    if (node_writer_started) {
        pthread_join(node_writer_thread, NULL);
        node_writer_started = 0;
    }
    if (downstream_socket != ICSS_INVALID_SOCKET) {
        icss_socket_close(downstream_socket);
        downstream_socket = ICSS_INVALID_SOCKET;
    }
    if (node_listener != ICSS_INVALID_SOCKET) {
        icss_socket_close(node_listener);
        node_listener = ICSS_INVALID_SOCKET;
    }
    if (discovery_socket != ICSS_INVALID_SOCKET) {
        icss_socket_close(discovery_socket);
        discovery_socket = ICSS_INVALID_SOCKET;
    }
    socket_runtime_stop();
    if (!save_index()) {
        fprintf(stderr, "icss: failed to persist hash metadata index\n");
    }
    free_index_entries();
    if (node_queue.items != NULL) {
        uint32_t index;
        for (index = 0; index < node_queue.count; ++index) {
            uint32_t slot = (node_queue.head + index) % node_queue.capacity;
            if (node_queue.items[slot].payload != NULL) {
                OPENSSL_cleanse(node_queue.items[slot].payload,
                    node_queue.items[slot].header.payload_size);
                free(node_queue.items[slot].payload);
            }
        }
        free(node_queue.items);
        node_queue.items = NULL;
    }
    return 0;
}

static int send_control(icss_socket_t socket, char operation, uint16_t ring_id,
    uint8_t flags)
{
    unsigned char control[ICSS_CONTROL_SIZE] = {'I','C','S','C',0,0,0,0};
    control[4] = (unsigned char)operation;
    control[5] = flags;
    put_u16(control + 6, ring_id);
    return socket_send_all(socket, control, sizeof(control));
}

static int parse_u32(const char *text, uint32_t minimum, uint32_t maximum,
    uint32_t *value)
{
    char *end = NULL;
    unsigned long parsed;
    errno = 0;
    parsed = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || parsed < minimum ||
        parsed > maximum) {
        return 0;
    }
    *value = (uint32_t)parsed;
    return 1;
}

static int parse_hash(const char *text, unsigned char hash[32])
{
    size_t index;
    if (strlen(text) != 64U) {
        return 0;
    }
    for (index = 0; index < 32U; ++index) {
        unsigned int value;
        if (sscanf(text + index * 2U, "%2x", &value) != 1) {
            return 0;
        }
        hash[index] = (unsigned char)value;
    }
    return 1;
}

static int hash_file_path(const char *path, unsigned char digest[32],
    uint64_t *file_size)
{
    FILE *file = fopen(path, "rb");
    EVP_MD_CTX *context = NULL;
    unsigned char buffer[1024U * 1024U];
    size_t count;
    int ok = 0;
    uint64_t total = 0;
    unsigned int digest_size = 0;
    if (file == NULL) {
        fprintf(stderr, "icss: cannot open '%s': %s\n", path, strerror(errno));
        return 0;
    }
    context = EVP_MD_CTX_new();
    if (context == NULL || EVP_DigestInit_ex(context, EVP_sha256(), NULL) != 1) {
        goto cleanup;
    }
    while ((count = fread(buffer, 1, sizeof(buffer), file)) != 0U) {
        total += (uint64_t)count;
        if (EVP_DigestUpdate(context, buffer, count) != 1) {
            goto cleanup;
        }
    }
    if (ferror(file) || EVP_DigestFinal_ex(context, digest, &digest_size) != 1 ||
        digest_size != 32U) {
        goto cleanup;
    }
    *file_size = total;
    ok = 1;
cleanup:
    OPENSSL_cleanse(buffer, sizeof(buffer));
    EVP_MD_CTX_free(context);
    fclose(file);
    return ok;
}

/*
 * Injection path.
 *
 * The file is split into groups of k data shards. Every group is extended with
 * m parity shards, so a total of k + m frames enter the ring per group. The
 * parity shards travel through the ring like any other frame: relays only
 * verify the payload hash and never decode them.
 *
 * Encryption happens after the erasure encoding, so the parity shards are
 * computed over the plaintext and the ciphertext stays opaque to the relays.
  */

/*
 * Check whether a dataset with the given name is already registered on the
 * node at 'endpoint'. Under one key, file names must be unique: an encrypted
 * file matches when its key fingerprint equals the given key_id; an
 * unencrypted file matches on name alone.
 *
 * Returns 1 if a matching entry exists, 0 if not found, 2 on error.
 */
static int name_exists_on_endpoint(const char *endpoint, uint16_t ring_id,
    const char *name, const unsigned char key_id[ICSS_KEY_ID_SIZE],
    int have_key)
{
    char host[256];
    char port[16];
    char *response = NULL;
    size_t response_capacity = 0, used = 0;
    icss_socket_t socket;
    int result = 2;

    if (!parse_endpoint(endpoint, host, sizeof(host), port, sizeof(port)) ||
        !socket_runtime_start()) {
        return 2;
    }
    socket = connect_to(host, port);
    if (socket == ICSS_INVALID_SOCKET ||
        !send_control(socket, ICSS_OP_LIST, ring_id, have_key ? 1U : 0U)) {
        if (socket != ICSS_INVALID_SOCKET) icss_socket_close(socket);
        socket_runtime_stop();
        return 2;
    }

    response = (char *)malloc(8192U);
    if (!response) {
        icss_socket_close(socket);
        socket_runtime_stop();
        return 2;
    }
    response_capacity = 8192U;
    used = 0;
    for (;;) {
        int count;
        if (used + 1024U >= response_capacity) {
            char *bigger_ptr;
            response_capacity *= 2U;
            bigger_ptr = (char *)realloc(response, response_capacity);
            if (!bigger_ptr) break;
            response = bigger_ptr;
        }
        count = recv(socket, response + used,
            (int)(response_capacity - used - 1U), 0);
        if (count <= 0) break;
        used += (size_t)count;
    }
    response[used] = '\0';
    icss_socket_close(socket);
    socket_runtime_stop();

    if (used == 0U) {
        free(response);
        return 2;
    }

    result = 0;
    {
        const char *cursor = response;
        while ((cursor = strstr(cursor, "{\"name\":")) != NULL) {
            char file_name[ICSS_NAME_SIZE];
            char hash_dummy[65];
            char key_id_text[ICSS_KEY_ID_SIZE * 2 + 1];
            int encrypted;
            const char *record_end = strchr(cursor, '}');
            if (!record_end) break;
            if (!parse_catalogue_record(cursor, file_name, sizeof(file_name),
                hash_dummy, sizeof(hash_dummy), key_id_text,
                sizeof(key_id_text), &encrypted)) {
                break;
            }
            if (strcmp(file_name, name) == 0) {
                if (!encrypted) {
                    result = 1;
                    break;
                }
                if (have_key) {
                    char expected[ICSS_KEY_ID_SIZE * 2 + 1];
                    unsigned int index;
                    for (index = 0; index < ICSS_KEY_ID_SIZE; ++index) {
                        snprintf(expected + index * 2U, 3U, "%02x",
                            key_id[index]);
                    }
                    if (strcmp(expected, key_id_text) == 0) {
                        result = 1;
                        break;
                    }
                }
            }
            cursor = record_end + 1;
        }
    }
    free(response);
    return result;
}

static int command_inject(const char *path, const char *endpoint,
    uint16_t ring_id, uint32_t chunk_size, const char *key_path,
    uint8_t data_shards, uint8_t parity_shards)
{
    FILE *file = NULL;
    icss_socket_t socket = ICSS_INVALID_SOCKET;
    unsigned char key[32];
    unsigned char key_id[ICSS_KEY_ID_SIZE];
    char dataset_name[ICSS_NAME_SIZE];
    unsigned char file_hash[32];
    unsigned char *payload = NULL;
    unsigned char *group_buffer = NULL;
    unsigned char *encoded = NULL;
    unsigned char matrix[ICSS_MAX_SHARDS * ICSS_MAX_SHARDS];
    uint64_t file_size = 0;
    uint32_t total_chunks;
    uint32_t data_chunk_count;
    uint32_t group_count;
    uint32_t group_index;
    uint32_t shard_position;
    uint64_t sequence = 0;
    char host[256];
    char port[16];
    int encrypted = key_path != NULL;
    int result = 2;
    size_t group_bytes;
    if (!parse_endpoint(endpoint, host, sizeof(host), port, sizeof(port)) ||
        chunk_size == 0U || chunk_size > INT32_MAX) {
        fprintf(stderr, "icss: invalid endpoint or chunk size\n");
        return 1;
    }
    if (data_shards == 0U ||
        data_shards + parity_shards > ICSS_MAX_SHARDS) {
        fprintf(stderr, "icss: invalid erasure code parameters\n");
        return 1;
    }
    memset(key, 0, sizeof(key));
    if (encrypted && !load_aes256_key(key_path, key)) {
        return 2;
    }
    /*
     * The key fingerprint identifies the AES key that protects this dataset.
     * For an unencrypted dataset it stays all zero, which marks the dataset as
     * readable without any key.
     */
    memset(key_id, 0, sizeof(key_id));
    if (encrypted && !compute_key_id(key, key_id)) {
        fprintf(stderr, "icss: cannot compute the key fingerprint\n");
        return 2;
    }
    /* The base name of the file travels with the dataset as its label. */
    {
        const char *base = path;
        const char *cursor = path;
        while (*cursor != '\0') {
            if (*cursor == '/' || *cursor == '\\') base = cursor + 1;
            ++cursor;
        }
        copy_bounded(dataset_name, ICSS_NAME_SIZE, base);
    }
    /*
     * Reject the injection if a file with the same name already exists under
     * the same key on the target node. File names are unique per key.
     */
    {
        int name_exists = name_exists_on_endpoint(endpoint, ring_id,
            dataset_name, key_id, encrypted);
        if (name_exists == 1) {
            fprintf(stderr, "icss: file '%s' already exists under this key "
                "on %s, refusing to inject duplicate name\n",
                dataset_name, endpoint);
            goto cleanup;
        }
        if (name_exists == 2) {
            fprintf(stderr, "icss: cannot verify name uniqueness on %s\n",
                endpoint);
            goto cleanup;
        }
    }
    if (!hash_file_path(path, file_hash, &file_size)) {
        goto cleanup;
    }
    group_bytes = (size_t)chunk_size * data_shards;
    data_chunk_count = file_size == 0U ? 1U :
        (uint32_t)(((file_size - 1U) / chunk_size) + 1U);
    group_count = (data_chunk_count + data_shards - 1U) / data_shards;
    /*
     * Every shard of a group circulates as its own frame, so the file
     * occupies group_count * (k + m) frames in total. The chunk index is
     * therefore group_index * (k + m) + shard_position and identifies data
     * and parity shards alike.
     */
    total_chunks = group_count * (uint32_t)(data_shards + parity_shards);
    if (total_chunks > ICSS_MAX_CHUNKS) {
        fprintf(stderr, "icss: file exceeds maximum chunk count\n");
        goto cleanup;
    }
    if (parity_shards > 0U && !rs_build_matrix(data_shards, parity_shards,
        matrix)) {
        fprintf(stderr, "icss: cannot build erasure coding matrix\n");
        goto cleanup;
    }
    file = fopen(path, "rb");
    if (file == NULL) {
        fprintf(stderr, "icss: cannot open '%s': %s\n", path, strerror(errno));
        goto cleanup;
    }
    if (!socket_runtime_start()) {
        goto cleanup_runtime;
    }
    socket = connect_to(host, port);
    if (socket == ICSS_INVALID_SOCKET ||
        !send_control(socket, ICSS_OP_INJECT, ring_id, 0U)) {
        fprintf(stderr, "icss: cannot connect to node %s:%s\n", host, port);
        goto cleanup_runtime;
    }
    set_socket_timeout(socket, 60);
    payload = (unsigned char *)malloc(chunk_size);
    group_buffer = (unsigned char *)malloc(group_bytes);
    encoded = (unsigned char *)malloc(group_bytes +
        (size_t)chunk_size * parity_shards);
    if (payload == NULL || group_buffer == NULL || encoded == NULL) {
        goto cleanup_runtime;
    }
    sequence = ((uint64_t)time(NULL) << 32) ^ (uint64_t)(uintptr_t)payload;
    for (group_index = 0; group_index < group_count; ++group_index) {
        uint32_t shard;
        /* Fill the data shards of this group. */
        memset(group_buffer, 0, group_bytes);
        for (shard = 0; shard < data_shards; ++shard) {
            uint32_t chunk_id = group_index * data_shards + shard;
            size_t payload_size = 0U;
            if (chunk_id < data_chunk_count) {
                payload_size = (size_t)fread(payload, 1, chunk_size, file);
                if (ferror(file) || (file_size != 0U && payload_size == 0U)) {
                    fprintf(stderr, "icss: source file changed or read failed\n");
                    goto cleanup_runtime;
                }
            }
            memcpy(group_buffer + (size_t)shard * chunk_size, payload,
                payload_size);
        }
        if (parity_shards > 0U) {
            /* Compute the parity shards over the data shards. */
            uint32_t parity;
            for (parity = 0; parity < parity_shards; ++parity) {
                size_t position;
                unsigned char *target = encoded +
                    (size_t)(data_shards + parity) * chunk_size;
                for (position = 0; position < chunk_size; ++position) {
                    unsigned char value = 0U;
                    uint32_t column;
                    for (column = 0; column < data_shards; ++column) {
                        value ^= gf_mul(matrix[(data_shards + parity) * data_shards + column],
                            group_buffer[(size_t)column * chunk_size + position]);
                    }
                    target[position] = value;
                }
            }
        }
        /* Emit every shard of this group as an independent frame. */
        for (shard_position = 0;
             shard_position < (uint32_t)(data_shards + parity_shards);
             ++shard_position) {
            icss_frame_header header;
            const unsigned char *source = shard_position < data_shards ?
                group_buffer + (size_t)shard_position * chunk_size :
                encoded + (size_t)shard_position * chunk_size;
            uint32_t payload_size = chunk_size;
            /* The trailing shard of the file may be shorter than chunk_size. */
            if (shard_position == data_shards - 1U) {
                uint64_t consumed = (uint64_t)(group_index * data_shards +
                    shard_position) * chunk_size;
                uint64_t remaining = file_size > consumed ? file_size - consumed : 0U;
                payload_size = remaining > chunk_size ? chunk_size :
                    (uint32_t)remaining;
            }
            memset(&header, 0, sizeof(header));
            header.version = ICSS_FRAME_VERSION;
            header.flags = encrypted ? ICSS_FLAG_ENCRYPTED : 0U;
            header.ring_id = ring_id;
            header.sequence = sequence;
            header.chunk_id = group_index * (uint32_t)(data_shards + parity_shards) +
                shard_position;
            header.total_chunks = total_chunks;
            header.file_size = file_size;
            header.ttl = 1U;
            header.chunk_size = chunk_size;
            header.payload_size = payload_size;
            header.data_shards = data_shards;
            header.parity_shards = parity_shards;
            header.shard_pos = (uint8_t)shard_position;
            header.shard_group = group_index;
            memcpy(header.file_hash, file_hash, sizeof(file_hash));
            memcpy(header.key_id, key_id, sizeof(key_id));
            copy_bounded(header.name, ICSS_NAME_SIZE, dataset_name);
            memcpy(payload, source, payload_size);
            if (encrypted && !aes256_gcm_encrypt(key, &header, payload,
                payload_size)) {
                fprintf(stderr, "icss: AES-GCM encryption failed\n");
                goto cleanup_runtime;
            }
            if (!sha256_buffer(payload, payload_size, header.payload_hash) ||
                !write_wire_frame(socket, &header, payload)) {
                fprintf(stderr, "icss: failed to send shard %u of group %u\n",
                    shard_position, group_index);
                goto cleanup_runtime;
            }
            fprintf(stderr, "icss: injected shard %u/%u of group %u/%u\r",
                shard_position + 1U, (unsigned int)(data_shards + parity_shards),
                group_index + 1U, group_count);
        }
    }
    fprintf(stderr, "\n");
    printf("{\"file_sha256\":\"");
    {
        unsigned int index;
        for (index = 0; index < sizeof(file_hash); ++index) {
            printf("%02x", file_hash[index]);
        }
    }
    printf("\",\"total_chunks\":%u,\"groups\":%u,\"data_shards\":%u,"
        "\"parity_shards\":%u,\"ring_id\":%u}\n",
        total_chunks, group_count, (unsigned int)data_shards,
        (unsigned int)parity_shards, (unsigned int)ring_id);
    result = 0;
cleanup_runtime:
    if (payload != NULL) {
        OPENSSL_cleanse(payload, chunk_size);
        free(payload);
    }
    if (group_buffer != NULL) {
        OPENSSL_cleanse(group_buffer, group_bytes);
        free(group_buffer);
    }
    if (encoded != NULL) {
        OPENSSL_cleanse(encoded, group_bytes + (size_t)chunk_size * parity_shards);
        free(encoded);
    }
    if (socket != ICSS_INVALID_SOCKET) {
        icss_socket_close(socket);
    }
    socket_runtime_stop();
cleanup:
    if (file != NULL) {
        fclose(file);
    }
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(file_hash, sizeof(file_hash));
    return result;
}

static int seek_file_offset(FILE *file, uint64_t offset)
{
#ifdef _WIN32
    return _fseeki64(file, (__int64)offset, SEEK_SET) == 0;
#else
    return fseeko(file, (off_t)offset, SEEK_SET) == 0;
#endif
}

/*
 * Read side.
 *
 * The node streams every shard of the requested file. The reader collects the
 * shards of each erasure group; as soon as k shards of a group are available
 * the group is reconstructed and written to the output file. Up to m shards per
 * group may be missing, which is exactly what the parity shards are for.
 */
/*
 * Check whether every erasure group already holds enough shards to be
 * reconstructed. As soon as this is true the read can complete, even when
 * some parity shards have not arrived yet.
 */
static int all_groups_recoverable(uint32_t group_count, uint32_t data_shards,
    uint32_t parity_shards, const unsigned char *shard_present)
{
    uint32_t group;
    if (shard_present == NULL) return 0;
    for (group = 0; group < group_count; ++group) {
        const unsigned char *present = shard_present +
            (size_t)group * (data_shards + parity_shards);
        uint32_t position;
        uint32_t available = 0;
        for (position = 0; position < data_shards + parity_shards; ++position) {
            if (present[position]) ++available;
        }
        if (available < data_shards) return 0;
    }
    return 1;
}

/*
 * Reconstruct every erasure group from the shards that were received and
 * write the original file content to the output.
 *
 * The shards stored in the buffer are already decrypted: the parity shards are
 * computed over the plaintext, so the decoding has to happen on plaintext
 * shards.
 */
static int reconstruct_output_file(FILE *output, uint32_t group_count,
    uint32_t data_shards, uint32_t parity_shards, uint32_t chunk_size,
    uint64_t expected_file_size, unsigned char *shard_buffer,
    const unsigned char *shard_present, const unsigned char *matrix)
{
    uint32_t group;
    unsigned char *contents = NULL;
    unsigned char *recovered = NULL;
    int success = 0;
    if (data_shards == 0U) return 0;
    contents = (unsigned char *)malloc((size_t)data_shards * chunk_size);
    recovered = (unsigned char *)malloc((size_t)data_shards * chunk_size);
    if (contents == NULL || recovered == NULL) {
        fprintf(stderr, "\nicss: cannot allocate reconstruction buffers\n");
        goto cleanup;
    }
    for (group = 0; group < group_count; ++group) {
        const unsigned char *base = shard_buffer +
            (size_t)group * (data_shards + parity_shards) * chunk_size;
        const unsigned char *present = shard_present +
            (size_t)group * (data_shards + parity_shards);
        uint8_t rows[ICSS_MAX_SHARDS];
        uint32_t available = 0;
        uint32_t position;
        for (position = 0; position < data_shards + parity_shards; ++position) {
            if (present[position]) {
                rows[available] = (uint8_t)position;
                ++available;
            }
        }
        if (available < data_shards) {
            fprintf(stderr, "\nicss: group %u is missing shards (%u of %u available)\n",
                group, available, data_shards);
            goto cleanup;
        }
        /* Gather the first k surviving shards as the linear system input. */
        for (position = 0; position < data_shards; ++position) {
            memcpy(contents + (size_t)position * chunk_size,
                base + (size_t)rows[position] * chunk_size, chunk_size);
        }
        if (data_shards > 1U) {
            if (!rs_recover_group((uint8_t)data_shards, matrix, rows, contents,
                chunk_size, recovered)) {
                fprintf(stderr, "\nicss: erasure decoding failed for group %u\n",
                    group);
                goto cleanup;
            }
        } else {
            memcpy(recovered, contents, chunk_size);
        }
        /* Write the data shards of this group back into the original order. */
        for (position = 0; position < data_shards; ++position) {
            uint64_t chunk_id = (uint64_t)group * data_shards + position;
            uint64_t offset = chunk_id * chunk_size;
            uint64_t remaining = expected_file_size > offset ?
                expected_file_size - offset : 0U;
            uint32_t write_size = remaining > chunk_size ? chunk_size :
                (uint32_t)remaining;
            if (write_size == 0U) continue;
            if (!seek_file_offset(output, offset) ||
                fwrite(recovered + (size_t)position * chunk_size, 1, write_size,
                    output) != write_size) {
                fprintf(stderr, "\nicss: cannot write reconstructed data\n");
                goto cleanup;
            }
        }
    }
    success = 1;
cleanup:
    if (contents != NULL) {
        OPENSSL_cleanse(contents, (size_t)data_shards * chunk_size);
        free(contents);
    }
    if (recovered != NULL) {
        OPENSSL_cleanse(recovered, (size_t)data_shards * chunk_size);
        free(recovered);
    }
    return success;
}


/* ========================================================================
 * Name-to-hash resolution via LIST query
 * ======================================================================== */
/* ========================================================================
 * Name-to-hash resolution via LIST query
 * ======================================================================== */

/*
 * Look up a dataset hash by its human-readable name in the local index.
 *
 * Matches by name; for encrypted datasets the key fingerprint must also match,
 * so that a client holding a key only resolves datasets it can decrypt.
 *
 * Returns 1 on success (out_hash set), 0 if not found.
 */
static int lookup_hash_by_name(const char *name,
    const unsigned char key_id[ICSS_KEY_ID_SIZE], int have_key_id,
    unsigned char out_hash[32])
{
    icss_index_entry *entry;
    pthread_mutex_lock(&index_mutex);
    for (entry = index_entries; entry != NULL; entry = entry->next) {
        if (entry->chunk_seen == NULL) continue;
        if (strcmp(entry->name, name) != 0) continue;
        if (entry->encrypted) {
            if (!have_key_id) continue;
            if (memcmp(entry->key_id, key_id, ICSS_KEY_ID_SIZE) != 0) continue;
        }
        memcpy(out_hash, entry->file_hash, 32);
        pthread_mutex_unlock(&index_mutex);
        return 1;
    }
    pthread_mutex_unlock(&index_mutex);
    return 0;
}

/*
 * Discover all peers in the ring via UDP broadcast.
 * Returns the number of peers found, or -1 on error.
 * The peers array must be allocated by the caller with capacity max_peers.
 */
static int discover_ring_peers(uint16_t discovery_port, uint16_t ring_id,
    icss_peer *peers, int max_peers, int timeout_seconds)
{
    icss_socket_t sock;
    struct sockaddr_in local_addr;
    struct sockaddr_in broadcast_addr;
    int opt = 1;
    int peer_count = 0;
    time_t start_time;
    unsigned char packet[ICSS_DISCOVERY_SIZE];
    struct sockaddr_in src_addr;
    socklen_t src_len = sizeof(src_addr);

    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == ICSS_INVALID_SOCKET) {
        return -1;
    }
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));
    setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (const char *)&opt, sizeof(opt));

    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    local_addr.sin_port = htons(0);  // ephemeral port
    if (bind(sock, (struct sockaddr *)&local_addr, sizeof(local_addr)) != 0) {
        icss_socket_close(sock);
        return -1;
    }

    /*
     * Learn our own source IP address: open a temporary UDP socket to a
     * public address and ask the kernel which local address it would use.
     */
    uint32_t local_ip = htonl(INADDR_LOOPBACK);
    {
        icss_socket_t probe = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (probe != ICSS_INVALID_SOCKET) {
            struct sockaddr_in target;
            struct sockaddr_in local;
            socklen_t local_size = (socklen_t)sizeof(local);
            memset(&target, 0, sizeof(target));
            target.sin_family = AF_INET;
            target.sin_addr.s_addr = inet_addr("8.8.8.8");
            target.sin_port = htons(53U);
            if (connect(probe, (struct sockaddr *)&target,
                (int)sizeof(target)) == 0 &&
                getsockname(probe, (struct sockaddr *)&local, &local_size) == 0 &&
                local.sin_addr.s_addr != htonl(INADDR_ANY)) {
                local_ip = local.sin_addr.s_addr;
            }
            icss_socket_close(probe);
        }
    }

    /* Determine the ephemeral port assigned to our discovery socket. */
    {
        struct sockaddr_in local;
        socklen_t local_size = (socklen_t)sizeof(local);
        if (getsockname(sock, (struct sockaddr *)&local, &local_size) != 0) {
            icss_socket_close(sock);
            return -1;
        }
        local_addr = local;
    }

    memset(&broadcast_addr, 0, sizeof(broadcast_addr));
    broadcast_addr.sin_family = AF_INET;
    broadcast_addr.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    broadcast_addr.sin_port = htons(discovery_port);

    /*
     * Build a valid discovery request so that nodes can verify our
     * identity (advertised IP must match the source IP, node_id must
     * match SHA-256 over IP:port).
     */
    unsigned char node_id[16];
    make_node_id(local_ip,
        (uint16_t)ntohs(local_addr.sin_port), node_id);

    memset(packet, 0, sizeof(packet));
    memcpy(packet, "ICSD", 4);
    memcpy(packet + 4, node_id, sizeof(node_id));
    memcpy(packet + 20, &local_ip, 4);
    put_u16(packet + 24, (uint16_t)ntohs(local_addr.sin_port));
    put_u16(packet + 26, ring_id);
    put_u64(packet + 28, (uint64_t)time(NULL));
    OPENSSL_cleanse(node_id, sizeof(node_id));

    if (sendto(sock, (const char *)packet, sizeof(packet), 0,
        (struct sockaddr *)&broadcast_addr, sizeof(broadcast_addr)) < 0) {
        icss_socket_close(sock);
        return -1;
    }

    set_socket_timeout(sock, 1);
    start_time = time(NULL);
    while (time(NULL) - start_time < timeout_seconds && peer_count < max_peers) {
        int received = recvfrom(sock, (char *)packet, sizeof(packet), 0,
            (struct sockaddr *)&src_addr, &src_len);
        if (received == (int)sizeof(packet) && memcmp(packet, "ICSD", 4) == 0) {
            uint32_t advertised_ip;
            uint16_t tcp_port;
            uint16_t peer_ring_id;
            uint64_t timestamp;
            uint64_t now = (uint64_t)time(NULL);
            unsigned char expected_id[16];

            memcpy(&advertised_ip, packet + 20, 4);
            tcp_port = get_u16(packet + 24);
            peer_ring_id = get_u16(packet + 26);
            timestamp = get_u64(packet + 28);

            if (peer_ring_id != ring_id || tcp_port == 0U ||
                advertised_ip != src_addr.sin_addr.s_addr ||
                (timestamp > now ? timestamp - now : now - timestamp) > ICSS_PEER_TIMEOUT) {
                continue;
            }
            make_node_id(advertised_ip, tcp_port, expected_id);
            if (memcmp(expected_id, packet + 4, sizeof(expected_id)) != 0) {
                OPENSSL_cleanse(expected_id, sizeof(expected_id));
                continue;
            }
            OPENSSL_cleanse(expected_id, sizeof(expected_id));

            /* Check if already in list */
            int exists = 0;
            for (int i = 0; i < peer_count; ++i) {
                if (peers[i].ip_address == advertised_ip &&
                    peers[i].tcp_port == tcp_port) {
                    exists = 1;
                    break;
                }
            }
            if (!exists) {
                peers[peer_count].ip_address = advertised_ip;
                peers[peer_count].tcp_port = tcp_port;
                peers[peer_count].ring_id = peer_ring_id;
                peers[peer_count].last_seen = time(NULL);
                memcpy(peers[peer_count].node_id, packet + 4, 16);
                ++peer_count;
            }
        }
    }
    icss_socket_close(sock);
    return peer_count;
}

/*
 * Query LIST on a specific peer and search for a file by name.
 * Returns 0 on success (found), 1 if not found, 2 on error.
 * If found, out_hash is set and out_endpoint is filled with the peer's endpoint.
 */
static int query_peer_for_file(const icss_peer *peer, uint16_t ring_id,
    const char *name, const unsigned char key_id[ICSS_KEY_ID_SIZE],
    int have_key, unsigned char out_hash[32], char *out_endpoint, size_t endpoint_cap)
{
    char host[INET_ADDRSTRLEN];
    char port[16];
    char *response = NULL;
    size_t response_capacity = 0, used = 0;
    icss_socket_t socket;
    struct in_addr addr;
    int result = 2;

    addr.s_addr = peer->ip_address;
    if (inet_ntop(AF_INET, &addr, host, sizeof(host)) == NULL) {
        return 2;
    }
    snprintf(port, sizeof(port), "%u", (unsigned int)peer->tcp_port);

    if (!socket_runtime_start()) {
        return 2;
    }
    socket = connect_to(host, port);
    if (socket == ICSS_INVALID_SOCKET ||
        !send_control(socket, ICSS_OP_LIST, ring_id, 0)) {
        if (socket != ICSS_INVALID_SOCKET) icss_socket_close(socket);
        socket_runtime_stop();
        return 2;
    }

    response = (char *)malloc(8192U);
    if (!response) {
        icss_socket_close(socket);
        socket_runtime_stop();
        return 2;
    }
    response_capacity = 8192U;
    used = 0;
    for (;;) {
        int count;
        if (used + 1024U >= response_capacity) {
            response_capacity *= 2U;
            char *bigger_ptr = (char *)realloc(response, response_capacity);
            if (!bigger_ptr) break;
            response = bigger_ptr;
        }
        count = recv(socket, response + used, (int)(response_capacity - used - 1U), 0);
        if (count <= 0) break;
        used += (size_t)count;
    }
    response[used] = '\0';
    icss_socket_close(socket);
    socket_runtime_stop();

    if (used == 0U) {
        free(response);
        return 2;
    }

    const char *cursor = response;
    while ((cursor = strstr(cursor, "{\"name\":")) != NULL) {
        char file_name[ICSS_NAME_SIZE];
        char hash[65];
        char key_id_text[ICSS_KEY_ID_SIZE * 2 + 1];
        int encrypted;
        const char *record_end = strchr(cursor, '}');
        if (!record_end) break;
        if (!parse_catalogue_record(cursor, file_name, sizeof(file_name),
            hash, sizeof(hash), key_id_text,
            sizeof(key_id_text), &encrypted)) {
            break;
        }
        if (strcmp(file_name, name) == 0) {
            if (!encrypted) {
                if (!parse_hash(hash, out_hash)) {
                    result = 2;
                    break;
                }
                snprintf(out_endpoint, endpoint_cap, "%s:%s", host, port);
                result = 0;
                break;
            }
            if (have_key) {
                char expected[ICSS_KEY_ID_SIZE * 2 + 1];
                unsigned int index;
                for (index = 0; index < ICSS_KEY_ID_SIZE; ++index) {
                    snprintf(expected + index * 2U, 3U, "%02x", key_id[index]);
                }
                if (strcmp(expected, key_id_text) == 0) {
                    if (!parse_hash(hash, out_hash)) {
                        result = 2;
                        break;
                    }
                    snprintf(out_endpoint, endpoint_cap, "%s:%s", host, port);
                    result = 0;
                    break;
                }
            }
        }
        cursor = record_end + 1;
    }
    free(response);
    return result;
}

/*
 * Resolve a file name to its hash by searching the entire ring.
 * Returns 0 on success, 1 if not found, 2 on error.
 * If found, out_hash is set and out_endpoint is filled with the peer endpoint where it was found.
 */
static int resolve_name_to_hash_in_ring(uint16_t discovery_port, uint16_t ring_id,
    const char *name, const unsigned char key_id[ICSS_KEY_ID_SIZE],
    int have_key, unsigned char out_hash[32], char *out_endpoint, size_t endpoint_cap)
{
    (void)endpoint_cap;
    icss_peer peers[ICSS_MAX_PEERS];
    int peer_count;
    int found_count = 0;
    unsigned char first_hash[32];
    char first_endpoint[256];

    peer_count = discover_ring_peers(discovery_port, ring_id, peers, ICSS_MAX_PEERS, 5);
    if (peer_count <= 0) {
        fprintf(stderr, "icss: no peers discovered in ring %u\n", (unsigned int)ring_id);
        return 2;
    }

    fprintf(stderr, "icss: discovered %d peer(s) in ring %u\n", peer_count, (unsigned int)ring_id);

    for (int i = 0; i < peer_count; ++i) {
        unsigned char hash[32];
        char endpoint[256];
        int res = query_peer_for_file(&peers[i], ring_id, name, key_id, have_key,
            hash, endpoint, sizeof(endpoint));
        if (res == 0) {
            if (found_count == 0) {
                memcpy(first_hash, hash, 32);
                strcpy(first_endpoint, endpoint);
                ++found_count;
            } else {
                /* Check if it's the same file (same hash) or a different file with same name */
                if (memcmp(first_hash, hash, 32) != 0) {
                    fprintf(stderr, "icss: duplicate file name '%s' with different content found in ring\n", name);
                    return 2;
                }
                /* Same file found on another peer, that's OK */
            }
        } else if (res == 2) {
            struct in_addr addr;
            addr.s_addr = peers[i].ip_address;
            fprintf(stderr, "icss: error querying peer %s:%u\n",
                inet_ntoa(addr),
                (unsigned int)peers[i].tcp_port);
        }
    }

    if (found_count == 0) {
        return 1;
    }
    memcpy(out_hash, first_hash, 32);
    strcpy(out_endpoint, first_endpoint);
    return 0;
}

static int command_fetch_by_hash(const char *hash_text, const char *output_path,
    const char *endpoint, uint16_t ring_id, const char *key_path)
{
    icss_socket_t socket = ICSS_INVALID_SOCKET;
    FILE *output = NULL;
    unsigned char target_hash[32];
    unsigned char key[32];
    unsigned char *seen = NULL;
    unsigned char *shard_buffer = NULL;
    unsigned char *shard_present = NULL;
    unsigned char matrix[ICSS_MAX_SHARDS * ICSS_MAX_SHARDS];
    uint32_t total_chunks = 0;
    uint32_t received_chunks = 0;
    uint32_t chunk_size = 0;
    uint32_t group_count = 0;
    uint32_t data_shards = 1U;
    uint32_t parity_shards = 0U;
    uint64_t expected_file_size = 0;
    char host[256];
    char port[16];
    int result = 2;
    int output_created = 0;
    memset(key, 0, sizeof(key));
    if (!parse_hash(hash_text, target_hash) ||
        !parse_endpoint(endpoint, host, sizeof(host), port, sizeof(port))) {
        fprintf(stderr, "icss: invalid file hash or endpoint\n");
        return 1;
    }
    if (key_path != NULL && !load_aes256_key(key_path, key)) {
        return 2;
    }
    if (!socket_runtime_start()) {
        goto cleanup_runtime;
    }
    socket = connect_to(host, port);
    if (socket == ICSS_INVALID_SOCKET ||
        !send_control(socket, ICSS_OP_FETCH, ring_id, 0U) ||
        !socket_send_all(socket, target_hash, sizeof(target_hash))) {
        fprintf(stderr, "icss: cannot register fetch with %s:%s\n", host, port);
        goto cleanup_runtime;
    }
    {
        unsigned char acknowledgement[4];
        if (!socket_recv_all(socket, acknowledgement, sizeof(acknowledgement)) ||
            memcmp(acknowledgement, "ACKF", sizeof(acknowledgement)) != 0) {
            fprintf(stderr, "icss: node rejected fetch registration\n");
            goto cleanup_runtime;
        }
    }
    /*
     * The read waits for the shards to circulate. When the dataset cannot be
     * completed the socket timeout ends the wait with a clear error instead
     * of blocking forever.
     */
    set_socket_timeout(socket, ICSS_FETCH_TIMEOUT_SECONDS);
    while (total_chunks == 0U || !all_groups_recoverable(group_count,
        data_shards, parity_shards, shard_present)) {
        icss_frame_header header;
        unsigned char *payload = NULL;
        unsigned char digest[32];
        if (!read_wire_frame(socket, &header, ICSS_MAX_CHUNK_SIZE, &payload)) {
            fprintf(stderr, "\nicss: dataset incomplete or node disconnected\n");
            goto cleanup_runtime;
        }
        if (header.ring_id != ring_id ||
            memcmp(header.file_hash, target_hash, sizeof(target_hash)) != 0 ||
            header.total_chunks > ICSS_MAX_CHUNKS ||
            !sha256_buffer(payload, header.payload_size, digest) ||
            memcmp(digest, header.payload_hash, sizeof(digest)) != 0) {
            OPENSSL_cleanse(payload, header.payload_size);
            free(payload);
            fprintf(stderr, "icss: invalid frame received\n");
            goto cleanup_runtime;
        }
        if (total_chunks == 0U) {
            /*
             * The first frame of the requested file defines the layout that the
             * reader follows. Only a frame that is encrypted exactly when a key
             * was supplied can be the reference, otherwise the reader would
             * wait for shards it can never decrypt.
             */
            if ((header.flags & ICSS_FLAG_ENCRYPTED) != (key_path != NULL ?
                ICSS_FLAG_ENCRYPTED : 0U)) {
                OPENSSL_cleanse(payload, header.payload_size);
                free(payload);
                continue;
            }
            total_chunks = header.total_chunks;
            chunk_size = header.chunk_size;
            expected_file_size = header.file_size;
            data_shards = header.data_shards;
            parity_shards = header.parity_shards;
            group_count = total_chunks / (uint32_t)(data_shards + parity_shards);
            if (group_count == 0U || total_chunks %
                (uint32_t)(data_shards + parity_shards) != 0U) {
                OPENSSL_cleanse(payload, header.payload_size);
                free(payload);
                fprintf(stderr, "icss: inconsistent chunk count\n");
                goto cleanup_runtime;
            }
            seen = (unsigned char *)calloc(total_chunks, sizeof(*seen));
            output = fopen(output_path, "wb+");
            if (seen == NULL || output == NULL) {
                OPENSSL_cleanse(payload, header.payload_size);
                free(payload);
                fprintf(stderr, "icss: cannot allocate index or create output\n");
                goto cleanup_runtime;
            }
            output_created = 1;
        }
        /*
         * The same file can circulate under more than one layout, for example
         * once plain and once erasure coded. The reader picked the first frame
         * it saw as its reference layout and has to ignore the frames of the
         * other layouts instead of aborting the whole read.
         */
        if (header.total_chunks != total_chunks || header.chunk_size != chunk_size ||
            header.file_size != expected_file_size || header.chunk_id >= total_chunks ||
            header.data_shards != data_shards ||
            header.parity_shards != parity_shards) {
            OPENSSL_cleanse(payload, header.payload_size);
            free(payload);
            continue;
        }
        if (!seen[header.chunk_id]) {
            seen[header.chunk_id] = 1U;
            ++received_chunks;
            /*
             * Store the shard in the group buffer. The group buffer holds
             * k + m slots of chunk_size bytes, indexed by the shard position.
             */
            {
                uint32_t group = header.shard_group;
                if (group >= group_count) {
                    OPENSSL_cleanse(payload, header.payload_size);
                    free(payload);
                    fprintf(stderr, "icss: invalid shard group\n");
                    goto cleanup_runtime;
                }
                if (shard_buffer == NULL) {
                    shard_buffer = (unsigned char *)calloc(
                        (size_t)group_count * (data_shards + parity_shards) * chunk_size,
                        1U);
                    shard_present = (unsigned char *)calloc(
                        (size_t)group_count * (data_shards + parity_shards), 1U);
                    if (shard_buffer == NULL || shard_present == NULL) {
                        OPENSSL_cleanse(payload, header.payload_size);
                        free(payload);
                        fprintf(stderr, "icss: cannot allocate shard buffer\n");
                        goto cleanup_runtime;
                    }
                }
                /*
                 * Decrypt before storing: the parity shards were computed over
                 * the plaintext, so the reconstruction has to work on plaintext
                 * shards. The authentication tag is verified here, which also
                 * proves that the shard was not tampered with in the ring.
                 */
                if ((header.flags & ICSS_FLAG_ENCRYPTED) != 0U &&
                    !aes256_gcm_decrypt(key, &header, payload,
                        header.payload_size)) {
                    OPENSSL_cleanse(payload, header.payload_size);
                    free(payload);
                    fprintf(stderr, "icss: shard authentication failed\n");
                    goto cleanup_runtime;
                }
                memcpy(shard_buffer +
                    ((size_t)group * (data_shards + parity_shards) + header.shard_pos) * chunk_size,
                    payload, header.payload_size);
                shard_present[(size_t)group * (data_shards + parity_shards) +
                    header.shard_pos] = 1U;
            }
        }
        OPENSSL_cleanse(payload, header.payload_size);
        free(payload);
        fprintf(stderr, "icss: received %u/%u shards\r", received_chunks,
            total_chunks);
    }
    /* Rebuild the file from the collected shards. */
    if (parity_shards > 0U && !rs_build_matrix((uint8_t)data_shards,
        (uint8_t)parity_shards, matrix)) {
        fprintf(stderr, "\nicss: cannot build erasure coding matrix\n");
        goto cleanup_runtime;
    }
    if (!reconstruct_output_file(output, group_count, data_shards, parity_shards,
        chunk_size, expected_file_size, shard_buffer, shard_present, matrix)) {
        goto cleanup_runtime;
    }
    if (fflush(output) != 0) {
        fprintf(stderr, "\nicss: output flush failed\n");
        goto cleanup_runtime;
    }
    {
        unsigned char actual_hash[32];
        uint64_t actual_size = 0;
        if (!hash_file_path(output_path, actual_hash, &actual_size) ||
            actual_size != expected_file_size ||
            memcmp(actual_hash, target_hash, sizeof(target_hash)) != 0) {
            OPENSSL_cleanse(actual_hash, sizeof(actual_hash));
            fprintf(stderr, "\nicss: reconstructed file SHA-256 mismatch\n");
            goto cleanup_runtime;
        }
        OPENSSL_cleanse(actual_hash, sizeof(actual_hash));
    }
    fprintf(stderr, "\n");
    printf("fetched %u shards (%u data, %u parity) to %s\n", total_chunks,
        (unsigned int)(group_count * data_shards),
        (unsigned int)(group_count * parity_shards), output_path);
    result = 0;
cleanup_runtime:
    if (output != NULL) {
        fclose(output);
    }
    if (output_created && result != 0) {
        remove(output_path);
    }
    if (socket != ICSS_INVALID_SOCKET) {
        icss_socket_close(socket);
    }
    socket_runtime_stop();
    free(seen);
    if (shard_buffer != NULL) {
        OPENSSL_cleanse(shard_buffer,
            (size_t)group_count * (data_shards + parity_shards) * chunk_size);
        free(shard_buffer);
    }
    free(shard_present);
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(target_hash, sizeof(target_hash));
    return result;
}
static int command_fetch(const char *hash_text, const char *name,
    const char *output_path, const char *endpoint,
    uint16_t ring_id, const char *key_path, uint16_t discovery_port)
{
    unsigned char target_hash[32];
    unsigned char key[32];
    unsigned char key_id[ICSS_KEY_ID_SIZE];
    int have_key = 0;
    char resolved_endpoint[256];

    if (key_path != NULL) {
        memset(key, 0, sizeof(key));
        if (!load_aes256_key(key_path, key) || !compute_key_id(key, key_id)) {
            fprintf(stderr, "icss: cannot load/compute key\n");
            return 2;
        }
        have_key = 1;
    } else {
        memset(key, 0, sizeof(key));
        memset(key_id, 0, sizeof(key_id));
    }

    if (name) {
        /* Search the entire ring for the file by name */
        if (resolve_name_to_hash_in_ring(discovery_port, ring_id, name, key_id, have_key,
            target_hash, resolved_endpoint, sizeof(resolved_endpoint)) != 0) {
            fprintf(stderr, "icss: file '%s' not found or not accessible with the given key in ring %u\n", name, (unsigned int)ring_id);
            return 1;
        }
        fprintf(stderr, "icss: found file '%s' at %s\n", name, resolved_endpoint);
        /* Convert resolved hash to hex text for command_fetch_by_hash */
        char hash_hex[65];
        for (int hi = 0; hi < 32; ++hi) {
            snprintf(hash_hex + hi * 2U, 3U, "%02x", target_hash[hi]);
        }
        hash_hex[64] = '\0';
        return command_fetch_by_hash(hash_hex, output_path, resolved_endpoint, ring_id, key_path);
    } else {
        if (!parse_hash(hash_text, target_hash)) return 1;
        return command_fetch_by_hash(hash_text, output_path, endpoint, ring_id, key_path);
    }
}

/*
 * Parse all fields of one catalogue JSON record in a bounded scan.
 * Extracts name, sha256, key_id and the encrypted flag from a record that
 * starts at '{'. Returns 1 when all four fields were found, 0 otherwise.
 *
 * This avoids calling json_get_string four times per record (each of which
 * re-scans the record with strstr), reducing the parse cost from O(4*fields)
 * to a single bounded pass over the record text.
 */
static int parse_catalogue_record(const char *record,
    char *name, size_t name_cap,
    char *hash, size_t hash_cap,
    char *key_id_text, size_t key_id_cap,
    int *encrypted)
{
    const char *end;
    const char *p;
    size_t len;

    /* name */
    p = strstr(record, "\"name\":\"");
    if (!p) return 0;
    p += 8;
    end = strchr(p, '"');
    if (!end) return 0;
    len = (size_t)(end - p);
    if (len + 1U > name_cap) len = name_cap - 1U;
    memcpy(name, p, len);
    name[len] = '\0';

    /* sha256 */
    p = strstr(record, "\"sha256\":\"");
    if (!p) return 0;
    p += 10;
    end = strchr(p, '"');
    if (!end) return 0;
    len = (size_t)(end - p);
    if (len + 1U > hash_cap) len = hash_cap - 1U;
    memcpy(hash, p, len);
    hash[len] = '\0';

    /* key_id */
    p = strstr(record, "\"key_id\":\"");
    if (!p) return 0;
    p += 10;
    end = strchr(p, '"');
    if (!end) return 0;
    len = (size_t)(end - p);
    if (len + 1U > key_id_cap) len = key_id_cap - 1U;
    memcpy(key_id_text, p, len);
    key_id_text[len] = '\0';

    /* encrypted */
    p = strstr(record, "\"encrypted\":");
    if (!p) return 0;
    p += 12;
    *encrypted = (strncmp(p, "true", 4) == 0);

    return 1;
}

/*
 * Simple open-addressing hash set for 32-byte content hashes.
 * Used to deduplicate catalogue entries across peers in O(1) expected time
 * instead of O(n) linear search.
 */
#define ICSS_SEEN_CAP 1024U
static unsigned char icss_seen_table[ICSS_SEEN_CAP][32U];
static int icss_seen_used[ICSS_SEEN_CAP];
static int icss_seen_count = 0;

static void icss_seen_reset(void)
{
    memset(icss_seen_used, 0, sizeof(icss_seen_used));
    icss_seen_count = 0;
}

static int icss_seen_contains(const unsigned char hash[32])
{
    uint32_t idx = ((uint32_t)hash[0] << 24) | ((uint32_t)hash[1] << 16) |
                   ((uint32_t)hash[2] << 8) | (uint32_t)hash[3];
    idx &= (uint32_t)(ICSS_SEEN_CAP - 1U);
    while (icss_seen_used[idx]) {
        if (memcmp(icss_seen_table[idx], hash, 32U) == 0) return 1;
        idx = (idx + 1U) & (uint32_t)(ICSS_SEEN_CAP - 1U);
    }
    return 0;
}

static int icss_seen_add(const unsigned char hash[32])
{
    if (icss_seen_count >= (int)ICSS_SEEN_CAP) return 0;
    uint32_t idx = ((uint32_t)hash[0] << 24) | ((uint32_t)hash[1] << 16) |
                   ((uint32_t)hash[2] << 8) | (uint32_t)hash[3];
    idx &= (uint32_t)(ICSS_SEEN_CAP - 1U);
    while (icss_seen_used[idx]) {
        if (memcmp(icss_seen_table[idx], hash, 32U) == 0) return 0;
        idx = (idx + 1U) & (uint32_t)(ICSS_SEEN_CAP - 1U);
    }
    memcpy(icss_seen_table[idx], hash, 32U);
    icss_seen_used[idx] = 1;
    ++icss_seen_count;
    return 1;
}

/*
 * Catalogue query on the client side.
 *
 * Without a key every dataset is listed. With a key only the datasets that the
 * key can actually decrypt are listed: a dataset is decryptable when it is not
 * encrypted at all, or when its key fingerprint matches the fingerprint of the
 * given key.
 */
/*
 * List the catalogue of the entire ring: discover all peers via UDP, query
 * LIST on each, and print merged, deduplicated results. With a key, only
 * datasets that the key can decrypt are shown.
 *
 * Returns 0 on success, 1 if nothing found, 2 on error.
 */
static int list_ring_catalogue(uint16_t discovery_port, uint16_t ring_id,
    const unsigned char key_id[ICSS_KEY_ID_SIZE], int have_key)
{
    icss_peer peers[ICSS_MAX_PEERS];
    int peer_count;
    int found_any = 0;
    int i;

    icss_seen_reset();

    peer_count = discover_ring_peers(discovery_port, ring_id, peers,
        ICSS_MAX_PEERS, 5);
    if (peer_count <= 0) {
        fprintf(stderr, "icss: no peers discovered in ring %u\n",
            (unsigned int)ring_id);
        return 2;
    }

    fprintf(stderr, "icss: discovered %d peer(s) in ring %u\n",
        peer_count, (unsigned int)ring_id);

    printf("%-32s %-64s %-10s %s\n", "NAME", "SHA256", "ENCRYPTED", "KEY_ID");

    for (i = 0; i < peer_count; ++i) {
        char host[INET_ADDRSTRLEN];
        char port[16];
        char *response = NULL;
        size_t response_capacity = 0, used = 0;
        icss_socket_t socket;
        struct in_addr addr;
        const char *cursor;

        addr.s_addr = peers[i].ip_address;
        if (inet_ntop(AF_INET, &addr, host, sizeof(host)) == NULL) continue;
        snprintf(port, sizeof(port), "%u", (unsigned int)peers[i].tcp_port);

        if (!socket_runtime_start()) continue;
        socket = connect_to(host, port);
        if (socket == ICSS_INVALID_SOCKET ||
            !send_control(socket, ICSS_OP_LIST, ring_id, have_key ? 1U : 0U)) {
            if (socket != ICSS_INVALID_SOCKET) icss_socket_close(socket);
            socket_runtime_stop();
            continue;
        }

        response = (char *)malloc(8192U);
        if (!response) {
            icss_socket_close(socket);
            socket_runtime_stop();
            continue;
        }
        response_capacity = 8192U;
        used = 0;
        for (;;) {
            int count;
            if (used + 1024U >= response_capacity) {
                char *bigger_ptr;
                response_capacity *= 2U;
                bigger_ptr = (char *)realloc(response, response_capacity);
                if (!bigger_ptr) break;
                response = bigger_ptr;
            }
            count = recv(socket, response + used,
                (int)(response_capacity - used - 1U), 0);
            if (count <= 0) break;
            used += (size_t)count;
        }
        response[used] = '\0';
        icss_socket_close(socket);
        socket_runtime_stop();

        if (used == 0U) {
            free(response);
            continue;
        }

        cursor = response;
        while ((cursor = strstr(cursor, "{\"name\":")) != NULL) {
            char name[ICSS_NAME_SIZE];
            char hash[65];
            char key_id_text[ICSS_KEY_ID_SIZE * 2 + 1];
            int encrypted;
            unsigned char hash_bytes[32];
            const char *record_end = strchr(cursor, '}');
            if (!record_end) break;
            if (!parse_catalogue_record(cursor, name, sizeof(name),
                hash, sizeof(hash), key_id_text,
                sizeof(key_id_text), &encrypted)) {
                break;
            }
            if (!parse_hash(hash, hash_bytes)) {
                cursor = record_end + 1;
                continue;
            }
            /* Deduplicate across peers in O(1) expected time via hash set. */
            if (icss_seen_contains(hash_bytes)) {
                cursor = record_end + 1;
                continue;
            }
            icss_seen_add(hash_bytes);
            if (have_key && encrypted) {
                if (strcmp(key_id_text, "") == 0) {
                    cursor = record_end + 1;
                    continue;
                }
                {
                    char expected[ICSS_KEY_ID_SIZE * 2 + 1];
                    unsigned int index;
                    for (index = 0; index < ICSS_KEY_ID_SIZE; ++index) {
                        snprintf(expected + index * 2U, 3U, "%02x", key_id[index]);
                    }
                    if (strcmp(expected, key_id_text) != 0) {
                        cursor = record_end + 1;
                        continue;
                    }
                }
            }
            printf("%-32s %-64s %-10s %s\n", name, hash,
                encrypted ? "yes" : "no", encrypted ? key_id_text : "-");
            found_any = 1;
            cursor = record_end + 1;
        }
        free(response);
    }

    if (!found_any) return 1;
    return 0;
}

static int command_list(const char *endpoint, uint16_t ring_id,
    const char *key_path, uint16_t discovery_port)
{
    char host[256];
    char port[16];
    char *response = NULL;
    size_t response_capacity = 0;
    size_t used = 0;
    icss_socket_t socket;
    unsigned char key[32];
    unsigned char key_id[ICSS_KEY_ID_SIZE];
    int have_key = 0;
    int result = 2;
    const char *cursor;

    memset(key, 0, sizeof(key));
    if (key_path != NULL) {
        if (!load_aes256_key(key_path, key)) {
            return 2;
        }
        if (!compute_key_id(key, key_id)) {
            fprintf(stderr, "icss: cannot compute the key fingerprint\n");
            return 2;
        }
        have_key = 1;
    }

    /*
     * When no endpoint is given, search the entire ring: discover every peer
     * via UDP and query LIST on each. Otherwise query the single named node.
     */
    if (!endpoint || endpoint[0] == '\0') {
        return list_ring_catalogue(discovery_port, ring_id, key_id, have_key);
    }

    if (!parse_endpoint(endpoint, host, sizeof(host), port, sizeof(port))) {
        fprintf(stderr, "icss: invalid endpoint\n");
        return 1;
    }
    if (!socket_runtime_start()) {
        return 2;
    }
    socket = connect_to(host, port);
    if (socket == ICSS_INVALID_SOCKET ||
        !send_control(socket, ICSS_OP_LIST, ring_id, (uint8_t)(have_key ? 1U : 0U))) {
        fprintf(stderr, "icss: cannot query node %s:%s\n", host, port);
        if (socket != ICSS_INVALID_SOCKET) {
            icss_socket_close(socket);
        }
        socket_runtime_stop();
        return 2;
    }
    /* Read until the peer closes the connection. */
    response_capacity = 8192U;
    response = (char *)malloc(response_capacity);
    if (response == NULL) {
        icss_socket_close(socket);
        socket_runtime_stop();
        return 2;
    }
    for (;;) {
        int count;
        if (used + 1024U >= response_capacity) {
            char *bigger;
            response_capacity *= 2U;
            bigger = (char *)realloc(response, response_capacity);
            if (bigger == NULL) {
                break;
            }
            response = bigger;
        }
        count = recv(socket, response + used, (int)(response_capacity - used - 1U), 0);
        if (count <= 0) {
            break;
        }
        used += (size_t)count;
    }
    response[used] = '\0';
    icss_socket_close(socket);
    socket_runtime_stop();
    if (used == 0U) {
        fprintf(stderr, "icss: empty catalogue response\n");
        free(response);
        return 2;
    }
    /*
     * Print the catalogue as a table: the name, the content hash and the key
     * fingerprint. The rows that the given key cannot decrypt are skipped.
     */
    printf("%-32s %-64s %-10s %s\n", "NAME", "SHA256", "ENCRYPTED", "KEY_ID");
    cursor = response;
    while ((cursor = strstr(cursor, "{\"name\":")) != NULL) {
        char name[ICSS_NAME_SIZE];
        char hash[65];
        char key_id_text[ICSS_KEY_ID_SIZE * 2 + 1];
        int encrypted;
        const char *record_end = strchr(cursor, '}');
        if (record_end == NULL) {
            break;
        }
        if (!parse_catalogue_record(cursor, name, sizeof(name),
            hash, sizeof(hash), key_id_text,
            sizeof(key_id_text), &encrypted)) {
            break;
        }
        if (have_key) {
            /* Only the datasets this key can really open are of interest. */
            if (encrypted) {
                if (strcmp(key_id_text, "") == 0) {
                    cursor = record_end + 1;
                    continue;
                }
                {
                    char expected[ICSS_KEY_ID_SIZE * 2 + 1];
                    unsigned int index;
                    for (index = 0; index < ICSS_KEY_ID_SIZE; ++index) {
                        snprintf(expected + index * 2U, 3U, "%02x", key_id[index]);
                    }
                    if (strcmp(expected, key_id_text) != 0) {
                        cursor = record_end + 1;
                        continue;
                    }
                }
            }
        }
        printf("%-32s %-64s %-10s %s\n", name, hash,
            encrypted ? "yes" : "no", encrypted ? key_id_text : "-");
        cursor = record_end + 1;
    }
    result = 0;
    free(response);
    OPENSSL_cleanse(key, sizeof(key));
    return result;
}

/*
 * Fault injection helper for the erasure code.
 *
 * It encodes a test buffer, drops a configurable number of shards per group
 * and verifies that the reconstruction still yields the original data. This
 * exercises the same recovery routine the read path uses.
 */
static int command_erasure_check(uint32_t data_shards, uint32_t parity_shards,
    uint32_t lost_shards)
{
    unsigned char matrix[ICSS_MAX_SHARDS * ICSS_MAX_SHARDS];
    unsigned char *data = NULL;
    unsigned char *encoded = NULL;
    unsigned char *contents = NULL;
    unsigned char *recovered = NULL;
    unsigned char *present = NULL;
    const size_t shard_size = 128U;
    uint32_t group;
    int success = 2;
    if (data_shards == 0U || data_shards + parity_shards > ICSS_MAX_SHARDS ||
        lost_shards > parity_shards) {
        fprintf(stderr, "icss: invalid erasure parameters\n");
        return 1;
    }
    if (!rs_build_matrix((uint8_t)data_shards, (uint8_t)parity_shards, matrix)) {
        fprintf(stderr, "icss: cannot build erasure coding matrix\n");
        return 2;
    }
    data = (unsigned char *)malloc((size_t)data_shards * shard_size);
    encoded = (unsigned char *)malloc((size_t)(data_shards + parity_shards) * shard_size);
    contents = (unsigned char *)malloc((size_t)data_shards * shard_size);
    recovered = (unsigned char *)malloc((size_t)data_shards * shard_size);
    present = (unsigned char *)calloc(data_shards + parity_shards, 1U);
    if (data == NULL || encoded == NULL || contents == NULL || recovered == NULL ||
        present == NULL) {
        fprintf(stderr, "icss: cannot allocate test buffers\n");
        goto cleanup;
    }
    for (group = 0; group < data_shards; ++group) {
        size_t index;
        for (index = 0; index < shard_size; ++index) {
            data[(size_t)group * shard_size + index] =
                (unsigned char)(index * 11U + group * 3U);
        }
    }
    /* Encode: data shards stay as they are, parity shards are the matrix rows. */
    for (group = 0; group < data_shards; ++group) {
        memcpy(encoded + (size_t)group * shard_size, data + (size_t)group * shard_size,
            shard_size);
    }
    for (group = data_shards; group < data_shards + parity_shards; ++group) {
        size_t position;
        for (position = 0; position < shard_size; ++position) {
            unsigned char value = 0U;
            uint32_t column;
            for (column = 0; column < data_shards; ++column) {
                value ^= gf_mul(matrix[group * data_shards + column],
                    data[(size_t)column * shard_size + position]);
            }
            encoded[(size_t)group * shard_size + position] = value;
        }
    }
    /*
     * Simulate the loss of shards. The first 'lost_shards' data shards are
     * dropped, which is the worst case: the parity shards have to replace
     * them.
     */
    for (group = 0; group < lost_shards; ++group) {
        present[group] = 0U;
    }
    for (group = lost_shards; group < data_shards + parity_shards; ++group) {
        present[group] = 1U;
    }
    {
        uint8_t rows[ICSS_MAX_SHARDS];
        uint32_t available = 0;
        uint32_t position;
        for (position = 0; position < data_shards + parity_shards; ++position) {
            if (present[position]) rows[available++] = (uint8_t)position;
        }
        if (available < data_shards) {
            fprintf(stderr, "icss: not enough shards to recover\n");
            goto cleanup;
        }
        for (position = 0; position < data_shards; ++position) {
            memcpy(contents + (size_t)position * shard_size,
                encoded + (size_t)rows[position] * shard_size, shard_size);
        }
        if (data_shards > 1U &&
            !rs_recover_group((uint8_t)data_shards, matrix, rows, contents,
                shard_size, recovered)) {
            fprintf(stderr, "icss: erasure decoding failed\n");
            goto cleanup;
        }
        if (data_shards == 1U) {
            memcpy(recovered, contents, shard_size);
        }
        if (memcmp(recovered, data, (size_t)data_shards * shard_size) != 0) {
            fprintf(stderr, "icss: recovered data does not match the original\n");
            goto cleanup;
        }
    }
    printf("erasure check passed: k=%u m=%u recovered with %u lost shard(s)\n",
        (unsigned int)data_shards, (unsigned int)parity_shards,
        (unsigned int)lost_shards);
    success = 0;
cleanup:
    if (data != NULL) free(data);
    if (encoded != NULL) free(encoded);
    if (contents != NULL) free(contents);
    if (recovered != NULL) free(recovered);
    free(present);
    return success;
}

static int command_status(const char *endpoint, uint16_t ring_id,
    int list_files, uint16_t discovery_port)
{
    char host[256];
    char port[16];
    char response[4096];
    size_t used = 0;
    icss_socket_t socket;
    if (!parse_endpoint(endpoint, host, sizeof(host), port, sizeof(port))) {
        fprintf(stderr, "icss: invalid endpoint\n");
        return 1;
    }
    if (!socket_runtime_start()) {
        return 2;
    }
    socket = connect_to(host, port);
    if (socket == ICSS_INVALID_SOCKET || !send_control(socket, 'S', ring_id, 0U)) {
        fprintf(stderr, "icss: cannot query node %s:%s\n", host, port);
        if (socket != ICSS_INVALID_SOCKET) {
            icss_socket_close(socket);
        }
        socket_runtime_stop();
        return 2;
    }
    while (used + 1U < sizeof(response)) {
        int count = recv(socket, response + used, (int)(sizeof(response) - used - 1U), 0);
        if (count <= 0) {
            break;
        }
        used += (size_t)count;
    }
    response[used] = '\0';
    icss_socket_close(socket);

    if (used == 0U) {
        fprintf(stderr, "icss: empty status response\n");
        socket_runtime_stop();
        return 2;
    }

    if (list_files) {
        /*
         * Discover every peer in the ring and collect the catalogue from each.
         * Merge all file entries, deduplicating by content hash, and append a
         * "files" array to the status JSON so the whole ring is listed.
         */
        icss_peer peers[ICSS_MAX_PEERS];
        int peer_count = discover_ring_peers(discovery_port, ring_id,
            peers, ICSS_MAX_PEERS, 5);
        char *files_json = NULL;
        size_t files_cap = 256U, files_used = 0U;
        int i;

        icss_seen_reset();

        files_json = (char *)malloc(files_cap);
        if (files_json == NULL) {
            fprintf(stderr, "icss: out of memory\n");
            socket_runtime_stop();
            return 2;
        }
        files_used = (size_t)snprintf(files_json, files_cap, "\"files\":[");
        int first_file = 1;

        for (i = 0; i < peer_count; ++i) {
            char p_host[INET_ADDRSTRLEN];
            char p_port[16];
            char *p_response = NULL;
            size_t p_cap = 0, p_used = 0;
            icss_socket_t psocket;
            struct in_addr addr;
            const char *cursor;

            addr.s_addr = peers[i].ip_address;
            if (inet_ntop(AF_INET, &addr, p_host, sizeof(p_host)) == NULL) continue;
            snprintf(p_port, sizeof(p_port), "%u", (unsigned int)peers[i].tcp_port);

            if (!socket_runtime_start()) continue;
            psocket = connect_to(p_host, p_port);
            if (psocket == ICSS_INVALID_SOCKET ||
                !send_control(psocket, ICSS_OP_LIST, ring_id, 0U)) {
                if (psocket != ICSS_INVALID_SOCKET) icss_socket_close(psocket);
                socket_runtime_stop();
                continue;
            }

            p_response = (char *)malloc(8192U);
            if (!p_response) {
                icss_socket_close(psocket);
                socket_runtime_stop();
                continue;
            }
            p_cap = 8192U;
            p_used = 0;
            for (;;) {
                int count;
                if (p_used + 1024U >= p_cap) {
                    char *bigger_ptr;
                    p_cap *= 2U;
                    bigger_ptr = (char *)realloc(p_response, p_cap);
                    if (!bigger_ptr) break;
                    p_response = bigger_ptr;
                }
                count = recv(psocket, p_response + p_used,
                    (int)(p_cap - p_used - 1U), 0);
                if (count <= 0) break;
                p_used += (size_t)count;
            }
            p_response[p_used] = '\0';
            icss_socket_close(psocket);
            socket_runtime_stop();

            if (p_used == 0U) {
                free(p_response);
                continue;
            }

            cursor = p_response;
            while ((cursor = strstr(cursor, "{\"name\":")) != NULL) {
                char name[ICSS_NAME_SIZE];
                char hash[65];
                char key_id_text[ICSS_KEY_ID_SIZE * 2 + 1];
                unsigned char hash_bytes[32];
                int encrypted;
                const char *record_end = strchr(cursor, '}');
                if (!record_end) break;
                if (!parse_catalogue_record(cursor, name, sizeof(name),
                    hash, sizeof(hash), key_id_text,
                    sizeof(key_id_text), &encrypted)) {
                    break;
                }
                if (!parse_hash(hash, hash_bytes)) {
                    cursor = record_end + 1;
                    continue;
                }
                /* Deduplicate across peers in O(1) expected time via hash set. */
                if (icss_seen_contains(hash_bytes)) {
                    cursor = record_end + 1;
                    continue;
                }
                icss_seen_add(hash_bytes);
                if (files_used + 200U >= files_cap) {
                    char *bigger_ptr;
                    files_cap *= 2U;
                    bigger_ptr = (char *)realloc(files_json, files_cap);
                    if (!bigger_ptr) {
                        free(p_response);
                        free(files_json);
                        socket_runtime_stop();
                        return 2;
                    }
                    files_json = bigger_ptr;
                }
                files_used += (size_t)snprintf(files_json + files_used,
                    files_cap - files_used,
                    "%s{\"name\":\"%s\",\"sha256\":\"%s\",\"encrypted\":%s,\"key_id\":\"%s\"}",
                    first_file ? "" : ",", name, hash,
                    encrypted ? "true" : "false", key_id_text);
                first_file = 0;
                cursor = record_end + 1;
            }
            free(p_response);
        }

        if (files_used + 8U >= files_cap) {
            char *bigger_ptr;
            files_cap = files_used + 16U;
            bigger_ptr = (char *)realloc(files_json, files_cap);
            if (!bigger_ptr) {
                free(files_json);
                socket_runtime_stop();
                return 2;
            }
            files_json = bigger_ptr;
        }
        files_used += (size_t)snprintf(files_json + files_used,
            files_cap - files_used, "]");

        {
            char *last_brace = strrchr(response, '}');
            if (last_brace) {
                *last_brace = '\0';
                printf("%s,%s}\n", response, files_json);
            } else {
                printf("%s,%s}\n", response, files_json);
            }
        }
        free(files_json);
    } else {
        fputs(response, stdout);
    }

    socket_runtime_stop();
    return 0;
}

static void print_help(FILE *stream)
{
    fprintf(stream,
        "icss %s - decentralized circulating storage prototype\n"
        "Usage: icss <command> [options]\n\n"
        "Commands:\n"
        "  +------------------+--------------------------------------------------+\n"
        "  | Command          | Description                                      |\n"
        "  +------------------+--------------------------------------------------+\n"
        "  | node             | Run a permanent storage node                     |\n"
        "  | inject           | Put a dataset into the ring                      |\n"
        "  | fetch            | Read a dataset by hash or name (searches ring)   |\n"
        "  | status           | Query the state of a node                        |\n"
        "  | ls               | List the datasets in the ring catalogue          |\n"
        "  | hash             | Print a file's SHA-256 digest                    |\n"
        "  | protocol         | Print the wire frame layout                      |\n"
        "  | key-check        | Validate a 32-byte AES-256 key file              |\n"
        "  | selftest         | Test frame, hash, crypto and erasure primitives  |\n"
        "  | erasure-check    | Verify the erasure code against shard loss       |\n"
        "  | version          | Show version and platform                        |\n"
        "  | help             | Show this help                                   |\n"
        "  +------------------+--------------------------------------------------+\n\n"
        "Run 'icss help <command>' for the options of a command.\n"
        "This prototype does not claim durable storage or zero-loss failover.\n",
        ICSS_VERSION);
}

static int hash_file(const char *path)
{
    FILE *input = NULL;
    EVP_MD_CTX *context = NULL;
    unsigned char buffer[1024U * 1024U];
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_size = 0;
    size_t count;
    int result = 2;
    size_t index;

    input = fopen(path, "rb");
    if (input == NULL) {
        fprintf(stderr, "icss: cannot open '%s': %s\n", path, strerror(errno));
        return 2;
    }
    context = EVP_MD_CTX_new();
    if (context == NULL || EVP_DigestInit_ex(context, EVP_sha256(), NULL) != 1) {
        fprintf(stderr, "icss: cannot initialize SHA-256\n");
        goto cleanup;
    }
    while ((count = fread(buffer, 1, sizeof(buffer), input)) != 0) {
        if (EVP_DigestUpdate(context, buffer, count) != 1) {
            fprintf(stderr, "icss: SHA-256 update failed\n");
            goto cleanup;
        }
    }
    if (ferror(input)) {
        fprintf(stderr, "icss: read failed for '%s'\n", path);
        goto cleanup;
    }
    if (EVP_DigestFinal_ex(context, digest, &digest_size) != 1 || digest_size != 32U) {
        fprintf(stderr, "icss: SHA-256 finalization failed\n");
        goto cleanup;
    }
    for (index = 0; index < digest_size; ++index) {
        printf("%02x", digest[index]);
    }
    putchar('\n');
    result = 0;

cleanup:
    OPENSSL_cleanse(buffer, sizeof(buffer));
    OPENSSL_cleanse(digest, sizeof(digest));
    EVP_MD_CTX_free(context);
    fclose(input);
    return result;
}

static void print_protocol(void)
{
    printf("ICSS data frame: %u-byte header followed by payload\n",
        ICSS_HEADER_SIZE);
    puts("offset  size  field");
    puts("0       4     magic (ICSS)");
    puts("4       2     version and flags");
    puts("6       2     ring_id (network byte order)");
    puts("8       8     circulation sequence / hop counter (network byte order)");
    puts("16      4     chunk_id (network byte order)");
    puts("20      4     total_chunks (network byte order)");
    puts("24      8     file_size (network byte order)");
    puts("32      4     ttl (network byte order)");
    puts("36      4     chunk_size (network byte order)");
    puts("40      4     payload_size (network byte order)");
    puts("44      32    file_sha256");
    puts("76      32    payload_sha256");
    puts("108     12    AES-GCM IV");
    puts("120     16    AES-GCM tag");
    puts("136     1     data_shards (k)");
    puts("137     1     parity_shards (m)");
    puts("138     1     shard_pos");
    puts("139     1     reserved");
    puts("140     4     shard_group (network byte order)");
    puts("144     32    key_id (SHA-256 fingerprint of the AES key)");
    puts("176     64    file name (NUL padded)");
    puts("");
    puts("Control frames: 4 byte magic + operation + flags + ring_id (8 bytes total)");
    puts("  ICSF  'P' pause, 'R' resume  (backpressure, hop by hop)");
    puts("  ICSC  'I' inject, 'F' fetch, 'S' status, 'L' list");
    puts("  ICSP  peer link handshake");
    puts("");
    puts("UDP discovery heartbeat: 36 bytes, magic ICSD, node id, ip, port, ring, time");
}

static void print_command_help(const char *command)
{
    if (strcmp(command, "node") == 0) {
        puts("usage: icss node --listen PORT [options]");
        puts("  -l, --listen PORT          local TCP forwarding port (required)");
        puts("  -b, --broadcast-port PORT  UDP discovery port (default 7777)");
        puts("  -c, --chunk-size BYTES     shard size (default 16777216)");
        puts("  -q, --queue-depth N        downstream queue depth (default 32)");
        puts("  -r, --ring-id ID           logical ring (default 0)");
        puts("  -i, --index-path PATH      hash metadata index file");
        puts("      --next IP:PORT         manual downstream, skips auto discovery");
    } else if (strcmp(command, "inject") == 0) {
        puts("usage: icss inject FILE IP:PORT [options]");
        puts("      --key KEYFILE          AES-256 key, enables encrypted mode");
        puts("  -r, --ring-id ID           logical ring (default 0)");
        puts("  -c, --chunk-size BYTES     shard size (default 16777216)");
        puts("      --data-shards K        erasure code data shards per group");
        puts("      --parity-shards M      erasure code parity shards per group");
    } else if (strcmp(command, "fetch") == 0) {
        puts("usage: icss fetch [FILE_SHA256|--name NAME] OUTPUT_FILE [IP:PORT] [options]");
        puts("      --name NAME            file name to fetch (searches entire ring)");
        puts("      --key KEYFILE          AES-256 key for encrypted datasets");
        puts("  -r, --ring-id ID           logical ring (default 0)");
        puts("      --discovery-port PORT  UDP discovery port (default 7777)");
        puts("");
        puts("  When using --name, the entire ring is searched for the file.");
        puts("  The file name must be unique within the same key (or unencrypted).");
        puts("  IP:PORT is optional with --name, required with FILE_SHA256.");
    } else if (strcmp(command, "status") == 0) {
        puts("usage: icss status IP:PORT [--ring-id ID] [--list-files] [--discovery-port PORT]");
    } else if (strcmp(command, "ls") == 0) {
        puts("usage: icss ls [IP:PORT] [--key KEYFILE] [--ring-id ID] [--discovery-port PORT]");
        puts("Lists the datasets of the ring catalogue with their name and SHA-256.");
        puts("Without IP:PORT, discovers all peers and lists the entire ring.");
        puts("With --key only the datasets that the key can decrypt are listed.");
    } else if (strcmp(command, "erasure-check") == 0) {
        puts("usage: icss erasure-check [--data-shards K] [--parity-shards M] [--lost N]");
        puts("Verifies that a group survives the loss of N shards per group.");
    } else {
        print_help(stdout);
    }
}

static int option_value(int argc, char **argv, int *index, const char **value)
{
    if (*index + 1 >= argc) {
        return 0;
    }
    *value = argv[++(*index)];
    return 1;
}

static int parse_ring_id(const char *text, uint16_t *ring_id)
{
    uint32_t value;
    if (!parse_u32(text, 0U, UINT16_MAX, &value)) {
        return 0;
    }
    *ring_id = (uint16_t)value;
    return 1;
}

static int command_node(int argc, char **argv)
{
    const char *listen_port = NULL;
    const char *next = NULL;
    const char *index_path = NULL;
    uint32_t chunk_size = ICSS_DEFAULT_CHUNK_SIZE;
    uint32_t discovery_port = 7777U;
    uint32_t queue_depth = ICSS_DEFAULT_QUEUE_DEPTH;
    uint16_t ring_id = 0;
    int index;
    for (index = 2; index < argc; ++index) {
        const char *value;
        if (strcmp(argv[index], "--help") == 0 || strcmp(argv[index], "-h") == 0) {
            print_command_help("node");
            return 0;
        } else if (strcmp(argv[index], "--listen") == 0 || strcmp(argv[index], "-l") == 0) {
            if (!option_value(argc, argv, &index, &listen_port)) return 1;
        } else if (strcmp(argv[index], "--next") == 0) {
            if (!option_value(argc, argv, &index, &next)) return 1;
        } else if (strcmp(argv[index], "--index-path") == 0) {
            if (!option_value(argc, argv, &index, &index_path)) return 1;
        } else if (strcmp(argv[index], "--broadcast-port") == 0 ||
            strcmp(argv[index], "-b") == 0) {
            if (!option_value(argc, argv, &index, &value) ||
                !parse_u32(value, 1U, UINT16_MAX, &discovery_port)) return 1;
        } else if (strcmp(argv[index], "--queue-depth") == 0 ||
            strcmp(argv[index], "-q") == 0) {
            if (!option_value(argc, argv, &index, &value) ||
                !parse_u32(value, 1U, 65536U, &queue_depth)) return 1;
        } else if (strcmp(argv[index], "--chunk-size") == 0 || strcmp(argv[index], "-c") == 0) {
            if (!option_value(argc, argv, &index, &value) ||
                !parse_u32(value, 1U, ICSS_MAX_CHUNK_SIZE, &chunk_size)) return 1;
        } else if (strcmp(argv[index], "--ring-id") == 0 || strcmp(argv[index], "-r") == 0) {
            if (!option_value(argc, argv, &index, &value) ||
                !parse_ring_id(value, &ring_id)) return 1;
        } else {
            fprintf(stderr, "icss: unknown node option '%s'\n", argv[index]);
            return 1;
        }
    }
    if (listen_port == NULL) {
        fprintf(stderr, "icss: node requires --listen PORT\n");
        return 1;
    }
    return node_run(listen_port, next, ring_id, chunk_size, index_path,
        (uint16_t)discovery_port, queue_depth);
}

static int command_inject_cli(int argc, char **argv)
{
    const char *key_path = NULL;
    uint16_t ring_id = 0;
    uint32_t chunk_size = ICSS_DEFAULT_CHUNK_SIZE;
    uint32_t data_shards = 1U;
    uint32_t parity_shards = 0U;
    int index;
    if (argc >= 3 && strcmp(argv[2], "--help") == 0) {
        print_command_help("inject");
        return 0;
    }
    if (argc < 4) {
        fprintf(stderr, "usage: icss inject FILE IP:PORT [options]\n");
        return 1;
    }
    for (index = 4; index < argc; ++index) {
        const char *value;
        if (strcmp(argv[index], "--help") == 0 || strcmp(argv[index], "-h") == 0) {
            print_command_help("inject");
            return 0;
        } else if (strcmp(argv[index], "--key") == 0) {
            if (!option_value(argc, argv, &index, &key_path)) return 1;
        } else if (strcmp(argv[index], "--ring-id") == 0 || strcmp(argv[index], "-r") == 0) {
            if (!option_value(argc, argv, &index, &value) || !parse_ring_id(value, &ring_id)) return 1;
        } else if (strcmp(argv[index], "--chunk-size") == 0 || strcmp(argv[index], "-c") == 0) {
            if (!option_value(argc, argv, &index, &value) ||
                !parse_u32(value, 1U, ICSS_MAX_CHUNK_SIZE, &chunk_size)) return 1;
        } else if (strcmp(argv[index], "--data-shards") == 0) {
            if (!option_value(argc, argv, &index, &value) ||
                !parse_u32(value, 1U, ICSS_MAX_SHARDS, &data_shards)) return 1;
        } else if (strcmp(argv[index], "--parity-shards") == 0) {
            if (!option_value(argc, argv, &index, &value) ||
                !parse_u32(value, 0U, ICSS_MAX_SHARDS, &parity_shards)) return 1;
        } else {
            fprintf(stderr, "icss: unknown inject option '%s'\n", argv[index]);
            return 1;
        }
    }
    if (data_shards + parity_shards > ICSS_MAX_SHARDS) {
        fprintf(stderr, "icss: data and parity shards exceed the limit\n");
        return 1;
    }
    return command_inject(argv[2], argv[3], ring_id, chunk_size, key_path,
        (uint8_t)data_shards, (uint8_t)parity_shards);
}

static int command_fetch_cli(int argc, char **argv)
{
    const char *key_path = NULL;
    const char *name = NULL;
    const char *hash_text = NULL;
    const char *output_path = NULL;
    const char *endpoint = NULL;
    uint16_t ring_id = 0;
    uint16_t discovery_port = 7777;
    int index;
    if (argc >= 3 && strcmp(argv[2], "--help") == 0) {
        print_command_help("fetch");
        return 0;
    }
    if (argc < 4) {
        fprintf(stderr, "usage: icss fetch [FILE_SHA256|--name NAME] OUTPUT_FILE [IP:PORT] [options]\n");
        return 1;
    }
    /* Handle the first positional argument: either a hash or --name */
    if (strcmp(argv[2], "--name") == 0) {
        if (argc < 4) {
            fprintf(stderr, "usage: icss fetch --name NAME OUTPUT_FILE [options]\n");
            return 1;
        }
        name = argv[3];
        index = 4;
    } else {
        hash_text = argv[2];
        index = 3;
    }
    for (; index < argc; ++index) {
        const char *value;
        if (strcmp(argv[index], "--help") == 0 || strcmp(argv[index], "-h") == 0) {
            print_command_help("fetch");
            return 0;
        } else if (strcmp(argv[index], "--name") == 0) {
            if (!option_value(argc, argv, &index, &name)) return 1;
        } else if (strcmp(argv[index], "--key") == 0) {
            if (!option_value(argc, argv, &index, &key_path)) return 1;
        } else if (strcmp(argv[index], "--ring-id") == 0 || strcmp(argv[index], "-r") == 0) {
            if (!option_value(argc, argv, &index, &value) || !parse_ring_id(value, &ring_id)) return 1;
        } else if (strcmp(argv[index], "--discovery-port") == 0) {
            if (!option_value(argc, argv, &index, &value) ||
                !parse_u32(value, 1U, UINT16_MAX, (uint32_t *)&discovery_port)) return 1;
        } else if (!hash_text && !name) {
            hash_text = argv[index];
        } else if (!output_path) {
            output_path = argv[index];
        } else if (!endpoint) {
            endpoint = argv[index];
        } else {
            fprintf(stderr, "icss: unknown fetch option '%s'\n", argv[index]);
            return 1;
        }
    }
    /* hash_text 与 name 二选一，至少提供一个 */
    if ((hash_text == NULL) == (name == NULL)) {
        fprintf(stderr, "icss: exactly one of FILE_SHA256 or --name NAME must be given\n");
        return 1;
    }
    if (!output_path) {
        fprintf(stderr, "usage: icss fetch [FILE_SHA256|--name NAME] OUTPUT_FILE [IP:PORT] [options]\n");
        return 1;
    }
    /* When using --name, endpoint is optional (will search entire ring).
       When using hash, endpoint is required. */
    if (hash_text && !endpoint) {
        fprintf(stderr, "icss: endpoint IP:PORT required when using FILE_SHA256\n");
        return 1;
    }
    return command_fetch(hash_text, name, output_path, endpoint ? endpoint : "", ring_id, key_path, discovery_port);
}

static int command_status_cli(int argc, char **argv)
{
    uint16_t ring_id = 0;
    int list_files = 0;
    uint16_t discovery_port = 7777;
    int index;
    if (argc < 3) {
        fprintf(stderr, "usage: icss status IP:PORT [--ring-id ID] [--list-files] [--discovery-port PORT]\n");
        return 1;
    }
    if (argc >= 3 && strcmp(argv[2], "--help") == 0) {
        print_command_help("status");
        return 0;
    }
    for (index = 3; index < argc; ++index) {
        const char *value;
        if (strcmp(argv[index], "--list-files") == 0) {
            list_files = 1;
            continue;
        }
        if (strcmp(argv[index], "--ring-id") == 0 || strcmp(argv[index], "-r") == 0) {
            if (!option_value(argc, argv, &index, &value) || !parse_ring_id(value, &ring_id)) return 1;
            continue;
        }
        if (strcmp(argv[index], "--discovery-port") == 0) {
            if (!option_value(argc, argv, &index, &value) ||
                !parse_u32(value, 1U, UINT16_MAX, (uint32_t *)&discovery_port)) return 1;
            continue;
        }
        fprintf(stderr, "icss: invalid status option\n");
        return 1;
    }
    return command_status(argv[2], ring_id, list_files, discovery_port);
}

static int command_list_cli(int argc, char **argv)
{
    const char *key_path = NULL;
    const char *endpoint = NULL;
    uint16_t ring_id = 0;
    uint16_t discovery_port = 7777;
    int index;
    if (argc < 3) {
        fprintf(stderr, "usage: icss ls [IP:PORT] [--key FILE] [--ring-id ID] [--discovery-port PORT]\n");
        return 1;
    }
    if (argc >= 3 && strcmp(argv[2], "--help") == 0) {
        print_command_help("ls");
        return 0;
    }
    /* argv[2] may be an endpoint or the first option flag */
    if (argv[2][0] != '-') {
        endpoint = argv[2];
    }
    for (index = (endpoint ? 3 : 2); index < argc; ++index) {
        const char *value;
        if (strcmp(argv[index], "--help") == 0 || strcmp(argv[index], "-h") == 0) {
            print_command_help("ls");
            return 0;
        } else if (strcmp(argv[index], "--key") == 0) {
            if (!option_value(argc, argv, &index, &key_path)) return 1;
        } else if (strcmp(argv[index], "--ring-id") == 0 || strcmp(argv[index], "-r") == 0) {
            if (!option_value(argc, argv, &index, &value) || !parse_ring_id(value, &ring_id)) return 1;
        } else if (strcmp(argv[index], "--discovery-port") == 0) {
            if (!option_value(argc, argv, &index, &value) ||
                !parse_u32(value, 1U, UINT16_MAX, (uint32_t *)&discovery_port)) return 1;
        } else {
            fprintf(stderr, "icss: unknown ls option '%s'\n", argv[index]);
            return 1;
        }
    }
    return command_list(endpoint, ring_id, key_path, discovery_port);
}

static int command_erasure_check_cli(int argc, char **argv)
{
    uint32_t data_shards = 4U;
    uint32_t parity_shards = 2U;
    uint32_t lost = 1U;
    int index;
    for (index = 2; index < argc; ++index) {
        const char *value;
        if (strcmp(argv[index], "--help") == 0 || strcmp(argv[index], "-h") == 0) {
            print_command_help("erasure-check");
            return 0;
        } else if (strcmp(argv[index], "--data-shards") == 0) {
            if (!option_value(argc, argv, &index, &value) ||
                !parse_u32(value, 1U, ICSS_MAX_SHARDS, &data_shards)) return 1;
        } else if (strcmp(argv[index], "--parity-shards") == 0) {
            if (!option_value(argc, argv, &index, &value) ||
                !parse_u32(value, 0U, ICSS_MAX_SHARDS, &parity_shards)) return 1;
        } else if (strcmp(argv[index], "--lost") == 0) {
            if (!option_value(argc, argv, &index, &value) ||
                !parse_u32(value, 0U, ICSS_MAX_SHARDS, &lost)) return 1;
        } else {
            fprintf(stderr, "icss: unknown erasure-check option '%s'\n", argv[index]);
            return 1;
        }
    }
    return command_erasure_check(data_shards, parity_shards, lost);
}

int main(int argc, char **argv)
{
    if (argc == 3 && strcmp(argv[1], "help") == 0) {
        print_command_help(argv[2]);
        return 0;
    }
    if (argc < 2 || strcmp(argv[1], "help") == 0 ||
        strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        print_help(stdout);
        return argc < 2 ? 0 : 0;
    }
    if (strcmp(argv[1], "version") == 0 || strcmp(argv[1], "--version") == 0 ||
        strcmp(argv[1], "-v") == 0) {
#ifdef _WIN32
        printf("icss %s (Windows/Winsock)\n", ICSS_VERSION);
#elif defined(__APPLE__)
        printf("icss %s (Unix/kqueue target)\n", ICSS_VERSION);
#else
        printf("icss %s (Unix/POSIX target)\n", ICSS_VERSION);
#endif
        return 0;
    }
    if (strcmp(argv[1], "protocol") == 0) {
        print_protocol();
        return 0;
    }
    if (strcmp(argv[1], "selftest") == 0) {
        return run_self_test() ? 0 : 2;
    }
    if (strcmp(argv[1], "key-check") == 0) {
        if (argc != 3) {
            fprintf(stderr, "usage: icss key-check <key-file>\n");
            return 1;
        }
        return check_key_file(argv[2]);
    }
    if (strcmp(argv[1], "hash") == 0) {
        if (argc != 3) {
            fprintf(stderr, "usage: icss hash <file>\n");
            return 1;
        }
        return hash_file(argv[2]);
    }
    if (strcmp(argv[1], "node") == 0) return command_node(argc, argv);
    if (strcmp(argv[1], "inject") == 0) return command_inject_cli(argc, argv);
    if (strcmp(argv[1], "fetch") == 0) return command_fetch_cli(argc, argv);
    if (strcmp(argv[1], "status") == 0) return command_status_cli(argc, argv);
    if (strcmp(argv[1], "ls") == 0) return command_list_cli(argc, argv);
    if (strcmp(argv[1], "erasure-check") == 0) return command_erasure_check_cli(argc, argv);
    fprintf(stderr, "icss: unsupported command '%s'\n", argv[1]);
    fprintf(stderr, "icss: use 'icss help' for commands\n");
    return 1;
}