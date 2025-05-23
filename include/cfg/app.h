/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2016 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __INCLUDE_APP_H__
#define __INCLUDE_APP_H__

#include <stdint.h>
#include <string.h>

#include <rte_common.h>
#include <rte_mempool.h>
#include <rte_ring.h>
#include <rte_sched.h>
#include <cmdline_parse.h>

#include <rte_ethdev.h>
#ifdef RTE_LIBRTE_KNI
#include <rte_kni.h>
#endif

#include "cpu_core_map.h"
#include "qnsm_service_ex.h"

#define APP_MAP(XX)                         \
  XX(EN_QNSM_SESSM,     "SESSM")            \
  XX(EN_QNSM_SIP_AGG,   "SIP_IN_AGG")       \
  XX(EN_QNSM_VIP_AGG,   "VIP_AGG")          \
  XX(EN_QNSM_EDGE,      "EDGE")             \
  XX(EN_QNSM_MASTER,    "MASTER")           \
  XX(EN_QNSM_DETECT,    "DETECT")           \
  XX(EN_QNSM_DUMP,      "DUMP")             \
  XX(EN_QNSM_TEST,      "TEST")             \
  XX(EN_QNSM_DUMMY,     "DUMMY")

#define APP_PARAM_NAME_SIZE                      (64)
#define APP_LINK_PCI_BDF_SIZE                    16

#ifndef APP_LINK_MAX_HWQ_IN
#define APP_LINK_MAX_HWQ_IN                      128
#endif

#ifndef APP_LINK_MAX_HWQ_OUT
#define APP_LINK_MAX_HWQ_OUT                     128
#endif

struct app_mempool_params {
    char *name;
    uint32_t parsed;
    uint32_t buffer_size;
    uint32_t pool_size;
    uint32_t cache_size;
    uint32_t cpu_socket_id;
    uint32_t private_size;
};

struct app_link_params {
    char *name;
    uint32_t parsed;
    uint32_t pmd_id; /* Generated based on port mask */
    uint32_t arp_q; /* 0 = Disabled (packets go to default queue 0) */
    uint32_t tcp_syn_q; /* 0 = Disabled (pkts go to default queue) */
    uint32_t ip_local_q; /* 0 = Disabled (pkts go to default queue 0) */
    uint32_t tcp_local_q; /* 0 = Disabled (pkts go to default queue 0) */
    uint32_t udp_local_q; /* 0 = Disabled (pkts go to default queue 0) */
    uint32_t sctp_local_q; /* 0 = Disabled (pkts go to default queue 0) */
    uint32_t rss_qs[APP_LINK_MAX_HWQ_IN];
    uint32_t n_rss_qs;
    uint32_t symmetrical_rss;
    uint64_t rss_proto_ipv4;
    uint64_t rss_proto_ipv6;
    uint64_t rss_proto_l2;
    uint32_t promisc;
    uint32_t state; /* DOWN = 0, UP = 1 */
    uint32_t ip; /* 0 = Invalid */
    uint32_t depth; /* Valid only when IP is valid */
    uint64_t mac_addr; /* Read from HW */
    char pci_bdf[APP_LINK_PCI_BDF_SIZE];

    struct rte_eth_conf conf;
};

struct app_pktq_hwq_in_params {
    char *name;
    uint32_t parsed;
    uint32_t mempool_id; /* Position in the app->mempool_params */
    uint32_t size;
    uint32_t burst;

    struct rte_eth_rxconf conf;
};

struct app_pktq_hwq_out_params {
    char *name;
    uint32_t parsed;
    uint32_t size;
    uint32_t burst;
    uint32_t dropless;
    uint64_t n_retries;
    struct rte_eth_txconf conf;
};

struct app_pktq_swq_params {
    char *name;
    uint32_t parsed;
    uint32_t size;
    uint32_t burst_read;
    uint32_t burst_write;
    uint32_t dropless;
    uint64_t n_retries;
    uint32_t cpu_socket_id;
    uint32_t ipv4_frag;
    uint32_t ipv6_frag;
    uint32_t ipv4_ras;
    uint32_t ipv6_ras;
    uint32_t mtu;
    uint32_t metadata_size;
    uint32_t mempool_direct_id;
    uint32_t mempool_indirect_id;
    uint32_t mempool_id;
    uint32_t dump;
    uint32_t dup;
};

struct app_pktq_kni_params {
    char *name;
    uint32_t parsed;

    uint32_t socket_id;
    uint32_t core_id;
    uint32_t hyper_th_id;
    uint32_t force_bind;

    uint32_t mempool_id; /* Position in the app->mempool_params */
    uint32_t burst_read;
    uint32_t burst_write;
    uint32_t dropless;
    uint64_t n_retries;
};

#ifndef APP_FILE_NAME_SIZE
#define APP_FILE_NAME_SIZE                       256
#endif

#ifndef APP_MAX_SCHED_SUBPORTS
#define APP_MAX_SCHED_SUBPORTS                   8
#endif

#ifndef APP_MAX_SCHED_PIPES
#define APP_MAX_SCHED_PIPES                      4096
#endif

struct app_pktq_tm_params {
    char *name;
    uint32_t parsed;
    const char *file_name;
    struct rte_sched_port_params sched_port_params;
    struct rte_sched_subport_params
        sched_subport_params[APP_MAX_SCHED_SUBPORTS];
    struct rte_sched_pipe_params
        sched_pipe_profiles[RTE_SCHED_PIPE_PROFILES_PER_PORT];
    int sched_pipe_to_profile[APP_MAX_SCHED_SUBPORTS * APP_MAX_SCHED_PIPES];
    uint32_t burst_read;
    uint32_t burst_write;
};

struct app_pktq_tap_params {
    char *name;
    uint32_t parsed;
    uint32_t burst_read;
    uint32_t burst_write;
    uint32_t dropless;
    uint64_t n_retries;
    uint32_t mempool_id; /* Position in the app->mempool_params */
};

struct app_pktq_source_params {
    char *name;
    uint32_t parsed;
    uint32_t mempool_id; /* Position in the app->mempool_params array */
    uint32_t burst;
    const char *file_name; /* Full path of PCAP file to be copied to mbufs */
    uint32_t n_bytes_per_pkt;
};

struct app_pktq_sink_params {
    char *name;
    uint8_t parsed;
    const char *file_name; /* Full path of PCAP file to be copied to mbufs */
    uint32_t n_pkts_to_dump;
};

struct app_msgq_params {
    char *name;
    uint32_t parsed;
    uint32_t size;
    uint32_t cpu_socket_id;
};

enum app_pktq_in_type {
    APP_PKTQ_IN_HWQ,
    APP_PKTQ_IN_SWQ,
    APP_PKTQ_IN_TM,
    APP_PKTQ_IN_TAP,
    APP_PKTQ_IN_KNI,
    APP_PKTQ_IN_SOURCE,
    APP_PKTQ_IN_MAX,
};

struct app_pktq_in_params {
    enum app_pktq_in_type type;
    uint32_t id; /* Position in the appropriate app array */
};

enum app_pktq_out_type {
    APP_PKTQ_OUT_HWQ,
    APP_PKTQ_OUT_SWQ,
    APP_PKTQ_OUT_TM,
    APP_PKTQ_OUT_TAP,
    APP_PKTQ_OUT_KNI,
    APP_PKTQ_OUT_SINK,
    APP_PKTQ_OUT_MAX
};

struct app_pktq_out_params {
    enum app_pktq_out_type type;
    uint32_t id; /* Position in the appropriate app array */
};

#define APP_PIPELINE_TYPE_SIZE                   (64)

#define APP_MAX_PIPELINE_PKTQ_IN                 (64)
#define APP_MAX_PIPELINE_PKTQ_OUT                (64)
#define APP_MAX_PIPELINE_MSGQ_IN                 (16)
#define APP_MAX_PIPELINE_MSGQ_OUT                (16)

#define APP_MAX_PIPELINE_ARGS                    (64)

struct app_pipeline_params {
    char *name;
    uint8_t parsed;

    char type[APP_PIPELINE_TYPE_SIZE];

    uint32_t socket_id;
    uint32_t core_id;
    uint32_t hyper_th_id;

    struct app_pktq_in_params pktq_in[APP_MAX_PIPELINE_PKTQ_IN];
    struct app_pktq_out_params pktq_out[APP_MAX_PIPELINE_PKTQ_OUT];
    uint32_t msgq_in[APP_MAX_PIPELINE_MSGQ_IN];
    uint32_t msgq_out[APP_MAX_PIPELINE_MSGQ_OUT];

    uint32_t n_pktq_in;
    uint32_t n_pktq_out;
    uint32_t n_msgq_in;
    uint32_t n_msgq_out;

    uint32_t timer_period;

    char *args_name[APP_MAX_PIPELINE_ARGS];
    char *args_value[APP_MAX_PIPELINE_ARGS];
    uint32_t n_args;

    EN_QNSM_APP app_type;
    void *app_data;
};

struct app_params;

typedef void (*app_link_op)(struct app_params *app,
                            uint32_t link_id,
                            uint32_t up,
                            void *arg);

#ifndef APP_MAX_PIPELINES
#define APP_MAX_PIPELINES                        64
#endif

struct app_link_data {
    app_link_op f_link[APP_MAX_PIPELINES];
    void *arg[APP_MAX_PIPELINES];
};

#ifndef APP_MAX_LINKS
#define APP_MAX_LINKS                            16
#endif

struct app_eal_params {
    /* Map lcore set to physical cpu set */
    char *coremap;

    /* Core ID that is used as master */
    uint32_t master_lcore_present;
    uint32_t master_lcore;

    /* Number of memory channels */
    uint32_t channels_present;
    uint32_t channels;

    /* Memory to allocate (see also --socket-mem) */
    uint32_t memory_present;
    uint32_t memory;

    /* Force number of memory ranks (don't detect) */
    uint32_t ranks_present;
    uint32_t ranks;

    /* Add a PCI device in black list. */
    char *pci_blacklist[APP_MAX_LINKS];

    /* Add a PCI device in white list. */
    char *pci_whitelist[APP_MAX_LINKS];

    /* Add a virtual device. */
    char *vdev[APP_MAX_LINKS];

    /* Use VMware TSC map instead of native RDTSC */
    uint32_t vmware_tsc_map_present;
    int vmware_tsc_map;

    /* Type of this process (primary|secondary|auto) */
    char *proc_type;

    /* Set syslog facility */
    char *syslog;

    /* Set default log level */
    uint32_t log_level_present;
    uint32_t log_level;

    /* Display version information on startup */
    uint32_t version_present;
    int version;

    /* This help */
    uint32_t help_present;
    int help;

    /* Use malloc instead of hugetlbfs */
    uint32_t no_huge_present;
    int no_huge;

    /* Disable PCI */
    uint32_t no_pci_present;
    int no_pci;

    /* Disable HPET */
    uint32_t no_hpet_present;
    int no_hpet;

    /* No shared config (mmap'd files) */
    uint32_t no_shconf_present;
    int no_shconf;

    /* Add driver */
    char *add_driver;

    /*  Memory to allocate on sockets (comma separated values)*/
    char *socket_mem;

    /* Directory where hugetlbfs is mounted */
    char *huge_dir;

    /* Prefix for hugepage filenames */
    char *file_prefix;

    /* Base virtual address */
    char *base_virtaddr;

    /* Create /dev/uioX (usually done by hotplug) */
    uint32_t create_uio_dev_present;
    int create_uio_dev;

    /* Interrupt mode for VFIO (legacy|msi|msix) */
    char *vfio_intr;

    /* Support running on Xen dom0 without hugetlbfs */
    uint32_t xen_dom0_present;
    int xen_dom0;

    uint32_t parsed;
};

#ifndef APP_APPNAME_SIZE
#define APP_APPNAME_SIZE                         256
#endif

#ifndef APP_MAX_MEMPOOLS
#define APP_MAX_MEMPOOLS                         8
#endif

#define APP_MAX_HWQ_IN                  (APP_MAX_LINKS * APP_LINK_MAX_HWQ_IN)

#define APP_MAX_HWQ_OUT                 (APP_MAX_LINKS * APP_LINK_MAX_HWQ_OUT)

#ifndef APP_MAX_PKTQ_SWQ
#define APP_MAX_PKTQ_SWQ                         256
#endif

#define APP_MAX_PKTQ_TM                          APP_MAX_LINKS

#ifndef APP_MAX_PKTQ_TAP
#define APP_MAX_PKTQ_TAP                         APP_MAX_LINKS
#endif

#define APP_MAX_PKTQ_KNI                         APP_MAX_LINKS

#ifndef APP_MAX_PKTQ_SOURCE
#define APP_MAX_PKTQ_SOURCE                      64
#endif

#ifndef APP_MAX_PKTQ_SINK
#define APP_MAX_PKTQ_SINK                        64
#endif

#ifndef APP_MAX_MSGQ
#define APP_MAX_MSGQ                             256
#endif

#ifndef APP_EAL_ARGC
#define APP_EAL_ARGC                             64
#endif

#ifndef APP_MAX_PIPELINE_TYPES
#define APP_MAX_PIPELINE_TYPES                   64
#endif

#ifndef APP_MAX_THREADS
#define APP_MAX_THREADS                          RTE_MAX_LCORE
#endif

#ifndef APP_MAX_CMDS
#define APP_MAX_CMDS                             64
#endif

#ifndef APP_THREAD_HEADROOM_STATS_COLLECT
#define APP_THREAD_HEADROOM_STATS_COLLECT        1
#endif

#define APP_CORE_MASK_SIZE                  \
    (RTE_MAX_LCORE / 64 + ((RTE_MAX_LCORE % 64) ? 1 : 0))

struct app_params {
    /* Config */
    char app_name[APP_APPNAME_SIZE];
    const char *config_file;
    const char *script_file;
    const char *parser_file;
    const char *output_file;
    const char *xml_conf_dir;
    const char *inst_id;
    const char *preproc;
    const char *preproc_args;
    uint64_t port_mask;
    uint32_t log_level;

    struct app_eal_params eal_params;
    struct app_mempool_params mempool_params[APP_MAX_MEMPOOLS];
    struct app_link_params link_params[APP_MAX_LINKS];
    struct app_pktq_hwq_in_params hwq_in_params[APP_MAX_HWQ_IN];
    struct app_pktq_hwq_out_params hwq_out_params[APP_MAX_HWQ_OUT];
    struct app_pktq_swq_params swq_params[APP_MAX_PKTQ_SWQ];
    struct app_pktq_tm_params tm_params[APP_MAX_PKTQ_TM];
    struct app_pktq_tap_params tap_params[APP_MAX_PKTQ_TAP];
    struct app_pktq_kni_params kni_params[APP_MAX_PKTQ_KNI];
    struct app_pktq_source_params source_params[APP_MAX_PKTQ_SOURCE];
    struct app_pktq_sink_params sink_params[APP_MAX_PKTQ_SINK];
    struct app_msgq_params msgq_params[APP_MAX_MSGQ];
    struct app_pipeline_params pipeline_params[APP_MAX_PIPELINES];
    const char *idps_conf_file;

    uint32_t n_mempools;
    uint32_t n_links;
    uint32_t n_pktq_hwq_in;
    uint32_t n_pktq_hwq_out;
    uint32_t n_pktq_swq;
    uint32_t n_pktq_tm;
    uint32_t n_pktq_tap;
    uint32_t n_pktq_kni;
    uint32_t n_pktq_source;
    uint32_t n_pktq_sink;
    uint32_t n_msgq;
    uint32_t n_pipelines;

    /* Init */
    char *eal_argv[1 + APP_EAL_ARGC];
    struct cpu_core_map *core_map;
    uint64_t core_mask[APP_CORE_MASK_SIZE];
    struct rte_mempool *mempool[APP_MAX_MEMPOOLS];
    struct app_link_data link_data[APP_MAX_LINKS];
    struct rte_ring *swq[APP_MAX_PKTQ_SWQ];
    struct rte_sched_port *tm[APP_MAX_PKTQ_TM];
    int tap[APP_MAX_PKTQ_TAP];
#ifdef RTE_LIBRTE_KNI
    struct rte_kni *kni[APP_MAX_PKTQ_KNI];
#endif /* RTE_LIBRTE_KNI */
    struct rte_ring *msgq[APP_MAX_MSGQ];

#if 0
    struct pipeline_type pipeline_type[APP_MAX_PIPELINE_TYPES];
    struct app_pipeline_data pipeline_data[APP_MAX_PIPELINES];
    struct app_thread_data thread_data[APP_MAX_THREADS];
#else
    EN_QNSM_APP app_type[APP_MAX_THREADS];
    uint8_t app_deploy_num[EN_QNSM_APP_MAX];
#endif
    cmdline_parse_ctx_t cmds[APP_MAX_CMDS + 1];

    int eal_argc;
    uint32_t n_pipeline_types;
    uint32_t n_cmds;
};

#define APP_PARAM_VALID(obj) ((obj)->name != NULL)

#define APP_PARAM_COUNT(obj_array, n_objs)              \
{                                   \
    size_t i;                           \
                                    \
    n_objs = 0;                         \
    for (i = 0; i < RTE_DIM(obj_array); i++)            \
        if (APP_PARAM_VALID(&((obj_array)[i])))         \
            n_objs++;                   \
}

#define APP_PARAM_FIND(obj_array, key)                  \
({                                  \
    ssize_t obj_idx;                        \
    const ssize_t obj_count = RTE_DIM(obj_array);           \
                                    \
    for (obj_idx = 0; obj_idx < obj_count; obj_idx++) {     \
        if (!APP_PARAM_VALID(&((obj_array)[obj_idx])))      \
            continue;                   \
                                    \
        if (strcmp(key, (obj_array)[obj_idx].name) == 0)    \
            break;                      \
    }                               \
    obj_idx < obj_count ? obj_idx : -ENOENT;            \
})

#define APP_PARAM_FIND_BY_ID(obj_array, prefix, id, obj)        \
do {                                    \
    char name[APP_PARAM_NAME_SIZE];                 \
    ssize_t pos;                            \
                                    \
    snprintf(name, sizeof(name), prefix "%" PRIu32, id);               \
    pos = APP_PARAM_FIND(obj_array, name);              \
    obj = (pos < 0) ? NULL : &((obj_array)[pos]);           \
} while (0)

#define APP_PARAM_GET_ID(obj, prefix, id)               \
do                                  \
    sscanf(obj->name, prefix "%" SCNu32, &id);              \
while (0)                               \

#define APP_CHECK(exp, fmt, ...)                    \
do {                                    \
    if (!(exp)) {                           \
        fprintf(stderr, fmt "\n", ## __VA_ARGS__);      \
        abort();                        \
    }                               \
} while (0)

enum app_log_level {
    APP_LOG_LEVEL_HIGH = 1,
    APP_LOG_LEVEL_LOW,
    APP_LOG_LEVELS
};

#define APP_LOG(app, level, fmt, ...)                   \
do {                                    \
    if (app->log_level >= APP_LOG_LEVEL_ ## level)          \
        fprintf(stdout, "[APP] " fmt "\n", ## __VA_ARGS__); \
} while (0)

static inline uint32_t
app_link_get_n_rxq(struct app_params *app, struct app_link_params *link)
{
    uint32_t n_rxq = 0, link_id, i;
    uint32_t n_pktq_hwq_in = RTE_MIN(app->n_pktq_hwq_in,
                                     RTE_DIM(app->hwq_in_params));

    APP_PARAM_GET_ID(link, "LINK", link_id);

    for (i = 0; i < n_pktq_hwq_in; i++) {
        struct app_pktq_hwq_in_params *p = &app->hwq_in_params[i];
        uint32_t rxq_link_id, rxq_queue_id;

        sscanf(p->name, "RXQ%" SCNu32 ".%" SCNu32,
               &rxq_link_id, &rxq_queue_id);
        if (rxq_link_id == link_id)
            n_rxq++;
    }

    return n_rxq;
}

static inline uint32_t
app_link_get_n_txq(struct app_params *app, struct app_link_params *link)
{
    uint32_t n_txq = 0, link_id, i;
    uint32_t n_pktq_hwq_out = RTE_MIN(app->n_pktq_hwq_out,
                                      RTE_DIM(app->hwq_out_params));

    APP_PARAM_GET_ID(link, "LINK", link_id);

    for (i = 0; i < n_pktq_hwq_out; i++) {
        struct app_pktq_hwq_out_params *p = &app->hwq_out_params[i];
        uint32_t txq_link_id, txq_queue_id;

        sscanf(p->name, "TXQ%" SCNu32 ".%" SCNu32,
               &txq_link_id, &txq_queue_id);
        if (txq_link_id == link_id)
            n_txq++;
    }

    return n_txq;
}

static inline uint32_t
app_rxq_get_readers(struct app_params *app, struct app_pktq_hwq_in_params *rxq)
{
    uint32_t pos = rxq - app->hwq_in_params;
    uint32_t n_pipelines = RTE_MIN(app->n_pipelines,
                                   RTE_DIM(app->pipeline_params));
    uint32_t n_readers = 0, i;

    for (i = 0; i < n_pipelines; i++) {
        struct app_pipeline_params *p = &app->pipeline_params[i];
        uint32_t n_pktq_in = RTE_MIN(p->n_pktq_in, RTE_DIM(p->pktq_in));
        uint32_t j;

        for (j = 0; j < n_pktq_in; j++) {
            struct app_pktq_in_params *pktq = &p->pktq_in[j];

            if ((pktq->type == APP_PKTQ_IN_HWQ) &&
                (pktq->id == pos))
                n_readers++;
        }
    }

    return n_readers;
}

static inline uint32_t
app_swq_get_readers(struct app_params *app, struct app_pktq_swq_params *swq)
{
    uint32_t pos = swq - app->swq_params;
    uint32_t n_pipelines = RTE_MIN(app->n_pipelines,
                                   RTE_DIM(app->pipeline_params));
    uint32_t n_readers = 0, i;

    for (i = 0; i < n_pipelines; i++) {
        struct app_pipeline_params *p = &app->pipeline_params[i];
        uint32_t n_pktq_in = RTE_MIN(p->n_pktq_in, RTE_DIM(p->pktq_in));
        uint32_t j;

        for (j = 0; j < n_pktq_in; j++) {
            struct app_pktq_in_params *pktq = &p->pktq_in[j];

            if ((pktq->type == APP_PKTQ_IN_SWQ) &&
                (pktq->id == pos))
                n_readers++;
        }
    }

    return n_readers;
}

static inline struct app_pipeline_params *
app_swq_get_reader(struct app_params *app,
                   struct app_pktq_swq_params *swq,
                   uint32_t *pktq_in_id)
{
    struct app_pipeline_params *reader = NULL;
    uint32_t pos = swq - app->swq_params;
    uint32_t n_pipelines = RTE_MIN(app->n_pipelines,
                                   RTE_DIM(app->pipeline_params));
    uint32_t n_readers = 0, id = 0, i;

    for (i = 0; i < n_pipelines; i++) {
        struct app_pipeline_params *p = &app->pipeline_params[i];
        uint32_t n_pktq_in = RTE_MIN(p->n_pktq_in, RTE_DIM(p->pktq_in));
        uint32_t j;

        for (j = 0; j < n_pktq_in; j++) {
            struct app_pktq_in_params *pktq = &p->pktq_in[j];

            if ((pktq->type == APP_PKTQ_IN_SWQ) &&
                (pktq->id == pos)) {
                n_readers++;
                reader = p;
                id = j;
            }
        }
    }

    if (n_readers != 1)
        return NULL;

    *pktq_in_id = id;
    return reader;
}

static inline uint32_t
app_tm_get_readers(struct app_params *app, struct app_pktq_tm_params *tm)
{
    uint32_t pos = tm - app->tm_params;
    uint32_t n_pipelines = RTE_MIN(app->n_pipelines,
                                   RTE_DIM(app->pipeline_params));
    uint32_t n_readers = 0, i;

    for (i = 0; i < n_pipelines; i++) {
        struct app_pipeline_params *p = &app->pipeline_params[i];
        uint32_t n_pktq_in = RTE_MIN(p->n_pktq_in, RTE_DIM(p->pktq_in));
        uint32_t j;

        for (j = 0; j < n_pktq_in; j++) {
            struct app_pktq_in_params *pktq = &p->pktq_in[j];

            if ((pktq->type == APP_PKTQ_IN_TM) &&
                (pktq->id == pos))
                n_readers++;
        }
    }

    return n_readers;
}

static inline struct app_pipeline_params *
app_tm_get_reader(struct app_params *app,
                  struct app_pktq_tm_params *tm,
                  uint32_t *pktq_in_id)
{
    struct app_pipeline_params *reader = NULL;
    uint32_t pos = tm - app->tm_params;
    uint32_t n_pipelines = RTE_MIN(app->n_pipelines,
                                   RTE_DIM(app->pipeline_params));
    uint32_t n_readers = 0, id = 0, i;

    for (i = 0; i < n_pipelines; i++) {
        struct app_pipeline_params *p = &app->pipeline_params[i];
        uint32_t n_pktq_in = RTE_MIN(p->n_pktq_in, RTE_DIM(p->pktq_in));
        uint32_t j;

        for (j = 0; j < n_pktq_in; j++) {
            struct app_pktq_in_params *pktq = &p->pktq_in[j];

            if ((pktq->type == APP_PKTQ_IN_TM) &&
                (pktq->id == pos)) {
                n_readers++;
                reader = p;
                id = j;
            }
        }
    }

    if (n_readers != 1)
        return NULL;

    *pktq_in_id = id;
    return reader;
}

static inline uint32_t
app_tap_get_readers(struct app_params *app, struct app_pktq_tap_params *tap)
{
    uint32_t pos = tap - app->tap_params;
    uint32_t n_pipelines = RTE_MIN(app->n_pipelines,
                                   RTE_DIM(app->pipeline_params));
    uint32_t n_readers = 0, i;

    for (i = 0; i < n_pipelines; i++) {
        struct app_pipeline_params *p = &app->pipeline_params[i];
        uint32_t n_pktq_in = RTE_MIN(p->n_pktq_in, RTE_DIM(p->pktq_in));
        uint32_t j;

        for (j = 0; j < n_pktq_in; j++) {
            struct app_pktq_in_params *pktq = &p->pktq_in[j];

            if ((pktq->type == APP_PKTQ_IN_TAP) &&
                (pktq->id == pos))
                n_readers++;
        }
    }

    return n_readers;
}

static inline struct app_pipeline_params *
app_tap_get_reader(struct app_params *app,
                   struct app_pktq_tap_params *tap,
                   uint32_t *pktq_in_id)
{
    struct app_pipeline_params *reader = NULL;
    uint32_t pos = tap - app->tap_params;
    uint32_t n_pipelines = RTE_MIN(app->n_pipelines,
                                   RTE_DIM(app->pipeline_params));
    uint32_t n_readers = 0, id = 0, i;

    for (i = 0; i < n_pipelines; i++) {
        struct app_pipeline_params *p = &app->pipeline_params[i];
        uint32_t n_pktq_in = RTE_MIN(p->n_pktq_in, RTE_DIM(p->pktq_in));
        uint32_t j;

        for (j = 0; j < n_pktq_in; j++) {
            struct app_pktq_in_params *pktq = &p->pktq_in[j];

            if ((pktq->type == APP_PKTQ_IN_TAP) &&
                (pktq->id == pos)) {
                n_readers++;
                reader = p;
                id = j;
            }
        }
    }

    if (n_readers != 1)
        return NULL;

    *pktq_in_id = id;
    return reader;
}

static inline uint32_t
app_kni_get_readers(struct app_params *app, struct app_pktq_kni_params *kni)
{
    uint32_t pos = kni - app->kni_params;
    uint32_t n_pipelines = RTE_MIN(app->n_pipelines,
                                   RTE_DIM(app->pipeline_params));
    uint32_t n_readers = 0, i;

    for (i = 0; i < n_pipelines; i++) {
        struct app_pipeline_params *p = &app->pipeline_params[i];
        uint32_t n_pktq_in = RTE_MIN(p->n_pktq_in, RTE_DIM(p->pktq_in));
        uint32_t j;

        for (j = 0; j < n_pktq_in; j++) {
            struct app_pktq_in_params *pktq = &p->pktq_in[j];

            if ((pktq->type == APP_PKTQ_IN_KNI) &&
                (pktq->id == pos))
                n_readers++;
        }
    }

    return n_readers;
}

static inline struct app_pipeline_params *
app_kni_get_reader(struct app_params *app,
                   struct app_pktq_kni_params *kni,
                   uint32_t *pktq_in_id)
{
    struct app_pipeline_params *reader = NULL;
    uint32_t pos = kni - app->kni_params;
    uint32_t n_pipelines = RTE_MIN(app->n_pipelines,
                                   RTE_DIM(app->pipeline_params));
    uint32_t n_readers = 0, id = 0, i;

    for (i = 0; i < n_pipelines; i++) {
        struct app_pipeline_params *p = &app->pipeline_params[i];
        uint32_t n_pktq_in = RTE_MIN(p->n_pktq_in, RTE_DIM(p->pktq_in));
        uint32_t j;

        for (j = 0; j < n_pktq_in; j++) {
            struct app_pktq_in_params *pktq = &p->pktq_in[j];

            if ((pktq->type == APP_PKTQ_IN_KNI) &&
                (pktq->id == pos)) {
                n_readers++;
                reader = p;
                id = j;
            }
        }
    }

    if (n_readers != 1)
        return NULL;

    *pktq_in_id = id;
    return reader;
}

static inline uint32_t
app_source_get_readers(struct app_params *app,
                       struct app_pktq_source_params *source)
{
    uint32_t pos = source - app->source_params;
    uint32_t n_pipelines = RTE_MIN(app->n_pipelines,
                                   RTE_DIM(app->pipeline_params));
    uint32_t n_readers = 0, i;

    for (i = 0; i < n_pipelines; i++) {
        struct app_pipeline_params *p = &app->pipeline_params[i];
        uint32_t n_pktq_in = RTE_MIN(p->n_pktq_in, RTE_DIM(p->pktq_in));
        uint32_t j;

        for (j = 0; j < n_pktq_in; j++) {
            struct app_pktq_in_params *pktq = &p->pktq_in[j];

            if ((pktq->type == APP_PKTQ_IN_SOURCE) &&
                (pktq->id == pos))
                n_readers++;
        }
    }

    return n_readers;
}

static inline uint32_t
app_msgq_get_readers(struct app_params *app, struct app_msgq_params *msgq)
{
    uint32_t pos = msgq - app->msgq_params;
    uint32_t n_pipelines = RTE_MIN(app->n_pipelines,
                                   RTE_DIM(app->pipeline_params));
    uint32_t n_readers = 0, i;

    for (i = 0; i < n_pipelines; i++) {
        struct app_pipeline_params *p = &app->pipeline_params[i];
        uint32_t n_msgq_in = RTE_MIN(p->n_msgq_in, RTE_DIM(p->msgq_in));
        uint32_t j;

        for (j = 0; j < n_msgq_in; j++)
            if (p->msgq_in[j] == pos)
                n_readers++;
    }

    return n_readers;
}

static inline uint32_t
app_txq_get_writers(struct app_params *app, struct app_pktq_hwq_out_params *txq)
{
    uint32_t pos = txq - app->hwq_out_params;
    uint32_t n_pipelines = RTE_MIN(app->n_pipelines,
                                   RTE_DIM(app->pipeline_params));
    uint32_t n_writers = 0, i;

    for (i = 0; i < n_pipelines; i++) {
        struct app_pipeline_params *p = &app->pipeline_params[i];
        uint32_t n_pktq_out = RTE_MIN(p->n_pktq_out,
                                      RTE_DIM(p->pktq_out));
        uint32_t j;

        for (j = 0; j < n_pktq_out; j++) {
            struct app_pktq_out_params *pktq = &p->pktq_out[j];

            if ((pktq->type == APP_PKTQ_OUT_HWQ) &&
                (pktq->id == pos))
                n_writers++;
        }
    }

    return n_writers;
}

static inline uint32_t
app_swq_get_writers(struct app_params *app, struct app_pktq_swq_params *swq)
{
    uint32_t pos = swq - app->swq_params;
    uint32_t n_pipelines = RTE_MIN(app->n_pipelines,
                                   RTE_DIM(app->pipeline_params));
    uint32_t n_writers = 0, i;

    for (i = 0; i < n_pipelines; i++) {
        struct app_pipeline_params *p = &app->pipeline_params[i];
        uint32_t n_pktq_out = RTE_MIN(p->n_pktq_out,
                                      RTE_DIM(p->pktq_out));
        uint32_t j;

        for (j = 0; j < n_pktq_out; j++) {
            struct app_pktq_out_params *pktq = &p->pktq_out[j];

            if ((pktq->type == APP_PKTQ_OUT_SWQ) &&
                (pktq->id == pos))
                n_writers++;
        }
    }

    return n_writers;
}

static inline struct app_pipeline_params *
app_swq_get_writer(struct app_params *app,
                   struct app_pktq_swq_params *swq,
                   uint32_t *pktq_out_id)
{
    struct app_pipeline_params *writer = NULL;
    uint32_t pos = swq - app->swq_params;
    uint32_t n_pipelines = RTE_MIN(app->n_pipelines,
                                   RTE_DIM(app->pipeline_params));
    uint32_t n_writers = 0, id = 0, i;

    for (i = 0; i < n_pipelines; i++) {
        struct app_pipeline_params *p = &app->pipeline_params[i];
        uint32_t n_pktq_out = RTE_MIN(p->n_pktq_out,
                                      RTE_DIM(p->pktq_out));
        uint32_t j;

        for (j = 0; j < n_pktq_out; j++) {
            struct app_pktq_out_params *pktq = &p->pktq_out[j];

            if ((pktq->type == APP_PKTQ_OUT_SWQ) &&
                (pktq->id == pos)) {
                n_writers++;
                writer = p;
                id = j;
            }
        }
    }

    if (n_writers != 1)
        return NULL;

    *pktq_out_id = id;
    return writer;
}

static inline uint32_t
app_tm_get_writers(struct app_params *app, struct app_pktq_tm_params *tm)
{
    uint32_t pos = tm - app->tm_params;
    uint32_t n_pipelines = RTE_MIN(app->n_pipelines,
                                   RTE_DIM(app->pipeline_params));
    uint32_t n_writers = 0, i;

    for (i = 0; i < n_pipelines; i++) {
        struct app_pipeline_params *p = &app->pipeline_params[i];
        uint32_t n_pktq_out = RTE_MIN(p->n_pktq_out,
                                      RTE_DIM(p->pktq_out));
        uint32_t j;

        for (j = 0; j < n_pktq_out; j++) {
            struct app_pktq_out_params *pktq = &p->pktq_out[j];

            if ((pktq->type == APP_PKTQ_OUT_TM) &&
                (pktq->id == pos))
                n_writers++;
        }
    }

    return n_writers;
}

static inline struct app_pipeline_params *
app_tm_get_writer(struct app_params *app,
                  struct app_pktq_tm_params *tm,
                  uint32_t *pktq_out_id)
{
    struct app_pipeline_params *writer = NULL;
    uint32_t pos = tm - app->tm_params;
    uint32_t n_pipelines = RTE_MIN(app->n_pipelines,
                                   RTE_DIM(app->pipeline_params));
    uint32_t n_writers = 0, id = 0, i;

    for (i = 0; i < n_pipelines; i++) {
        struct app_pipeline_params *p = &app->pipeline_params[i];
        uint32_t n_pktq_out = RTE_MIN(p->n_pktq_out,
                                      RTE_DIM(p->pktq_out));
        uint32_t j;

        for (j = 0; j < n_pktq_out; j++) {
            struct app_pktq_out_params *pktq = &p->pktq_out[j];

            if ((pktq->type == APP_PKTQ_OUT_TM) &&
                (pktq->id == pos)) {
                n_writers++;
                writer = p;
                id = j;
            }
        }
    }

    if (n_writers != 1)
        return NULL;

    *pktq_out_id = id;
    return writer;
}

static inline uint32_t
app_tap_get_writers(struct app_params *app, struct app_pktq_tap_params *tap)
{
    uint32_t pos = tap - app->tap_params;
    uint32_t n_pipelines = RTE_MIN(app->n_pipelines,
                                   RTE_DIM(app->pipeline_params));
    uint32_t n_writers = 0, i;

    for (i = 0; i < n_pipelines; i++) {
        struct app_pipeline_params *p = &app->pipeline_params[i];
        uint32_t n_pktq_out = RTE_MIN(p->n_pktq_out,
                                      RTE_DIM(p->pktq_out));
        uint32_t j;

        for (j = 0; j < n_pktq_out; j++) {
            struct app_pktq_out_params *pktq = &p->pktq_out[j];

            if ((pktq->type == APP_PKTQ_OUT_TAP) &&
                (pktq->id == pos))
                n_writers++;
        }
    }

    return n_writers;
}

static inline struct app_pipeline_params *
app_tap_get_writer(struct app_params *app,
                   struct app_pktq_tap_params *tap,
                   uint32_t *pktq_out_id)
{
    struct app_pipeline_params *writer = NULL;
    uint32_t pos = tap - app->tap_params;
    uint32_t n_pipelines = RTE_MIN(app->n_pipelines,
                                   RTE_DIM(app->pipeline_params));
    uint32_t n_writers = 0, id = 0, i;

    for (i = 0; i < n_pipelines; i++) {
        struct app_pipeline_params *p = &app->pipeline_params[i];
        uint32_t n_pktq_out = RTE_MIN(p->n_pktq_out,
                                      RTE_DIM(p->pktq_out));
        uint32_t j;

        for (j = 0; j < n_pktq_out; j++) {
            struct app_pktq_out_params *pktq = &p->pktq_out[j];

            if ((pktq->type == APP_PKTQ_OUT_TAP) &&
                (pktq->id == pos)) {
                n_writers++;
                writer = p;
                id = j;
            }
        }
    }

    if (n_writers != 1)
        return NULL;

    *pktq_out_id = id;
    return writer;
}

static inline uint32_t
app_kni_get_writers(struct app_params *app, struct app_pktq_kni_params *kni)
{
    uint32_t pos = kni - app->kni_params;
    uint32_t n_pipelines = RTE_MIN(app->n_pipelines,
                                   RTE_DIM(app->pipeline_params));
    uint32_t n_writers = 0, i;

    for (i = 0; i < n_pipelines; i++) {
        struct app_pipeline_params *p = &app->pipeline_params[i];
        uint32_t n_pktq_out = RTE_MIN(p->n_pktq_out,
                                      RTE_DIM(p->pktq_out));
        uint32_t j;

        for (j = 0; j < n_pktq_out; j++) {
            struct app_pktq_out_params *pktq = &p->pktq_out[j];

            if ((pktq->type == APP_PKTQ_OUT_KNI) &&
                (pktq->id == pos))
                n_writers++;
        }
    }

    return n_writers;
}

static inline struct app_pipeline_params *
app_kni_get_writer(struct app_params *app,
                   struct app_pktq_kni_params *kni,
                   uint32_t *pktq_out_id)
{
    struct app_pipeline_params *writer = NULL;
    uint32_t pos = kni - app->kni_params;
    uint32_t n_pipelines = RTE_MIN(app->n_pipelines,
                                   RTE_DIM(app->pipeline_params));
    uint32_t n_writers = 0, id = 0, i;

    for (i = 0; i < n_pipelines; i++) {
        struct app_pipeline_params *p = &app->pipeline_params[i];
        uint32_t n_pktq_out = RTE_MIN(p->n_pktq_out,
                                      RTE_DIM(p->pktq_out));
        uint32_t j;

        for (j = 0; j < n_pktq_out; j++) {
            struct app_pktq_out_params *pktq = &p->pktq_out[j];

            if ((pktq->type == APP_PKTQ_OUT_KNI) &&
                (pktq->id == pos)) {
                n_writers++;
                writer = p;
                id = j;
            }
        }
    }

    if (n_writers != 1)
        return NULL;

    *pktq_out_id = id;
    return writer;
}

static inline uint32_t
app_sink_get_writers(struct app_params *app, struct app_pktq_sink_params *sink)
{
    uint32_t pos = sink - app->sink_params;
    uint32_t n_pipelines = RTE_MIN(app->n_pipelines,
                                   RTE_DIM(app->pipeline_params));
    uint32_t n_writers = 0, i;

    for (i = 0; i < n_pipelines; i++) {
        struct app_pipeline_params *p = &app->pipeline_params[i];
        uint32_t n_pktq_out = RTE_MIN(p->n_pktq_out,
                                      RTE_DIM(p->pktq_out));
        uint32_t j;

        for (j = 0; j < n_pktq_out; j++) {
            struct app_pktq_out_params *pktq = &p->pktq_out[j];

            if ((pktq->type == APP_PKTQ_OUT_SINK) &&
                (pktq->id == pos))
                n_writers++;
        }
    }

    return n_writers;
}

static inline uint32_t
app_msgq_get_writers(struct app_params *app, struct app_msgq_params *msgq)
{
    uint32_t pos = msgq - app->msgq_params;
    uint32_t n_pipelines = RTE_MIN(app->n_pipelines,
                                   RTE_DIM(app->pipeline_params));
    uint32_t n_writers = 0, i;

    for (i = 0; i < n_pipelines; i++) {
        struct app_pipeline_params *p = &app->pipeline_params[i];
        uint32_t n_msgq_out = RTE_MIN(p->n_msgq_out,
                                      RTE_DIM(p->msgq_out));
        uint32_t j;

        for (j = 0; j < n_msgq_out; j++)
            if (p->msgq_out[j] == pos)
                n_writers++;
    }

    return n_writers;
}

static inline struct app_link_params *
app_get_link_for_rxq(struct app_params *app, struct app_pktq_hwq_in_params *p)
{
    char link_name[APP_PARAM_NAME_SIZE];
    ssize_t link_param_idx;
    uint32_t rxq_link_id, rxq_queue_id;

    sscanf(p->name, "RXQ%" SCNu32 ".%" SCNu32,
           &rxq_link_id, &rxq_queue_id);
    snprintf(link_name, sizeof(link_name), "LINK%" PRIu32, rxq_link_id);
    link_param_idx = APP_PARAM_FIND(app->link_params, link_name);
    APP_CHECK((link_param_idx >= 0),
              "Cannot find %s for %s", link_name, p->name);

    return &app->link_params[link_param_idx];
}

static inline struct app_link_params *
app_get_link_for_txq(struct app_params *app, struct app_pktq_hwq_out_params *p)
{
    char link_name[APP_PARAM_NAME_SIZE];
    ssize_t link_param_idx;
    uint32_t txq_link_id, txq_queue_id;

    sscanf(p->name, "TXQ%" SCNu32 ".%" SCNu32,
           &txq_link_id, &txq_queue_id);
    snprintf(link_name, sizeof(link_name), "LINK%" PRIu32, txq_link_id);
    link_param_idx = APP_PARAM_FIND(app->link_params, link_name);
    APP_CHECK((link_param_idx >= 0),
              "Cannot find %s for %s", link_name, p->name);

    return &app->link_params[link_param_idx];
}

static inline struct app_link_params *
app_get_link_for_tm(struct app_params *app, struct app_pktq_tm_params *p_tm)
{
    char link_name[APP_PARAM_NAME_SIZE];
    uint32_t link_id;
    ssize_t link_param_idx;

    sscanf(p_tm->name, "TM%" PRIu32, &link_id);
    snprintf(link_name, sizeof(link_name), "LINK%" PRIu32, link_id);
    link_param_idx = APP_PARAM_FIND(app->link_params, link_name);
    APP_CHECK((link_param_idx >= 0),
              "Cannot find %s for %s", link_name, p_tm->name);

    return &app->link_params[link_param_idx];
}

static inline struct app_link_params *
app_get_link_for_kni(struct app_params *app, struct app_pktq_kni_params *p_kni)
{
    char link_name[APP_PARAM_NAME_SIZE];
    uint32_t link_id;
    ssize_t link_param_idx;

    sscanf(p_kni->name, "KNI%" PRIu32, &link_id);
    snprintf(link_name, sizeof(link_name), "LINK%" PRIu32, link_id);
    link_param_idx = APP_PARAM_FIND(app->link_params, link_name);
    APP_CHECK((link_param_idx >= 0),
              "Cannot find %s for %s", link_name, p_kni->name);

    return &app->link_params[link_param_idx];
}

static inline uint32_t
app_core_is_enabled(struct app_params *app, uint32_t lcore_id)
{
    return((app->core_mask[lcore_id / 64] &
            (1LLU << (lcore_id % 64))) > 0);
}

static inline void
app_core_enable_in_core_mask(struct app_params *app, int lcore_id)
{
    app->core_mask[lcore_id / 64] |= 1LLU << (lcore_id % 64);

}

static inline void
app_core_build_core_mask_string(struct app_params *app, char *mask_buffer)
{
    int i;

    mask_buffer[0] = '\0';
    for (i = (int)RTE_DIM(app->core_mask); i > 0; i--) {
        /* For Hex representation of bits in uint64_t */
        char buffer[(64 / 8) * 2 + 1];
        memset(buffer, 0, sizeof(buffer));
        snprintf(buffer, sizeof(buffer), "%016" PRIx64,
                 app->core_mask[i-1]);
        strcat(mask_buffer, buffer);
    }
}
static inline EN_QNSM_APP* app_get_lcore_app_type(struct app_params *app)
{
    return app->app_type;
}

static inline uint8_t app_get_deploy_num(struct app_params *app, EN_QNSM_APP type)
{
    return app->app_deploy_num[type];
}


static inline int
app_is_socket_used(struct app_params *app, uint32_t socket)
{
    uint32_t lcore;

    for (lcore = 0; lcore < RTE_MAX_LCORE; lcore ++) {
        if (0 == app_core_is_enabled(app, lcore)) {
            continue;
        }

        if (socket == rte_lcore_to_socket_id(lcore)) {
            return 1;
        }
    }

    return 0;
}

static inline uint32_t app_mempool_get_pool_size(struct app_params *app, uint32_t socket_id)
{
    uint16_t index = 0;
    uint32_t mempool_size = 0;

    for (index = 0; index< app->n_mempools; index++) {
        if (socket_id == app->mempool_params[index].cpu_socket_id) {
            mempool_size += app->mempool_params[index].pool_size;
        }
    }

    return mempool_size;
}

static uint32_t app_type_find(struct app_params *app, EN_QNSM_APP type)
{
    uint16_t index = 0;
    for (index = 0; index< app->n_pipelines; index++) {
        if (app->pipeline_params[index].app_type == type) {
            return 1;
        }

    }

    return 0;
}

int app_config_init(struct app_params *app);

int app_config_args(struct app_params *app,
                    int argc, char **argv);

int app_config_preproc(struct app_params *app);

int app_config_parse(struct app_params *app,
                     const char *file_name);

int app_config_parse_tm(struct app_params *app);

void app_config_save(struct app_params *app,
                     const char *file_name);

int app_config_check(struct app_params *app);

int app_init(struct app_params *app);

int app_post_init(struct app_params *app);

int app_thread(void *arg);

#if 0
int app_pipeline_type_register(struct app_params *app,
                               struct pipeline_type *ptype);

struct pipeline_type *app_pipeline_type_find(struct app_params *app,
        char *name);
#endif

void app_link_up_internal(struct app_params *app,
                          struct app_link_params *cp);

void app_link_down_internal(struct app_params *app,
                            struct app_link_params *cp);

void
app_init_swq(struct app_params *app);

#endif
