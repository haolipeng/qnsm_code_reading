/*
 * QNSM is a Network Security Monitor based on DPDK.
 *
 * Copyright (C) 2017 iQIYI (www.iqiyi.com).
 * All Rights Reserved.
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
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>

#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_tailq.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_lpm.h>
#include <rte_timer.h>

#include "qnsm_inspect_main.h"
#include "util.h"
#include "qnsm_cfg.h"
#include "app.h"
#include "qnsm_dbg.h"
#include "qnsm_msg_ex.h"
#include "qnsm_port_ex.h"
#include "qnsm_session_ex.h"
#include "qnsm_ip_agg.h"
#include "qnsm_edge_ex.h"
#include "qnsm_master_ex.h"
#include "qnsm_ips_shell.h"
#include "qnsm_dump_ex.h"
#include "qnsm_dummy.h"

int
app_lcore_main_loop(void *arg)
{
    // 1. 获取基本信息
    unsigned lcore = rte_lcore_id();                    // 获取当前逻辑核心ID
    struct app_params *app = qnsm_service_get_cfg_para(); // 获取应用配置参数
    EN_QNSM_APP app_type = app->app_type[lcore];       // 获取该核心运行的应用类型
    uint16_t lcore_id = 0;
    uint32_t p_id;
    struct app_pipeline_params *params = NULL;

    // 2. 初始化函数数组
    static QNSM_APP_INIT init_fun[EN_QNSM_APP_MAX] = {
        qnsm_sess_service_init,        // 会话管理服务初始化
        qnsm_service_cus_ip_agg_init,  // 自定义IP聚合服务初始化
        qnsm_service_svr_host_init,    // 服务器主机初始化
        qnsm_edge_service_init,        // 边缘服务初始化
        qnsm_master_init,              // 主控服务初始化
#ifdef QNSM_LIBQNSM_IDPS
        qnsm_detect_service_init,      // 入侵检测服务初始化（条件编译）
#else
        NULL,
#endif
        qnsm_service_dump_init,        // 数据转储服务初始化
        NULL,
        qnsm_dummy_init,               // 测试服务初始化
    };

    // 3. 查找当前核心对应的pipeline参数
    for (p_id = 0; p_id < app->n_pipelines; p_id++) {
        params = &app->pipeline_params[p_id];

        // 通过socket_id, core_id和hyper_th_id映射到逻辑核心ID
        lcore_id = cpu_core_map_get_lcore_id(app->core_map,
                                             params->socket_id,
                                             params->core_id,
                                             params->hyper_th_id);
        // 找到当前核心对应的pipeline参数后跳出循环
        if (lcore_id == lcore) {
            break;
        }
    }

    // 4. 启动服务
    if (params && init_fun[app_type]) {
        // 打印启动信息
        printf("Logical core %u (%s) main loop.\n", lcore, params->name);
        // 启动应用服务
        qnsm_servcie_app_launch(params,
                                init_fun[app_type]);
    }
    return 0;
}
