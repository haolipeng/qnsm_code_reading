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

#ifndef __QNSM_TBL_CONF__
#define __QNSM_TBL_CONF__

#include <rte_hash.h>
#include "util.h"
#include "list.h"
#include "qnsm_service.h"

#include "qnsm_tbl_ex.h"


#ifdef __cplusplus
extern "C" {
#endif

#define QNSM_TBL_CONF_SOCKET_MAX    (2)
#define QNSM_TBL_CONF_CORE_MAX      (48)
#define QNSM_POOL_CACHE_SIZE        (256)

typedef struct qnsm_tbl {
    struct rte_hash *tbl;
    struct rte_mempool *pool;

    QNSM_TBL_PARA      *para;
    volatile uint32_t   item_num;
    uint32_t emergency_mode;
} QNSM_TBL;

typedef struct qnsm_lcore_tbl {
    /**
     * @brief 表数组，存储该逻辑核使用的所有类型的表实例
     * 每个元素代表一种类型的表 (例如：会话表, IP聚合表等)
     * EN_QNSM_TBL_MAX 定义了系统支持的最大表类型数量
     */
    QNSM_TBL tbl[EN_QNSM_TBL_MAX];
    /**
     * @brief 当前结构体关联的逻辑核心ID
     */
    uint32_t          lcore_id;
    /**
     * @brief 当前逻辑核心所属的CPU Socket ID (用于NUMA优化)
     */
    uint32_t          socket_id;
} QNSM_LCORE_TBL;

typedef struct {
    /**
     * @brief 表的部署数量/目标大小 (例如，期望存储的条目总数)
     * 通常在配置时设定
     */
    uint32_t           deploy_num;
    /**
     * @brief 每个逻辑核心应处理或分配的大小/容量
     * 可能用于分布式表或资源限制
     */
    uint32_t           per_lcore_size;
    /**
     * @brief 紧急恢复阈值/数量
     * 可能指当表满时，可以临时存储或用于恢复的条目数量
     */
    uint32_t           emergency_recovery_num;
    /**
     * @brief 紧急差异数量
     * 可能与emergency_recovery_num配合使用，定义触发某种紧急处理机制的差异阈值
     */
    uint32_t           emergency_diff_num;
} QNSM_TBL_INFO;

typedef struct {
    /**
     * @brief 用于保护每个Socket的tbl_info访问的自旋锁数组
     * APP_MAX_SOCKETS 定义了系统支持的最大CPU Socket数量
     */
    rte_spinlock_t      info_lock[APP_MAX_SOCKETS];
    /**
     * @brief 指向每个Socket的表信息(QNSM_TBL_INFO)结构的指针数组
     * 每个Socket可以有不同的表配置信息
     */
    QNSM_TBL_INFO       *tbl_info[APP_MAX_SOCKETS];
    /**
     * @brief 用于保护每个Socket上每种类型表的内存池访问的自旋锁 (二维数组)
     * 第一维是Socket ID，第二维是表类型 (EN_QNSM_TBL_MAX)
     */
    rte_spinlock_t lock[APP_MAX_SOCKETS][EN_QNSM_TBL_MAX];
    /**
     * @brief 指向DPDK内存池(rte_mempool)的指针数组 (二维数组)
     * 用于为每个Socket上的每种类型的表分配表项对象内存
     * 实现NUMA本地内存分配，提高访问效率
     * 第一维是Socket ID，第二维是表类型 (EN_QNSM_TBL_MAX)
     */
    struct rte_mempool *object_pool[APP_MAX_SOCKETS][EN_QNSM_TBL_MAX];
} QNSM_TBL_POOLS;

typedef struct {
    SERVICE_LIB_COMMON
    QNSM_TBL_PARA       tbl_para[EN_QNSM_TBL_MAX];
    QNSM_LCORE_TBL      tbls;
    QNSM_TBL_INFO       *tbl_info;
} QNSM_TBL_HANDLE;

int32_t qnsm_tbl_pre_init(void);
int32_t qnsm_tbl_init(void **tbl_handle);


#ifdef __cplusplus
}
#endif

#endif

