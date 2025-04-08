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
#ifndef __QNSM_CRM__
#define __QNSM_CRM__

#include "list.h"
#include "app.h"

#ifdef __cplusplus
extern "C" {
#endif

#define QNSM_CRM_MAX_MSGQ_IN  (48)
#define QNSM_CRM_MAX_MSGQ_OUT (48)

#if QNSM_PART("crm msg")
enum qnsm_crm_msg_type {
    EN_QNSM_CRM_MSG_ONLINE = 0,
    EN_QNSM_CRM_MSG_OFFLINE,
    EN_QNSM_CRM_MSG_MAX,
};

enum qnsm_crm_act {
    EN_QNSM_CRM_ACT_SUBCRIBE = 0x01,
    EN_QNSM_CRM_ACT_PUBLISH  = 0x02,
    EN_QNSM_CRM_ACT_MAX,
};

typedef struct {
    enum qnsm_crm_act act;
    uint32_t pub_lcore;
    uint32_t sub_lcore;
} QNSM_CR_ACT_HEAD;

typedef struct {

    uint32_t tx_lcore;
    uint32_t rx_lcore;
    struct rte_ring *ring;
} QNSM_CR_VALUE;

typedef struct {
    enum qnsm_crm_msg_type type;
    int32_t resp_status;
    QNSM_CR_ACT_HEAD act_head;
    int32_t value_len;
    QNSM_CR_VALUE cr_value[0];
} QNSM_CRM_MSG;

static inline void *
qnsm_crm_alloc(void)
{
    return rte_zmalloc(NULL, 2048, RTE_CACHE_LINE_SIZE);
}

static inline void
qnsm_crm_free(void *msg)
{
    rte_free(msg);
}
#endif

#if QNSM_PART("crm agent")

typedef void (*QNSM_CRM_RESP_HANDLER)(void *arg, void *msg);

typedef struct {
    /*agent que*/
    struct rte_ring *msgq_in;
    struct rte_ring *msgq_out;
} QNSM_CRM_AGENT;
void qnsm_crm_agent_msg_send(void *req_msg);
void qnsm_crm_agent_msg_handle(QNSM_CRM_AGENT *crm_agent, QNSM_CRM_RESP_HANDLER rsp_cb, void *arg);
int32_t qnsm_crm_agent_init(struct app_params *app, struct app_pipeline_params *pipeline_params, void **tbl_handle);
#endif

#if QNSM_PART("crm")
// 订阅节点结构体，通过链表将多个订阅者组织在一起
typedef struct {
    struct qnsm_list_head node;//链表节点，用于将订阅者添加到链表中
    uint32_t target_lcore_id;//目标逻辑核心ID，表示消息发送给哪个逻辑核心，这个有啥用？
} QNSM_CR_SUB_NODE;

//通过链表头节点可以遍历所有订阅者
typedef struct {
    struct qnsm_list_head subscribe_head;//订阅者链表头节点
} QNSM_CR_SUB_LIST;

typedef struct {
    enum qnsm_crm_act act;//动作类型
    QNSM_CR_SUB_LIST subscribe_list;//订阅者列表

    /*ring*/
    struct rte_ring *ring[APP_MAX_LCORES];//和其他核心通信的环形缓冲区数组
} QNSM_CR;

// 核心资源管理器结构体
// 管理消息队列系统
// 管理每个核心的资源
// 处理核心间的通信
typedef struct {
    /*rcv/snd msg*/
    uint8_t msgq_id[APP_MAX_LCORES];//消息队列ID数组
    struct rte_ring *msgq_in[QNSM_CRM_MAX_MSGQ_IN];//输入消息队列数组
    struct rte_ring *msgq_out[QNSM_CRM_MAX_MSGQ_OUT];//输出消息队列数组
    uint32_t n_msgq;//消息队列数量

    QNSM_CR cr_map[APP_MAX_LCORES];//核心资源映射表
} QNSM_CRM;

//整体架构和工作原理
//采用发布-订阅模式实现核心间的解耦
//1. 每个逻辑核心lcore都有自己的资源管理器
//2. 核心可以发布资源或订阅其他核心的资源
//3. 发布者将资源发布到消息队列中，订阅者从消息队列中接收资源，
//通过环形缓冲区rte_ring实现核心间的通信
//4. 消息队列用于管理核心间的消息传递

typedef void (*QMSM_CRM_REQ_HANDLER)(QNSM_CRM *crm, void *msg);

void qnsm_crm_msg_req_handle(void *crm);
int32_t qnsm_crm_init(struct app_params *app, void **crm);
#endif

#ifdef __cplusplus
}
#endif

#endif
