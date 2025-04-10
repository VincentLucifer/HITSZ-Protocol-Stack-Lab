#include "arp.h"

#include "ethernet.h"
#include "net.h"

#include <stdio.h>
#include <string.h>
/**
 * @brief 初始的arp包
 *
 */
static const arp_pkt_t arp_init_pkt = {
    .hw_type16 = swap16(ARP_HW_ETHER),
    .pro_type16 = swap16(NET_PROTOCOL_IP),
    .hw_len = NET_MAC_LEN,
    .pro_len = NET_IP_LEN,
    .sender_ip = NET_IF_IP,
    .sender_mac = NET_IF_MAC,
    .target_mac = {0}};

/**
 * @brief arp地址转换表，<ip,mac>的容器
 *
 */
map_t arp_table;

/**
 * @brief arp buffer，<ip,buf_t>的容器
 *
 */
map_t arp_buf;

/**
 * @brief 打印一条arp表项
 *
 * @param ip 表项的ip地址
 * @param mac 表项的mac地址
 * @param timestamp 表项的更新时间
 */
void arp_entry_print(void *ip, void *mac, time_t *timestamp) {
    printf("%s | %s | %s\n", iptos(ip), mactos(mac), timetos(*timestamp));
}

/**
 * @brief 打印整个arp表
 *
 */
void arp_print() {
    printf("===ARP TABLE BEGIN===\n");
    map_foreach(&arp_table, arp_entry_print);
    printf("===ARP TABLE  END ===\n");
}

/**
 * @brief 发送一个arp请求
 *
 * @param target_ip 想要知道的目标的ip地址
 */
void arp_req(uint8_t *target_ip) {
    // TO-DO
    // Step1: 初始化缓冲区 buf_init() txbuf
    buf_init(&txbuf, sizeof(arp_pkt_t));

    // Step2: 填写ARP报头
    arp_pkt_t *pkt = (arp_pkt_t *) txbuf.data;
    memcpy(pkt, &arp_init_pkt, sizeof(arp_pkt_t));

    // Step3: 设置操作类型 ARP_REQUEST
    pkt->opcode16 = swap16(ARP_REQUEST);
    memcpy(pkt->target_ip, target_ip, NET_IP_LEN);

    // Step4: 发送ARP报文 ethernet_out
    ethernet_out(&txbuf, ether_broadcast_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 发送一个arp响应
 *
 * @param target_ip 目标ip地址
 * @param target_mac 目标mac地址
 */
void arp_resp(uint8_t *target_ip, uint8_t *target_mac) {
    // TO-DO
    // Step1: 初始化缓冲区：
    // 调用 buf_init() 函数初始化 txbuf。
    buf_init(&txbuf, sizeof(arp_pkt_t));
    // Step2: 填写 ARP 报头首部：
    // 按照 ARP 协议规范，准确填写 ARP 报头首部信息。
    arp_pkt_t *pkt = (arp_pkt_t *) txbuf.data;
    memcpy(pkt, &arp_init_pkt, sizeof(arp_pkt_t));
    pkt->opcode16 = swap16(ARP_REPLY);
    memcpy(pkt->target_ip, target_ip, NET_IP_LEN);
    memcpy(pkt->target_mac, target_mac, NET_MAC_LEN);
    // Step3: 发送 ARP 报文：
    // 调用 ethernet_out() 函数将填充好的 ARP 报文发送出去。
    ethernet_out(&txbuf, target_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void arp_in(buf_t *buf, uint8_t *src_mac) {
    // TO-DO
    // Step1: 检查数据长度
    // 判断数据长度，若数据长度小于 ARP 头部长度，则认为数据包不完整，将其丢弃，不予处理。
    if(buf->len < sizeof(arp_pkt_t)) {
        return;
    }
    // Step2: 报头检查,查看报文是否完整
    arp_pkt_t *arp_pkt = (arp_pkt_t *) buf->data;
    // 硬件类型
    if(arp_pkt->hw_type16 != swap16(ARP_HW_ETHER)) {
        return;
    }
    // 上层协议类型
    if(arp_pkt->pro_type16 != swap16(NET_PROTOCOL_IP)) {
        return;
    }
    // MAC硬件地址长度
    if(arp_pkt->hw_len != NET_MAC_LEN) {
        return;
    }
    // IP协议地址长度
    if(arp_pkt->pro_len != NET_IP_LEN) {
        return;
    }    
    // 操作类型
    if(arp_pkt->opcode16 != swap16(ARP_REQUEST) && arp_pkt->opcode16 != swap16(ARP_REPLY)) {
        return;
    }

    // Step3: 更新 ARP 表项
    // 调用 map_set() 函数更新 ARP 表项
    map_set(&arp_table, arp_pkt->sender_ip, arp_pkt->sender_mac);
    
    // Step4: 查看缓存情况
    // 调用 map_get() 函数查看该接收报文的 IP 地址是否有对应的 arp_buf 缓存
    buf_t *buf2 = (buf_t *) map_get(&arp_buf, arp_pkt->sender_ip);
    // 有缓存，说明 ARP 分组队列里面有待发送的数据包。
    if(buf2 != NULL) {
        // 将缓存的数据包 arp_buf 发送给以太网层，调用 ethernet_out() 函数
        ethernet_out(buf2, arp_pkt->sender_mac, NET_PROTOCOL_IP);
        // 调用 map_delete() 函数将这个缓存的数据包删除。   
        map_delete(&arp_buf, arp_pkt->sender_ip);
    } else {
        // 无缓存: 接收报文的 IP 地址没有对应的 arp_buf 缓存
        // 还需要判断接收到的报文是否为 ARP_REQUEST 请求报文，并且该请求报文的 target_ip 是本机的 IP。
        if(arp_pkt->opcode16 == swap16(ARP_REQUEST) && memcmp(arp_pkt->target_ip, net_if_ip, NET_IP_LEN) == 0) {
            // 若是，则认为是请求本主机 MAC 地址的 ARP 请求报文，调用 arp_resp() 函数回应一个响应报文。
            arp_resp(arp_pkt->sender_ip, arp_pkt->sender_mac);
        }   
    }
}

/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的数据包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void arp_out(buf_t *buf, uint8_t *ip) {
    // TO-DO
    // Step1: 查找ARP表 map_get(), 在arp_table中查找
    uint8_t *MAC = (uint8_t *) map_get(&arp_table, ip);

    // Step2: 找到对应MAC地址
    // 找到MAC地址，将数据包直接发送给以太网层
    // 调用ethernet_out函数将数据包发出
    if(MAC != NULL) {
        ethernet_out(buf, MAC, NET_PROTOCOL_IP);
    } else {
        // Step3: 未找到对应MAC地址
        // 若未找到对应的MAC地址
        // 进一步判断arp_buf是否有包
        buf_t *buf2 = (buf_t *) map_get(&arp_buf, ip);
        if(buf2 != NULL) {
            // 有包，正在等待IP回应ARP请求， 不再发送ARP请求
            return;
        } else {
            // 没有包，调用map_set()函数将IP层的数据包缓存到arp_buf
            // 调用arp_req()函数，发送一个请求目标IP地址对应的MAC地址的ARP request报文
            map_set(&arp_buf, ip, buf);
            arp_req(ip);
        }
    }
}

/**
 * @brief 初始化arp协议
 *
 */
void arp_init() {
    map_init(&arp_table, NET_IP_LEN, NET_MAC_LEN, 0, ARP_TIMEOUT_SEC, NULL, NULL);
    map_init(&arp_buf, NET_IP_LEN, sizeof(buf_t), 0, ARP_MIN_INTERVAL, NULL, buf_copy);
    net_add_protocol(NET_PROTOCOL_ARP, arp_in);
    arp_req(net_if_ip);
}