#include "udp.h"

#include "icmp.h"
#include "ip.h"

/**
 * @brief udp处理程序表
 *
 */
map_t udp_table;

/**
 * @brief 处理一个收到的udp数据包
 *
 * @param buf 要处理的包
 * @param src_ip 源ip地址
 */
void udp_in(buf_t *buf, uint8_t *src_ip) {
    // TO-DO
    // Step1 包检查
    // 判断数据报的长度是否小于 UDP 首部长度
    if (buf->len < sizeof(udp_hdr_t)) {
        return;
    }
    // 或者接收到的包长度是否小于 UDP 首部长度字段给出的长度
    udp_hdr_t *hdr = (udp_hdr_t *)buf->data;

    // 报文长度字段是网络字节序，需要转换
    uint16_t total_len = swap16(hdr->total_len16);
    if (buf->len < total_len) {
        return;
    }
    // Step2 重新计算校验和
    // 先把首部的校验和字段保存起来
    uint16_t checksum_backup = hdr->checksum16;
    // 然后将该字段填充为 0, 接着调用 transport_checksum() 函数重新计算校验和
    hdr->checksum16 = 0;
    uint16_t checksum = transport_checksum(NET_PROTOCOL_UDP, buf, src_ip, net_if_ip);
    // 将计算得到的校验和值与接收到的 UDP 数据报的校验和进行比较
    if (checksum != checksum_backup) {
        // 如果两者不一致，则说明数据报在传输过程中可能发生了错误，将其丢弃。
        return;
    }
    hdr->checksum16 = checksum;
    // Step3 查询处理函数：
    // 调用 map_get() 函数，在 udp_table 中查询是否有该目的端口号对应的处理函数（回调函数）。
    uint16_t dst_port = swap16(hdr->dst_port16);
    udp_handler_t *handler = map_get(&udp_table, &dst_port);
    // Step4 处理未找到处理函数的情况：
    // 如果在 udp_table 中没有找到对应的处理函数
    if(handler == NULL) {
        // 调用 buf_add_header() 函数增加 IPv4 数据报头部
        // 再调用 icmp_unreachable() 函数发送一个端口不可达的 ICMP 差错报文
        // 通知发送方该端口不可用
        buf_add_header(buf, sizeof(ip_hdr_t));
        icmp_unreachable(buf, src_ip, ICMP_CODE_PORT_UNREACH);
    } else {
        // Step5 调用处理函数：如果在 udp_table 中能找到对应的处理函数
        // 去掉 UDP 报头，调用该处理函数对数据进行相应的处理
        buf_remove_header(buf, sizeof(udp_hdr_t));
        (* handler)(buf->data, buf->len, src_ip, swap16(hdr->src_port16));
    }
}

/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的包
 * @param src_port 源端口号
 * @param dst_ip 目的ip地址
 * @param dst_port 目的端口号
 */
void udp_out(buf_t *buf, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port) {
    // TO-DO
    // Step1: 添加 UDP 报头：
    // 调用 buf_add_header() 函数，为待发送的数据添加 UDP 报头
    buf_add_header(buf, sizeof(udp_hdr_t));
    // Step2 填充 UDP 首部字段：
    // 依次填充 UDP 首部的各个字段，如源端口号、目的端口号、长度等。
    udp_hdr_t *hdr = (udp_hdr_t *) buf->data;
    hdr->src_port16 = swap16(src_port);
    hdr->dst_port16 = swap16(dst_port);
    hdr->total_len16 = swap16(buf->len);
    // Step3 计算并填充校验和：
    // 先将校验和字段填充为 0
    hdr->checksum16 = 0;
    // 然后调用 transport_checksum() 函数计算 UDP 数据报的校验和
    // 计算完成后，将得到的校验和结果填入校验和字段。
    hdr->checksum16 = transport_checksum(
        NET_PROTOCOL_UDP,
        buf,
        net_if_ip,
        dst_ip
    );
    // Step4 发送 UDP 数据报：
    // 调用 ip_out() 函数，将封装好的 UDP 数据报发送出去。
    ip_out(buf, dst_ip, NET_PROTOCOL_UDP);
}

/**
 * @brief 初始化udp协议
 *
 */
void udp_init() {
    map_init(&udp_table, sizeof(uint16_t), sizeof(udp_handler_t), 0, 0, NULL, NULL);
    net_add_protocol(NET_PROTOCOL_UDP, udp_in);
}

/**
 * @brief 打开一个udp端口并注册处理程序
 *
 * @param port 端口号
 * @param handler 处理程序
 * @return int 成功为0，失败为-1
 */
int udp_open(uint16_t port, udp_handler_t handler) {
    return map_set(&udp_table, &port, &handler);
}

/**
 * @brief 关闭一个udp端口
 *
 * @param port 端口号
 */
void udp_close(uint16_t port) {
    map_delete(&udp_table, &port);
}

/**
 * @brief 发送一个udp包
 *
 * @param data 要发送的数据
 * @param len 数据长度
 * @param src_port 源端口号
 * @param dst_ip 目的ip地址
 * @param dst_port 目的端口号
 */
void udp_send(uint8_t *data, uint16_t len, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port) {
    buf_init(&txbuf, len);
    memcpy(txbuf.data, data, len);
    udp_out(&txbuf, src_port, dst_ip, dst_port);
}