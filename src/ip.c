#include "ip.h"

#include "arp.h"
#include "ethernet.h"
#include "icmp.h"
#include "net.h"

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip_in(buf_t *buf, uint8_t *src_mac) {
    // TO-DO
    // Step1: 检查数据包长度：
    // 数据包的长度小于 IP 头部长度，丢弃
    if(buf->len < sizeof(ip_hdr_t)){
        return;
    }
    // Step2: 进行 IP 报头检测
    // IP 头部的版本号是否为 IPv4
    // 总长度字段是否小于或等于收到的数据包长度
    ip_hdr_t *hdr = (ip_hdr_t *) buf->data;
    if(hdr->version != IP_VERSION_4) {
        return;
    }
    // 总长度字段是否小于或等于收到的数据包长度
    if(swap16(hdr->total_len16) > buf->len) {
        return;
    }
    // Step3: 校验头部校验和
    // 先把 IP 头部的头部校验和字段用其他变量保存起来，接着将该头部校验和字段置为 0。
    uint16_t hdr_checksum16_backup = hdr->hdr_checksum16;
    hdr->hdr_checksum16 = 0;
    // 随后调用 checksum16 函数来计算头部校验和，将计算结果与 IP 头部原本的首部校验和字段进行对比。
    uint16_t hdr_checksum16 = checksum16((uint16_t *) hdr, sizeof(ip_hdr_t)); 
    // 若不一致，说明数据包在传输过程中可能出现损坏，将其丢弃
    if(hdr_checksum16 != hdr_checksum16_backup) {
        return;
    }
    // 若一致，则再将该头部校验和字段恢复成原来的值。
    hdr->hdr_checksum16 = hdr_checksum16_backup;
    
    // Step4 对比目的 IP 地址：
    // IP 地址不是本机的 IP 地址，将其丢弃
    if(memcmp(hdr->dst_ip, net_if_ip, NET_IP_LEN) != 0) {
        return;
    }

    // buf备份， 发送ICMP协议不可达信息
    buf_t copy_buf;
    buf_copy(&copy_buf, buf, buf->len);

    // Step5: 去除填充字段
    // 接收到的数据包的长度大于 IP 头部的总长度字段
    // 调用 buf_remove_padding() 函数去除填充字段。
    if(buf->len > swap16(hdr->total_len16)) {
        buf_remove_padding(buf, buf->len - swap16(hdr->total_len16));
    }
    // Step6: 去掉 IP 报头,调用 buf_remove_header()
    uint8_t protocol = hdr->protocol;
    uint8_t *src_ip = hdr->src_ip;
    buf_remove_header(buf, hdr->hdr_len * 4);
    // Step7: 向上层传递数据包
    // 调用 net_in() 函数向上层传递数据包
    int flag = net_in(buf, protocol, src_ip);
    // 若遇到不能识别的协议类型，调用 icmp_unreachable() 函数返回 ICMP 协议不可达信息。
    if(flag == -1) {
        icmp_unreachable(&copy_buf, src_ip, ICMP_CODE_PROTOCOL_UNREACH);
    }
    // 需要特别注意的是，在 Step 6 中已经去掉了 IP 报头
    // 在发出 ICMP 协议报文前，需重新加入 IP 报头，以确保报文格式的完整性。
    // 调用 icmp_unreachable() 这个空函数，并传入 ICMP_CODE_PROTOCOL_UNREACH（ICMP 协议不可达信息）

}
/**
 * @brief 处理一个要发送的ip分片
 *
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf) {
    // TO-DO
    // Step1: 调用 buf_add_header() 函数增加 IP 数据报头部缓存空间
    buf_add_header(buf, sizeof(ip_hdr_t));
    // Step2: 填写 IP 数据报头部字段
    ip_hdr_t *hdr = (ip_hdr_t *) buf->data;
    // 版本号
    hdr->version = IP_VERSION_4;
    //首部长度
    hdr->hdr_len = sizeof(ip_hdr_t) / 4;
    // 区分服务
    hdr->tos = 0;
    // 总长度
    hdr->total_len16 = swap16(buf->len);
    hdr->id16 = swap16(id);
    hdr->flags_fragment16 = swap16((mf ? IP_MORE_FRAGMENT : 0) | offset);
    hdr->ttl = 64;
    hdr->protocol = protocol;
    memcpy(hdr->src_ip, net_if_ip, NET_IP_LEN);
    memcpy(hdr->dst_ip, ip, NET_IP_LEN);
    // Step3: 计算并填写校验和
    // 先把 IP 头部的首部校验和字段填 0
    // 调用 checksum16 函数计算校验和
    // 然后把计算出来的校验和填入首部校验和字段
    hdr->hdr_checksum16 = 0;
    uint16_t new_checksum = checksum16((uint16_t *)hdr, sizeof(ip_hdr_t));
    hdr->hdr_checksum16 = new_checksum;
    // Step4: 调用 arp_out 函数将封装后的 IP 头部和数据发送出去
    arp_out(buf, ip);
}

/**
 * @brief 处理一个要发送的ip数据包
 *
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol) {
    // TO-DO
    // Step1 检查数据报包长
    // 首先检查从上层传递下来的数据报包长是否大于 IP 协议最大负载包长（1500 字节（MTU）减去 IP 首部长度）。
    int max_load_length = 1500 - sizeof(ip_hdr_t);
    static uint16_t id = 0;
    // Step2 分片处理
    // 若数据报包长超过 IP 协议最大负载包长，则需要进行分片发送。
    if (buf->len > max_load_length) {
        int offset = 0;
        while (offset < buf->len) {
            // 如果截断后最后的一个分片小于或等于 IP 协议最大负载包长，调用 buf_init() 初始化一个 ip_buf，其大小等于该分片大小
            int frag_size = (buf->len - offset > max_load_length) ? max_load_length : (buf->len - offset);
            // 首先调用 buf_init() 初始化一个 ip_buf。    
            buf_t ip_buf;
            buf_init(&ip_buf, frag_size);
            memcpy(ip_buf.data, buf->data + offset, frag_size);
            // 需要注意的是，最后一个分片的 MF（更多分片标志）应置为 0。
            int more_fragment = (offset + frag_size < buf->len) ? 1 : 0; // 最后一个分片 MF = 0

            ip_fragment_out(&ip_buf, ip, protocol, id, offset / 8, more_fragment); // 注意 offset 单位为 8 字节
            offset += frag_size;
        } 
    } else {
        // Step3 直接发送：
        // 若数据报包长没有超过 IP 协议最大负载包长
        // 直接调用 ip_fragment_out() 函数发送出去。
        ip_fragment_out(buf, ip, protocol, id, 0, 0);
    }
    id ++;
}

/**
 * @brief 初始化ip协议
 *
 */
void ip_init() {
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}