#include "utils.h"

#include "net.h"

#include <stdio.h>
#include <string.h>
/**
 * @brief ip转字符串
 *
 * @param ip ip地址
 * @return char* 生成的字符串
 */
char *iptos(uint8_t *ip) {
    static char output[3 * 4 + 3 + 1];
    sprintf(output, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
    return output;
}

/**
 * @brief mac转字符串
 *
 * @param mac mac地址
 * @return char* 生成的字符串
 */
char *mactos(uint8_t *mac) {
    static char output[2 * 6 + 5 + 1];
    sprintf(output, "%02X-%02X-%02X-%02X-%02X-%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return output;
}

/**
 * @brief 时间戳转字符串
 *
 * @param timestamp 时间戳
 * @return char* 生成的字符串
 */
char *timetos(time_t timestamp) {
    static char output[20];
    struct tm *utc_time = gmtime(&timestamp);
    sprintf(output, "%04d-%02d-%02d %02d:%02d:%02d", utc_time->tm_year + 1900, utc_time->tm_mon + 1, utc_time->tm_mday, utc_time->tm_hour, utc_time->tm_min, utc_time->tm_sec);
    return output;
}

/**
 * @brief ip前缀匹配
 *
 * @param ipa 第一个ip
 * @param ipb 第二个ip
 * @return uint8_t 两个ip相同的前缀长度
 */
uint8_t ip_prefix_match(uint8_t *ipa, uint8_t *ipb) {
    uint8_t count = 0;
    for (size_t i = 0; i < 4; i++) {
        uint8_t flag = ipa[i] ^ ipb[i];
        for (size_t j = 0; j < 8; j++) {
            if (flag & (1 << 7))
                return count;
            else
                count++, flag <<= 1;
        }
    }
    return count;
}

/**
 * @brief 计算16位校验和
 *
 * @param buf 要计算的数据包
 * @param len 要计算的长度
 * @return uint16_t 校验和
 */
uint16_t checksum16(uint16_t *data, size_t len) {
    // TO-DO
    // Step1: 按 16 位分组相加：
    // 把 data 看成是每 16 个 bit（即 2 个字节）组成一个数，依次相加。
    // 由于 16 位加法的结果可能会超过 16 位，因此加法结果需要用 32 位数来保存。
    uint32_t sum = 0;

    for(int i = 0; i < len; i += 2) {
        if(i == len -1) {
            // Step2: 处理剩余 8 位
            // 如果最后还剩 8 个 bit 值，也要将这个 8bit 值与之前的和相加。
            sum += *((uint8_t *)data + i);
        } else {
            sum += data[i / 2];
        }
    }
    // Step3 循环处理高 16 位：
    // 判断相加后 32bit 结果值的高 16 位是否为 0。
    // 如果不为 0，则将高 16 位和低 16 位相加，如此循环，直至高 16 位为 0 为止。
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    // Step4 取反得到校验和：
    // 将上述处理后的和（低 16 位）取反，即得到校验和。
    return (uint16_t)(~sum);
}

#pragma pack(1)
typedef struct peso_hdr {
    uint8_t src_ip[4];     // 源IP地址
    uint8_t dst_ip[4];     // 目的IP地址
    uint8_t placeholder;   // 必须置0,用于填充对齐
    uint8_t protocol;      // 协议号
    uint16_t total_len16;  // 整个数据包的长度
} peso_hdr_t;
#pragma pack()

/**
 * @brief 计算传输层协议（如TCP/UDP）的校验和
 *
 * @param protocol  传输层协议号（如NET_PROTOCOL_UDP、NET_PROTOCOL_TCP）
 * @param buf       待计算的数据包缓冲区
 * @param src_ip    源IP地址
 * @param dst_ip    目的IP地址
 * @return uint16_t 计算得到的16位校验和
 */
uint16_t transport_checksum(uint8_t protocol, buf_t *buf, uint8_t *src_ip, uint8_t *dst_ip) {
    // TO-DO
    uint16_t checksum = 0;
    if(protocol == NET_PROTOCOL_UDP) {
        // Step1 增加 UDP 伪头部：
        // 调用 buf_add_header() 函数，为 UDP 数据报增加 UDP 伪头部
        uint16_t len_backup = swap16(buf->len);
        buf_add_header(buf, sizeof(peso_hdr_t));

        // Step2 暂存 IP 头部：
        // 将被 UDP 伪头部覆盖的 IP 头部拷贝出来，暂存起来，避免其被 UDP 伪头部覆盖。
        peso_hdr_t pre;
        memcpy(&pre, buf->data, sizeof(peso_hdr_t));
    
        // Step3 填写 UDP 伪头部字段：
        // 按照 UDP 伪头部的格式要求，填写 12 字节的字段
        // 包括源 IP 地址、目的 IP 地址、协议号和 UDP 长度等。
        peso_hdr_t* peso_hdr = (peso_hdr_t*)(buf->data);
        memcpy(peso_hdr->src_ip, src_ip, NET_IP_LEN);
        memcpy(peso_hdr->dst_ip, dst_ip, NET_IP_LEN);

        peso_hdr->placeholder = 0;
        peso_hdr->protocol = NET_PROTOCOL_UDP;
        peso_hdr->total_len16 = len_backup;
        // Step4 计算 UDP 校验和：
        // 对包含 UDP 伪头部、UDP 头部和 UDP 数据的数据块进行校验和计算。
        checksum = checksum16((uint16_t*)buf->data, buf->len);
        // Step5 恢复 IP 头部：
        // 再将 Step2 中暂存的 IP 头部拷贝回来，确保 IP 头部信息的完整性。
        memcpy(buf->data, &pre, sizeof(peso_hdr_t));
        // Step6 去掉 UDP 伪头部：
        // 调用 buf_remove_header() 函数，去掉之前添加的 UDP 伪头部
        // 因为伪头部不会随 UDP 数据报一起传输。
        buf_remove_header(buf, sizeof(peso_hdr_t));
        // Step7 返回校验和值：
        // 返回计算得到的 UDP 校验和值
    } else if(protocol == NET_PROTOCOL_TCP) {
        uint16_t len = (uint16_t)buf->len;
    
        // 获取 TCP 校验和所需的伪头部位置
        peso_hdr_t* peso_hdr = (peso_hdr_t*)(buf->data - sizeof(peso_hdr_t));
    
        peso_hdr_t pre; //暂存被覆盖的IP头
    
        // 备份原始伪头部内容，防止后续计算修改原数据
        memcpy(&pre, peso_hdr, sizeof(peso_hdr_t));
    
        // 填写伪头部的源 IP 和目的 IP 地址
        memcpy(peso_hdr->src_ip, src_ip, NET_IP_LEN);
        memcpy(peso_hdr->dst_ip, dst_ip, NET_IP_LEN);
    
        // 伪头部中的保留字段设为 0
        peso_hdr->placeholder = 0;
    
        // 指定协议类型为 TCP
        peso_hdr->protocol = NET_PROTOCOL_TCP;
    
        // 设置 TCP 段长度（需要大小端转换）
        peso_hdr->total_len16 = swap16(len);
    
        // 计算 TCP 校验和，包含 TCP 数据 + 伪头部
        checksum = checksum16((uint16_t*)peso_hdr, len + sizeof(peso_hdr_t));
    
        // 将伪头部恢复为原内容
        memcpy(peso_hdr, &pre, sizeof(peso_hdr_t));
    }
    return checksum;
}