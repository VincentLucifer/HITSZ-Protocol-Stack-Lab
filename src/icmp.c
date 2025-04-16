#include "icmp.h"

#include "ip.h"
#include "net.h"

/**
 * @brief 发送icmp响应
 *
 * @param req_buf 收到的icmp请求包
 * @param src_ip 源ip地址
 */
static void icmp_resp(buf_t *req_buf, uint8_t *src_ip) {
    // TO-DO
    // Step1: 初始化并封装数据
    // 调用 buf_init() 函数来初始化 txbuf
    buf_init(&txbuf, req_buf->len);
    // 封装 ICMP 报头和数据
    // 数据部分直接拷贝来自接收的回显请求报文中的数据，保证信息的一致性。
    memcpy(txbuf.data, req_buf->data, req_buf->len);
    icmp_hdr_t *hdr = (icmp_hdr_t *) txbuf.data;
    icmp_hdr_t *req_hdr = (icmp_hdr_t *) req_buf->data;
    hdr->type = ICMP_TYPE_ECHO_REPLY;
    hdr->code = 0;
    hdr->id16 = req_hdr->id16;
    hdr->seq16 = req_hdr->seq16;
    // Step2: 填写校验和
    // ICMP 的校验和计算方法与 IP 协议校验和算法相同。
    // 并将校验和其填写到相应位置，确保报文在传输过程中的完整性。
    hdr->checksum16 = 0;
    hdr->checksum16 = checksum16((uint16_t *)txbuf.data, txbuf.len);
    // Step3: 发送数据报
    // 调用 ip_out() 函数将封装好且填写了校验和的 ICMP 数据报发送出去。
    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_ip 源ip地址
 */
void icmp_in(buf_t *buf, uint8_t *src_ip) {
    // TO-DO
    // Step1: 报头检测, 检查接收到的数据包长度
    // 若包长小于 ICMP 头部长度，表明数据包不完整，丢弃
    if(buf->len < sizeof(icmp_hdr_t)) {
        return;
    }
    // Step2: 查看 ICMP 报文的类型：
    // 重点关注是否为回显请求类型
    icmp_hdr_t *hdr = (icmp_hdr_t *) buf->data;
    // Step3: 回送回显应答
    // 如果报文的 ICMP 类型是回显请求
    // 则调用 icmp_resp() 函数回送一个回显应答（ping 应答）。
    if(hdr->type == ICMP_TYPE_ECHO_REQUEST) {
        icmp_resp(buf, src_ip);
    }
}

/**
 * @brief 发送icmp不可达
 *
 * @param recv_buf 收到的ip数据包
 * @param src_ip 源ip地址
 * @param code icmp code，协议不可达或端口不可达
 */
void icmp_unreachable(buf_t *recv_buf, uint8_t *src_ip, icmp_code_t code) {
    // TO-DO
    // Step1 初始化并填写报头：
    // 首先调用 buf_init() 函数来初始化 txbuf。
    // 报头 + IP头 + 前8字节
    buf_init(&txbuf, sizeof(icmp_hdr_t) + sizeof(ip_hdr_t) + 8);
    // 然后，按照 ICMP 协议规范填写 ICMP 报头首部，包含类型、代码等关键信息。
    icmp_hdr_t *icmp_hdr = (icmp_hdr_t *)txbuf.data;
    icmp_hdr->type = ICMP_TYPE_UNREACH;
    icmp_hdr->code = code;
    icmp_hdr->id16 = 0;
    icmp_hdr->seq16 = 0;

    // Step2 填写数据与校验和：
    // 该部分要包含 IP 数据报首部
    ip_hdr_t *ip_hdr = (ip_hdr_t *)(icmp_hdr + 1);
    ip_hdr_t *recv_ip_hdr = (ip_hdr_t *)recv_buf->data;
    memcpy(ip_hdr, recv_ip_hdr, sizeof(ip_hdr_t));
    //IP 数据报的前 8 个字节的数据字段
    uint8_t *data = (uint8_t *)(ip_hdr + 1);    
    uint8_t *recv_ip_data = (uint8_t *)(recv_ip_hdr + 1);
    memcpy(data, recv_ip_data, 8);
    // 使用与 IP 协议相同的校验和算法计算校验和, 并将其填写到相应位置。
    icmp_hdr->checksum16 = 0;
    icmp_hdr->checksum16 = checksum16((uint16_t *)txbuf.data, sizeof(icmp_hdr_t) + sizeof(ip_hdr_t) + 8);
    
    // Step3 发送数据报：
    // 调用 ip_out() 函数将封装好且填写了校验和的 ICMP 差错数据报发送出去。
    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 初始化icmp协议
 *
 */
void icmp_init() {
    net_add_protocol(NET_PROTOCOL_ICMP, icmp_in);
}