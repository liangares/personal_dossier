//#include "stdafx.h"
//#include "pcap.h"
//#include<winsock2.h>
//#include "remote-ext.h"
#include "stdafx.h"  

//#include<winsock2.h>
//#include <winsock.h>
#include<time.h>

#include <winsock2.h>
#include <ws2tcpip.h>
#include "pcap.h"  
#include <windows.h> 


#pragma comment(lib,"wpcap.lib")  
#pragma comment(lib,"packet.lib")  
#pragma comment(lib,"ws2_32.lib")  


void ethernet_protocol_packet_callback(u_char *argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content);
void ip_protool_packet_callback(u_char *argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content);
void tcp_protool_packet_callback(u_char *argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content);
void udp_protool_packet_callback(u_char *argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content);
void arp_Analyse(const u_char *pkt_data);
void icmp_Analyse(const u_char *pkt_data);
void igmp_Analyse(const u_char *pkt_data);

// 以太网协议头  
typedef struct ether_header
{
	u_int8_t ether_dhost[6]; // 目的 Mac 地址  
	u_int8_t ether_shost[6]; // 源 Mac 地址  
	u_int16_t ether_type;    // 协议类型  
}ether_header;

//IPv4 协议头  
struct ip_header
{
#if defined(WORDS_BIENDIAN)  
	u_int8_t    ip_version : 4, ip_header_length : 4;
#else  
	u_int8_t    ip_header_length : 4, ip_version : 4;
#endif  
	u_int8_t    ip_tos;
	u_int16_t   ip_length;
	u_int16_t   ip_id;
	u_int16_t   ip_off;
	u_int8_t    ip_ttl;
	u_int8_t    ip_protocol;
	u_int16_t   ip_checksum;
	struct in_addr ip_souce_address;
	struct in_addr ip_destination_address;
};

//UDP 协议头  
struct udphdr
{
	u_int16_t source_port; /* 源地址端口 */
	u_int16_t dest_port;    /* 目的地址端口 */
	u_int16_t len;     /*UDP 长度 */
	u_int16_t check;   /*UDP 校验和 */
};

//TCP 协议头  
#define __LITTLE_ENDIAN_BITFIELD  
struct tcphdr
{
	u_int16_t   source_port;         /* 源地址端口 */
	u_int16_t   dest_port;           /* 目的地址端口 */
	u_int32_t   seq;            /* 序列号 */
	u_int32_t   ack_seq;        /* 确认序列号 */
#if defined(__LITTLE_ENDIAN_BITFIELD)  
	u_int16_t res1 : 4,   /* 保留 */
		doff : 4,             /* 偏移 */
		fin : 1,              /* 关闭连接标志 */
		syn : 1,              /* 请求连接标志 */
		rst : 1,              /* 重置连接标志 */
		psh : 1,              /* 接收方尽快将数据放到应用层标志 */
		ack : 1,              /* 确认序号标志 */
		urg : 1,              /* 紧急指针标志 */
		ece : 1,              /* 拥塞标志位 */
		cwr : 1;              /* 拥塞标志位 */
#elif defined(__BIG_ENDIAN_BITFIELD)  
	u_int16_t doff : 4,   /* 偏移 */
		res1 : 4,             /* 保留 */
		cwr : 1,              /* 拥塞标志位 */
		ece : 1,              /* 拥塞标志位 */
		urg : 1,              /* 紧急指针标志 */
		ack : 1,              /* 确认序号标志 */
		psh : 1,              /* 接收方尽快将数据放到应用层标志 */
		rst : 1,              /* 重置连接标志 */
		syn : 1,              /* 请求连接标志 */
		fin : 1;              /* 关闭连接标志 */
#else  
	u_int16_t   flag;
#endif   
	u_int16_t   window;         /* 滑动窗口大小 */
	u_int16_t   check;          /* 校验和 */
	u_int16_t   urg_ptr;        /* 紧急字段指针 */
};

//ICMP 协议头
typedef struct icmp_header
{
	u_int8_t icmp_type;                 //类型
	u_int8_t icmp_code;                 //代码
	u_int16_t icmp_checksum;            //校验和
	u_int16_t icmp_id;                  //标识符
	u_int16_t icmp_sequence;            //序列号
}icmp_header;

//IP 结构地址
typedef struct ip_address   //ip地址结构
{
	u_int16_t  byte1;
	u_int16_t  byte2;
	u_int16_t  byte3;
	u_int16_t  byte4;
}ip_address;

//IGMP 协议头
typedef struct igmp_header
{
	u_int8_t igmp_type;                 //类型
	u_int8_t igmp_time;                 //最大响应时间
	u_int16_t igmp_checksum;            //校验和
	ip_address  addr;                  //组地址

}igmp_header;

////////////////////////////////////////////////////////////////////////////////////////////////

// 以太网协议分析  
void ethernet_protocol_packet_callback(u_char *argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content)
{

	int i;
	int ethernet_type;
	//u_short ethernet_type;
	struct ether_header *ethernet_protocol;  //协议类型
	u_char *mac_string;
	static int packet_number = 1;

	printf("-------------------------------------------------------------------------------------\n");
	printf("捕获第 %d 个网络数据包 \n", packet_number);
	printf("捕获时间:%d\n", packet_header->ts.tv_sec);
	printf("数据包长度:%d\n", packet_header->len);
	printf("--------- 以太网协议 ---------\n");
	ethernet_protocol = (struct ether_header*)packet_content;// 获得数据包内容 
	
	ethernet_type = ntohs(ethernet_protocol->ether_type);// 获得以太网类型  
	printf("以太网类型:%04x\n", ethernet_type);
	switch (ethernet_type)
	{

		case 0x0800:
			//printf(" (IP协议)\n\r");//IP协议分析
			ip_protool_packet_callback(argument, packet_header, packet_content + sizeof(ether_header));
			break;


		case 0x0806:
			printf(" (ARP协议)\n\r");//ARP协议分析
			arp_Analyse(packet_content);
			break;

		default:
			printf("\n\r未知类型数据报:0x%0X\n");
			break;
	}

	mac_string = ethernet_protocol->ether_shost;
	printf("MAC 帧源地址:%02x:%02x:%02x:%02x:%02x:%02x\n", *mac_string, *(mac_string + 1), *(mac_string + 2), *(mac_string + 3), *(mac_string + 4), *(mac_string + 5));
	mac_string = ethernet_protocol->ether_dhost;
	printf("MAC 帧目的地址:%02x:%02x:%02x:%02x:%02x:%02x\n", *mac_string, *(mac_string + 1), *(mac_string + 2), *(mac_string + 3), *(mac_string + 4), *(mac_string + 5));
	if (ethernet_type == 0x0800)// 继续分析 IP 协议  
	{
		ip_protool_packet_callback(argument, packet_header, packet_content + sizeof(ether_header));
	}
	printf("----------------------------------------------\n");
	packet_number++;
}

//ARP 协议分析
void arp_Analyse(const u_char *pkt_data)
{
	arp_header *ah;

	

	u_int16_t arp_hardware_type;
	u_int16_t arp_protocol_type;
	u_int16_t arp_operation_code;

	/* 获得ARP数据包头部的位置 */
	ah = (arp_header *)(pkt_data + 14);

	/* 将网络字节序列转换成主机字节序列 (大于一个字节要转换)*/
	arp_hardware_type = ntohs(ah->arp_hardware_type);
	arp_protocol_type = ntohs(ah->arp_protocol_type);
	arp_operation_code = ntohs(ah->arp_operation_code);


	printf("ARP(地址解析协议)-----------------------------\n\r");
	printf("--硬件类型=%d\n", arp_hardware_type);
	printf("--协议类型=%d\n", arp_protocol_type);
	printf("--硬件地址长度=%d\n", ah->arp_hardware_length);
	printf("--协议地址长度=%d\n", ah->arp_protocol_length);
	printf("--操作码=%d", arp_operation_code);
	switch (arp_operation_code)
	{
	case 1:
		printf(" (ARP请求)\n");
		break;
	case 2:
		printf(" (ARP 响应)\n");
		break;
	case 3:
		printf(" (RARP 请求)\n");
		break;
	case 4:
		printf(" (RARP 响应)\n");
		break;
	default:
		break;
	}

	printf("--发送端硬件地址=%02x:%02x:%02x:%02x:%02x:%02x\n",
		ah->arp_source_ethernet_address[0],
		ah->arp_source_ethernet_address[1],
		ah->arp_source_ethernet_address[2],
		ah->arp_source_ethernet_address[3],
		ah->arp_source_ethernet_address[4],
		ah->arp_source_ethernet_address[5]);

	printf("--发送端逻辑地址=%d.%d.%d.%d\n",
		ah->arp_source_ip_address[0],
		ah->arp_source_ip_address[1],
		ah->arp_source_ip_address[2],
		ah->arp_source_ip_address[3]);

	printf("--目的端硬件地址=%02x:%02x:%02x:%02x:%02x:%02x\n",
		ah->arp_destination_ethernet_address[0],
		ah->arp_destination_ethernet_address[1],
		ah->arp_destination_ethernet_address[2],
		ah->arp_destination_ethernet_address[3],
		ah->arp_destination_ethernet_address[4],
		ah->arp_destination_ethernet_address[5]);

	printf("--目的端逻辑地址=%d.%d.%d.%d\n",
		ah->arp_destination_ip_address[0],
		ah->arp_destination_ip_address[1],
		ah->arp_destination_ip_address[2],
		ah->arp_destination_ip_address[3]);

}

//IP 协议分析  
void ip_protool_packet_callback(u_char *argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content)
{
	struct ip_header *ip_protocol;
	u_int header_length = 0;
	u_int offset;
	u_char tos;
	u_int16_t checksum;

	ip_protocol = (struct ip_header *)packet_content;
	checksum = ntohs(ip_protocol->ip_checksum);
	tos = ip_protocol->ip_tos;
	offset = ntohs(ip_protocol->ip_off);
	printf("---------IP 协议 ---------\n");
	printf("版本号:%d\n", ip_protocol->ip_version);
	printf("首部长度:%d\n", header_length);
	printf("服务质量:%d\n", tos);
	printf("总长度:%d\n", ntohs(ip_protocol->ip_length));
	printf("标识:%d\n", ntohs(ip_protocol->ip_id));
	printf("偏移:%d\n", (offset & 0x1fff) * 8);
	printf("生存时间:%d\n", ip_protocol->ip_ttl);
	printf("协议类型:%d\n", ip_protocol->ip_protocol);

	printf("检验和:%d\n", checksum);
	printf("源 IP 地址:%s\n", inet_ntoa(ip_protocol->ip_souce_address));
	printf("目的地址:%s\n", inet_ntoa(ip_protocol->ip_destination_address));

	switch (ip_protocol->ip_protocol)
	{
	case 1: 
	{   
		printf("上层协议是 ICMP 协议 \n");
		icmp_Analyse(packet_content);
	}break;
	case 2:
	{
		printf("上层协议是 IGMP 协议 \n");
		igmp_Analyse(packet_content);
	}break;
	case 6:
	{
		printf("上层协议是 TCP 协议 \n");  
		tcp_protool_packet_callback(argument, packet_header, packet_content + sizeof(ip_header));
	}
	break;

	case 17:
	{
		printf("上层协议是 UDP 协议 \n");  
		udp_protool_packet_callback(argument, packet_header, packet_content + sizeof(ip_header));
	}
	break;
	default:break;
	}

}

//TCP 协议分析  
void tcp_protool_packet_callback(u_char *argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content)
{
	struct tcphdr *tcp_protocol;
	u_int header_length = 0;
	u_int offset;
	u_char tos;
	u_int16_t checksum;

	tcp_protocol = (struct tcphdr *) packet_content;
	checksum = ntohs(tcp_protocol->check);

	printf("---------TCP 协议 ---------\n");
	printf("源端口:%d\n", ntohs(tcp_protocol->source_port));
	printf("目的端口:%d\n", ntohs(tcp_protocol->dest_port));
	printf("SEQ:%d\n", ntohl(tcp_protocol->seq));
	printf("ACK SEQ:%d\n", ntohl(tcp_protocol->ack_seq));
	printf("check:%d\n", checksum);


	if (ntohs(tcp_protocol->source_port) == 80 || ntohs(tcp_protocol->dest_port) == 80)
	{
		//http 协议  
		printf("http data:\n%s\n", packet_content + sizeof(tcphdr));
	}

}

//UDP 协议分析  
void udp_protool_packet_callback(u_char *argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content)
{
	struct udphdr *udp_protocol;
	u_int header_length = 0;
	u_int16_t checksum;

	udp_protocol = (struct udphdr *) packet_content;
	checksum = ntohs(udp_protocol->check);

	u_int16_t source_port; /* 源地址端口 */
	u_int16_t dest_port;    /* 目的地址端口 */
	u_int16_t len;     /*UDP 长度 */
	u_int16_t check;   /*UDP 校验和 */

	printf("---------UDP 协议 ---------\n");
	printf("源端口:%d\n", udp_protocol->source_port);
	printf("目的端口:%d\n", udp_protocol->dest_port);
	printf("len:%d\n", udp_protocol->len);
	printf("check:%d\n", checksum);

}

//ICPM 协议分析
void icmp_Analyse(const u_char *pkt_data)
{

	ip_header *ih;
	icmp_header *icmph;


	u_int16_t icmp_checksum;
	u_int16_t icmp_id;
	u_int16_t icmp_sequence;
	//u_int16_t *check_sum;

	

	/* 获得IP数据包头部的位置 */
	ih = (ip_header *)(pkt_data + 14);

	/* 获得ICMP首部的位置 */
	icmph = (icmp_header *)((u_char*)ih + 20);

	/* 将网络字节序列转换成主机字节序列 */

	icmp_checksum = ntohs(icmph->icmp_checksum);
	icmp_id = ntohs(icmph->icmp_id);
	icmp_sequence = ntohs(icmph->icmp_sequence);

	printf("ICMP(Internet控制报文协议)-----------------------------\n\r");
	printf("--类型=%d", icmph->icmp_type);
	if (icmph->icmp_code == 0 && icmph->icmp_type == 8)
		printf(" (回显请求)\n");
	else
		printf(" (回显应答)\n");
	printf("--代码=%d\n\r", icmph->icmp_code);

	printf("--校验和=%04x  \n", icmp_checksum);
	/*if (check_sum(ih, 10) == 1)
		printf("(correct)\n");
	else
		printf("(error)\n");*/

	printf("--标识号=%d\n\r", icmp_id);
	printf("--序列号=%d\n\r", icmp_sequence);

}

//IGMP 协议分析
void igmp_Analyse(const u_char *pkt_data)
{

	ip_header *ih;
	igmp_header *igmph;
	u_int ip_len;
	unsigned long sum;
	int nword;

	u_int16_t igmp_checksum;            //校验和

										/* 获得IP数据包头部的位置 */
	ih = (ip_header *)(pkt_data + 14);

	/* 获得ICMP首部的位置 */
	ip_len = (ih->ip_version & 0xf) * 4;
	igmph = (igmp_header *)((u_char*)ih + ip_len);

	/* 将网络字节序列转换成主机字节序列 */

	igmp_checksum = ntohs(igmph->igmp_checksum);


	printf("IGMP(Internet组管理协议)-----------------------------\n\r");
	printf("--类型=%d", igmph->igmp_type);

	switch (igmph->igmp_type)
	{
	case 17:
		printf(" (成员关系查询报文)\n");
		break;

	case 22:
		printf(" (成员关系报告报文)\n");
		break;

	case 23:
		printf(" (退出报告报文)\n");
		break;
	default:
		printf("\n");
		break;
	}

	printf("--最大响应时间=%d\n\r", igmph->igmp_time);

	printf("--校验和=%04x \n ", igmp_checksum);
	//printf("%s",ih);
	/*nword = 10;
	unsigned short iq = (unsigned short)ih;
	for (sum = 0; nword>0; nword--)
	{
		sum += ih->ip_header_length++;
	}
	sum = (sum >> 16) + (sum & 0xffff);
	sum = sum + (sum >> 16);
	if (sum == 0xFFFF)
	{
		printf("(correct)\n");
	}
	else
		printf("(error)\n");*/

	printf("--组地址=%d.%d.%d.%d\n",
		igmph->addr.byte1,
		igmph->addr.byte2,
		igmph->addr.byte3,
		igmph->addr.byte4);

}

int main()
{
	u_int netmask;
    int fileterr;
	char packet_filter[30];
	char packet_filter_all[] = "";
	int inum;
	int i = 0;
	char a[1000]= "0";  //文件临时空间
	pcap_dumper_t * dumpfile; //存入文件



	//pcap_t* pcap_handle; //winpcap 句柄  
	char error_content[PCAP_ERRBUF_SIZE]; // 存储错误信息  
	bpf_u_int32 net_mask = 0; // 掩码地址  
	bpf_u_int32 net_ip = 0;  // 网络地址  
	char *net_interface;  // 网络接口  
	struct bpf_program bpf_filter;  //BPF 过滤规则  
	char bpf_filter_string[] = "ip"; // 过滤规则字符串，只分析 IPv4 的数据包  

	pcap_if_t * allAdapters;// 适配器列表  
	pcap_if_t * adapter;
	pcap_t           * adapterHandle;// 适配器句柄  

	char errorBuffer[PCAP_ERRBUF_SIZE];// 错误信息缓冲区  
	

	

	/* 获取本机设备列表 */
	if (pcap_findalldevs(&allAdapters, errorBuffer) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", error_content);
		exit(1);
	}

	/* 打印列表 */
	for (adapter = allAdapters; adapter; adapter = adapter->next)
	{
		printf("%d. %s", ++i, adapter->name);
		if (adapter->description)
			printf(" (%s)\n", adapter->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf_s("%d", &inum);  //用户选择网卡编号

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* 释放设备列表 */
		pcap_freealldevs(allAdapters);
		return -1;
	}

	/* 跳转到选中的适配器 */
	for (adapter = allAdapters, i = 0; i< inum - 1; adapter = adapter->next, i++);

	// 打开指定适配器  
	adapterHandle = pcap_open(adapter->name, // name of the adapter  
		65536,         // portion of the packet to capture  
					   // 65536 guarantees that the whole   
					   // packet will be captured  
		PCAP_OPENFLAG_PROMISCUOUS, // promiscuous mode  
		1000,             // read timeout - 1 millisecond  
		NULL,          // authentication on the remote machine  
		errorBuffer    // error buffer  
	);
	if (adapter->addresses != NULL)
		/* 获得接口第一个地址的掩码 */
		netmask = ((struct sockaddr_in *)(adapter->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* 如果接口没有地址，那么我们假设一个C类的掩码 */
		netmask = 0xffffff;
	


//////////////////////////////////////////////////////
	
	printf("\n选择过滤器：0、不过滤   1、过滤\n");
	

	scanf_s("%d", &fileterr);
	switch (fileterr)
	{
	case 1:
		printf("%s", "请输入过滤器条件：\ntcp   udp   arp  icmp  igmp\n\n");
		fflush(stdin);

		scanf_s("%s", &packet_filter,20);

		if (pcap_compile(adapterHandle, &bpf_filter, packet_filter, 1, netmask) <0)
		{
			fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
			/* 释放设备列表 */
			pcap_freealldevs(allAdapters);
			//return -1;
		}
		break;
	default:
		if (pcap_compile(adapterHandle, &bpf_filter, packet_filter_all, 1, netmask) <0)
		{
			fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
			/* 释放设备列表 */
			pcap_freealldevs(allAdapters);
			//	return -1;
		}
	}
	//设置过滤器
	if (pcap_setfilter(adapterHandle, &bpf_filter)<0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* 释放设备列表 */
		pcap_freealldevs(allAdapters);
		return -1;
	}
	//初始化存文件
	dumpfile = pcap_dump_open(adapterHandle, a);
	//打开一个存储文件并将它和接口联系起来  存文件
	if (dumpfile == NULL) {
		fprintf(stderr, "\nError opening output file\n"); return -1;
	}
	dumpfile = pcap_dump_open(adapterHandle, "traffic.txt"); //文件名
	if (dumpfile == NULL) {
		printf("Error on opening output file\n");
		exit(-1);
	}


	printf("\nlistening on %s...\n", adapter->description);
	
	pcap_freealldevs(allAdapters);
//开始捕获报文

	pcap_loop(adapterHandle, 5, ethernet_protocol_packet_callback, (u_char *)dumpfile); // 捕获 65536 个数据包进行分析  
	pcap_dump_close(dumpfile);
	//pcap_close(adapterHandle);
	//ethernet_protocol_packet_callback();
	//dumpfile = pcap_dump_open(adapterHandle, "D:\Class\计算机网络课设\code");
	return 0;
}
//存文件
//void ethernet_protocol_packet_callback(u_char *user, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data)
//{
//	printf("in packet handler\n");
//	pcap_dump(NULL, pkt_header, pkt_data);
//	return;
//}