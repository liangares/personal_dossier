// stdafx.h : 标准系统包含文件的包含文件，
// 或是经常使用但不常更改的
// 特定于项目的包含文件
//
#pragma once


#include <stdio.h>
#include <tchar.h>

typedef struct arp_header
{
	unsigned short arp_hardware_type;				 /* Format of hardware address.  */
	unsigned short arp_protocol_type;				 /* Format of protocol address.  */
	unsigned char arp_hardware_length;			     /* Length of hardware address.  */
	unsigned char arp_protocol_length;			     /* Length of protocol address.  */
	unsigned short  arp_operation_code;			     /* ARP opcode (command).  */ //1为请求2为回复
	unsigned char  arp_source_ethernet_address[6];     /* Sender hardware address.  */
	unsigned char  arp_source_ip_address[4];			 /* Sender IP address.  */
	unsigned char  arp_destination_ethernet_address[6];/* Target hardware address.  */
	unsigned char  arp_destination_ip_address[4];		 /* Target IP address.  */
}arp_header;


#define _WINSOCK_DEPRECATED_NO_WARNINGS



// TODO: 在此处引用程序需要的其他头文件


