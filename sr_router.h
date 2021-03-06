/*-----------------------------------------------------------------------------
 * File: sr_router.h
 * Date: ?
 * Authors: Guido Apenzeller, Martin Casado, Virkam V.
 * Contact: casado@stanford.edu
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_ROUTER_H
#define SR_ROUTER_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>

#include "sr_protocol.h"
#include "sr_arpcache.h"

/* we dont like this debug , but what to do for varargs ? */
#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ## args)
#define DebugMAC(x) \
  do { int ivyl; for(ivyl=0; ivyl<5; ivyl++) printf("%02x:", \
  (unsigned char)(x[ivyl])); printf("%02x",(unsigned char)(x[5])); } while (0)
#else
#define Debug(x, args...) do{}while(0)
#define DebugMAC(x) do{}while(0)
#endif

#define INIT_TTL 255
#define PACKET_DUMP_SIZE 1024

/* forward declare */
struct sr_if;
struct sr_rt;

/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */

struct sr_instance
{
    int  sockfd;   /* socket to server */
    char user[32]; /* user name */
    char host[32]; /* host name */ 
    char template[30]; /* template name if any */
    unsigned short topo_id;
    struct sockaddr_in sr_addr; /* address to server */
    struct sr_if* if_list; /* list of interfaces */
    struct sr_rt* routing_table; /* routing table */
    struct sr_arpcache cache;   /* ARP cache */
    pthread_attr_t attr;
    FILE* logfile;
};

enum icmp_codes{
    icmp_echo = 0,
    icmp_net_unreachable = 0,
    icmp_host_unreachable = 1,
    icmp_protocol_unreachable = 2,
    icmp_port_unreachable = 3,
};

enum icmp_types{
    icmp_dest_unreachable = 3,
    icmp_echo_mess = 8,
    icmp_echo_rep = 0,
    icmp_time_exceeded = 11,
};

enum ip_prots{
    ip_tcp_protocol = 6,
    ip_udp_protocol = 17,
};

enum arp_consts{
    max_arp_resend = 5,
};

enum scalars{
    word_to_byte = 4,
};

/* -- sr_main.c -- */
int sr_verify_routing_table(struct sr_instance* sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet(struct sr_instance* , uint8_t* , unsigned int , const char*);
int sr_connect_to_server(struct sr_instance* ,unsigned short , char* );
int sr_read_from_server(struct sr_instance* );

/* -- sr_router.c -- */
void sr_init(struct sr_instance* );
void sr_handlepacket(struct sr_instance* , uint8_t * , unsigned int , char* );
void sr_handle_arp_packet(struct sr_instance* , uint8_t * , unsigned int , char* );
void sr_handle_ip_packet(struct sr_instance* , uint8_t * , unsigned int , char* );
struct sr_rt* sr_get_rt_entry(struct sr_instance*, char*);
struct sr_if* sr_get_interface_ip(struct sr_instance*, uint32_t);
void sr_send_error(struct sr_instance *, uint8_t *, unsigned int, char *, uint8_t, uint8_t);
void sr_create_icmp_packet(uint8_t*, unsigned int , struct sr_if *);
struct sr_rt* sr_get_lpm_entry(struct sr_instance *, uint32_t);
void sr_send_arp_request(struct sr_instance*, uint32_t, char*);
void forward_ip_packet(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface);
void handle_arpreq(struct sr_instance *sr, struct sr_arpreq *arpreq, uint32_t next_hop, char* interface);

/* -- sr_if.c -- */
void sr_add_interface(struct sr_instance* , const char* );
void sr_set_ether_ip(struct sr_instance* , uint32_t );
void sr_set_ether_addr(struct sr_instance* , const unsigned char* );
void sr_print_if_list(struct sr_instance* );

#endif /* SR_ROUTER_H */
