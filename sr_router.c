/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/
void sr_init(struct sr_instance* sr){
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */


} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);
  /* drop packet if less than ethernet header length */
  if(len < sizeof(sr_ethernet_hdr_t)){return;}

  uint8_t packet_cpy[len];
  memcpy(packet_cpy, packet, len);

  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t*)(packet);
  if(ntohs(eth_hdr->ether_type) == ethertype_arp){
      sr_handle_arp_packet(sr, packet_cpy, len, interface);
  }
  else if (ntohs(eth_hdr->ether_type) == ethertype_ip){
      sr_handle_ip_packet(sr, packet_cpy, len, interface);
  }
}

/*---------------------------------------------------------------------
 * Method: sr_handle_arp_packet(uint8_t* packet,char* interface)
 * Scope:  Private
 *
 * This method is called by sr_handlepacket when it's given packet is
 * an ARP packet. The packet is a copy of the packet given to
 * sr_handlepacket, and it still holds the ethernet header.
 *
 * This method updates our cache table if this packet gives us a new
 * IP->MAC mapping, forwards packets in queue if they were waiting,
 * and responds with an ARP reply if this packet is a request.
 *---------------------------------------------------------------------*/
void sr_handle_arp_packet(struct sr_instance* sr,
            uint8_t* packet,
            unsigned int len,
            char* interface){

    struct sr_if *iface = sr_get_interface(sr, interface);
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t*)(packet);
    if(len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)){return;}
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

    if(ntohs(arp_hdr->ar_hrd) != arp_hrd_ethernet){return;}
    int merge_flag = 0;

    struct sr_arpentry *arpentry = sr_arpcache_lookup(&(sr->cache), arp_hdr->ar_sip);
    if(arpentry){
        merge_flag = 1;
        free(arpentry);
    }

    /* Only takes action if the destination address matches our address*/
    if(arp_hdr->ar_tip == iface->ip){

        /* If the senders MAC address is not in our cache table, we add a cache entry and forward all the
         * packets which were waiting on the senders MAC address (if there were any waiting) */
        if(!merge_flag){
            struct sr_arpreq *arpreq = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);
            if(arpreq != NULL) {
                struct sr_packet *packet;
                for (packet = arpreq->packets; packet != NULL; packet = packet->next) {
                    sr_ethernet_hdr_t *eth_hdr2 = ((sr_ethernet_hdr_t *) (packet->buf));
                    memcpy(eth_hdr2->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
                    sr_send_packet(sr, packet->buf, packet->len, packet->iface);
                }
                sr_arpreq_destroy(&(sr->cache), arpreq);
            }
        }

        /* If this is an ARP request, we reply with our interface's hardware address*/
        if(ntohs(arp_hdr->ar_op) == arp_op_request){
            arp_hdr->ar_op = htons(arp_op_reply);
            memcpy(arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
            arp_hdr->ar_tip = arp_hdr->ar_sip;
            memcpy(arp_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN);
            arp_hdr->ar_sip = iface->ip;
            memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
            memcpy(eth_hdr->ether_shost, iface->addr, sizeof (uint8_t) * ETHER_ADDR_LEN);
            sr_send_packet(sr, packet, len, interface);
        }
    }
}

/*---------------------------------------------------------------------
 * Method: sr_handle_ip_packet(struct sr_instance* sr, uint8_t* packet,
                                unsigned int len, char* interface)
 * Scope:  Private
 *
 * This method is called by sr_handlepacket when it's given packet is
 * an IP packet. The packet is a copy of the packet given to
 * sr_handlepacket, and it still holds the ethernet header.
 *
 * This method drops/responds with ICMP error if the IP packet contains
 * an error. Replies to echo requests, and forwards the packet if it
 * is not destined to the router.
 *---------------------------------------------------------------------*/
void sr_handle_ip_packet(struct sr_instance* sr, uint8_t* packet,
                          unsigned int len, char* interface){

    struct sr_if *iface = sr_get_interface(sr, interface);
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t*)(packet);
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

    /* Drop packet if there are errors, respond with time exceeded if the TTL <= 0*/
    if(len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)){return;}
    if(ntohs(ip_hdr->ip_len) < sizeof(sr_ip_hdr_t)){return;}
    uint16_t checksum = ip_hdr->ip_sum;
    ip_hdr->ip_sum = 0;
    if(checksum != cksum(ip_hdr, ip_hdr->ip_hl * word_to_byte)){return;}
    if(ip_hdr->ip_ttl <= 0){
        sr_send_error(sr, packet, len, interface, icmp_echo, icmp_time_exceeded);
        return;
    }

    struct sr_if *ip_iface = sr_get_interface_ip(sr, ip_hdr->ip_dst);

    if(ip_iface){

        /* Respond with port unreachable if TCP or UDP is sent to router*/
        if((ip_hdr->ip_p == ip_tcp_protocol) || (ip_hdr->ip_p == ip_udp_protocol)){
            sr_send_error(sr, packet, len, interface, icmp_port_unreachable, icmp_dest_unreachable);
            return;
        }

        /* Respond with echo reply if echo request was sent to router*/
        if(ip_hdr->ip_p != ip_protocol_icmp){return;}

        sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t*)((uint8_t*)(ip_hdr) + (ip_hdr->ip_hl * word_to_byte));
        if(icmp_hdr->icmp_type != icmp_echo_mess || icmp_hdr->icmp_code != icmp_echo){return;}

        icmp_hdr->icmp_type = icmp_echo_rep;
        ip_hdr->ip_dst = ip_hdr->ip_src;
        ip_hdr->ip_src = ip_iface->ip;
        ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * word_to_byte);
        icmp_hdr->icmp_sum = 0;
        icmp_hdr->icmp_sum = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * word_to_byte));
        memcpy(eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
        struct sr_arpentry *arpentry = sr_arpcache_lookup(&(sr->cache), ip_hdr->ip_dst);
        if(arpentry != NULL){
            memcpy(eth_hdr->ether_dhost, arpentry->mac, ETHER_ADDR_LEN);
            sr_send_packet(sr, packet, len, iface->name);
            free(arpentry);
            return;
        }

        uint8_t *packet_cpy = malloc(len);
        memcpy(packet_cpy, packet, len);
        struct sr_arpreq *arpreq = sr_arpcache_queuereq(&(sr->cache), ip_hdr->ip_dst, packet_cpy, len, interface);
        handle_arpreq(sr, arpreq, ip_hdr->ip_dst, interface);
        return;
    }

    /* Forward this packet if the router isn't the final destination*/
    forward_ip_packet(sr, packet, len, interface);
}

/*---------------------------------------------------------------------
 * Method: forward_ip_packet(struct sr_instance* sr, uint8_t* packet,
                            unsigned int len, char* interface)
 * Scope:  Private
 *
 * This method is called by sr_handle_ip_packet when it's given packet is
 * not destined to the router.
 *
 * This method drops/responds with ICMP error if the IP packet contains
 * an error. Replies to echo requests, and forwards the packet if it
 * is not destined to the router.
 *---------------------------------------------------------------------*/
void forward_ip_packet(struct sr_instance* sr, uint8_t* packet,
                       unsigned int len, char* interface){

    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t*)(packet);
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

    /* Drop packet and send ICMP error if TTL <= 1 or routing table can't make a routing decision*/
    if(ip_hdr->ip_ttl <= 1){
        sr_send_error(sr, packet, len, interface, icmp_echo, icmp_time_exceeded);
        return;
    }

    ip_hdr->ip_ttl -= 1;
    ip_hdr->ip_sum = cksum(ip_hdr, (ip_hdr->ip_hl * word_to_byte));

    struct sr_rt *routing_entry = sr_get_lpm_entry(sr, ip_hdr->ip_dst);
    if(routing_entry == NULL){
        sr_send_error(sr, packet, len, interface, icmp_net_unreachable, icmp_dest_unreachable);
        return;
    }

    /* Determine the next hop*/
    struct sr_if *entry_if = sr_get_interface(sr, routing_entry->interface);
    memcpy(eth_hdr->ether_shost, entry_if->addr, ETHER_ADDR_LEN);

    uint32_t gw = (uint32_t)(routing_entry->gw.s_addr);
    uint32_t next_hop;
    if(gw == 0){
        next_hop = ip_hdr->ip_dst;
    } else{
        next_hop = gw;
    }

    /* Forward the packet if we have the MAC address for the next-hop IP*/
    struct sr_arpentry *arpentry = sr_arpcache_lookup(&(sr->cache), next_hop);
    if(arpentry != NULL){
        memcpy(eth_hdr->ether_dhost, arpentry->mac, ETHER_ADDR_LEN);
        sr_send_packet(sr, packet, len, routing_entry->interface);
        free(arpentry);
        return;
    }

    /* Queue the packet for sending if we do not have it's next-hop IP, and handle the ARP request needed to obtain
     * this address.*/
    uint8_t *packet_cpy = malloc(len);
    memcpy(packet_cpy, packet, len);
    struct sr_arpreq *arpreq = sr_arpcache_queuereq(&(sr->cache), next_hop, packet_cpy, len, interface);
    handle_arpreq(sr, arpreq, next_hop, routing_entry->interface);
}

/*---------------------------------------------------------------------
 * Method: sr_handle_ip_packet(uint8_t* packet,char* interface)
 * Scope:  Private
 *
 * Return the routing table entry which corresponds to the
 * longest prefix match of the address ip.
 *---------------------------------------------------------------------*/
struct sr_rt* sr_get_lpm_entry(struct sr_instance *sr, uint32_t ip){

    unsigned int match_length = 0;
    struct sr_rt *entry;
    struct sr_rt *matching_entry = NULL;
    ip = ntohl(ip);
    for(entry = sr->routing_table; entry != NULL; entry = entry->next){
        uint32_t entry_dest = ntohl((uint32_t)(entry->dest.s_addr));
        uint32_t entry_mask = ntohl((uint32_t)(entry->mask.s_addr));

        uint32_t ip_masked = ip & entry_mask;
        uint32_t dest_masked = entry_dest & entry_mask;

        if((ip_masked == dest_masked) && (entry_mask >= match_length)){
            match_length = entry_mask;
            matching_entry = entry;
        }
    }
    return matching_entry;
}

/*---------------------------------------------------------------------
 * Method: sr_send_arp_request(struct sr_instance *sr, uint32_t ip, char *interface)
 * Scope:  Private
 *
 * Send an arp request to the ip "ip" out of the specified router interface.
 *---------------------------------------------------------------------*/
void sr_send_arp_request(struct sr_instance *sr, uint32_t ip, char *interface){

    struct sr_if *iface = sr_get_interface(sr, interface);
    unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t packet[len];
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t*)(packet);
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

    uint8_t max_eth[ETHER_ADDR_LEN] = {255,255,255,255,255,255};
    uint8_t min_eth[ETHER_ADDR_LEN] = {0,0,0,0,0,0};

    arp_hdr->ar_hrd = htons(1);
    arp_hdr->ar_pro = htons(2048);
    arp_hdr->ar_hln = ETHER_ADDR_LEN;
    arp_hdr->ar_pln = sizeof(uint32_t);
    arp_hdr->ar_op = htons(arp_op_request);
    arp_hdr->ar_tip = ip;
    arp_hdr->ar_sip = iface->ip;
    memcpy(arp_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN);
    memcpy(arp_hdr->ar_tha, min_eth, ETHER_ADDR_LEN);

    eth_hdr->ether_type = htons(ethertype_arp);
    memcpy(eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_dhost, max_eth, ETHER_ADDR_LEN);
    sr_send_packet(sr, packet, len, interface);
}

/*---------------------------------------------------------------------
 * Method: handle_arpreq(struct sr_instance *sr, struct sr_arpreq *arpreq,
 *                          uint32_t next_hop, char* interface)
 * Scope:  Global
 *
 * Handle the packets which are queued to send when we receive an ARP
 * packet from the next_hop ip from the specified interface.
 *---------------------------------------------------------------------*/
void handle_arpreq(struct sr_instance *sr, struct sr_arpreq *arpreq, uint32_t next_hop, char* interface){

    /* If we haven't sent a request in the last second and we haven't sent the maximum amount of requests, send another*/
    if(((time(NULL) - arpreq->sent) >= 1) && (arpreq->times_sent < max_arp_resend)){
        sr_send_arp_request(sr, next_hop, interface);
        arpreq->times_sent += 1;
        arpreq->sent = time(NULL);
    }
    /* If we've sent the maximum amount of requests and haven't received a response, send all the queued packets
     * a host unreachable error and destroy the request queue*/
    else if(arpreq->times_sent >= max_arp_resend){
        struct sr_packet *packet;
        for(packet = arpreq->packets; packet != NULL; packet = packet->next){
            sr_send_error(sr, packet->buf, packet->len, packet->iface, icmp_host_unreachable, icmp_dest_unreachable);
        }
        sr_arpreq_destroy(&(sr->cache), arpreq);
    }
}

/*---------------------------------------------------------------------
 * Method: void sr_send_error(struct sr_instance *sr, uint8_t* packet, unsigned int len,
                   char* interface, uint8_t code, uint8_t type)
 * Scope:  Private
 *
 * This method sends an ICMP destination unreachable packet or time
 * exceeded packet based on the receiving packet variable packet.
 *---------------------------------------------------------------------*/
void sr_send_error(struct sr_instance *sr, uint8_t* packet, unsigned int len,
                   char* interface, uint8_t code, uint8_t type){

    struct sr_if* iface = sr_get_interface(sr, interface);
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t*)(packet);
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    unsigned int packet_send_len = 42 + (ip_hdr->ip_hl * word_to_byte) + 8;
    uint8_t packet_to_send[packet_send_len];

    memcpy(packet_to_send, packet, sizeof(sr_ethernet_hdr_t));
    sr_ethernet_hdr_t *eth_hdr_send = (sr_ethernet_hdr_t*)(packet_to_send);
    memcpy(eth_hdr_send->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(eth_hdr_send->ether_shost, iface->addr, ETHER_ADDR_LEN);

    sr_ip_hdr_t *ip_hdr_send = (sr_ip_hdr_t*)(packet_to_send + sizeof(sr_ethernet_hdr_t));
    ip_hdr_send->ip_v = 4;
    ip_hdr_send->ip_hl = 5;
    ip_hdr_send->ip_tos = 0;
    ip_hdr_send->ip_len = htons(packet_send_len - sizeof(sr_ethernet_hdr_t));
    ip_hdr_send->ip_id = htons(0);
    ip_hdr_send->ip_off = htons(0);
    ip_hdr_send->ip_ttl = 64;
    ip_hdr_send->ip_p = 1;
    ip_hdr_send->ip_sum = 0;
    ip_hdr_send->ip_dst = ip_hdr->ip_src;
    /* Port unreachable implies destination was a router interface, and that router interface has to respond */
    if(code == icmp_port_unreachable){
        ip_hdr_send->ip_src = ip_hdr->ip_dst;
    }
    else{
        ip_hdr_send->ip_src = iface->ip;
    }
    ip_hdr_send->ip_sum = cksum(ip_hdr_send, (ip_hdr_send->ip_hl * word_to_byte));
    sr_icmp_hdr_t *icmp_hdr_send = (sr_icmp_hdr_t*)(packet_to_send + (ip_hdr_send->ip_hl * word_to_byte) + sizeof(sr_ethernet_hdr_t));
    icmp_hdr_send->icmp_type = type;
    icmp_hdr_send->icmp_code = code;

    memcpy(((uint8_t*)(icmp_hdr_send)) + 8, ip_hdr, (ip_hdr->ip_hl * word_to_byte) + 8);
    icmp_hdr_send->icmp_sum = 0;
    icmp_hdr_send->icmp_sum = cksum(icmp_hdr_send, ntohs((ip_hdr_send->ip_len)) - (ip_hdr_send->ip_hl * word_to_byte));

    sr_send_packet(sr, packet_to_send, packet_send_len, interface);
}

/*---------------------------------------------------------------------
 * Method: sr_get_interface_ip(struct sr_instance *sr, uint32_t ip)
 * Scope:  Private
 *
 * Return a router's interface if its ip matches ip. Return 0
 * if the router has no such interface.
 *---------------------------------------------------------------------*/
struct sr_if* sr_get_interface_ip(struct sr_instance *sr, uint32_t ip){
    struct sr_if* if_walker = 0;

    /* -- REQUIRES -- */
    assert(sr);

    if_walker = sr->if_list;

    while(if_walker)
    {
        if(if_walker->ip == ip)
        { return if_walker; }
        if_walker = if_walker->next;
    }

    return 0;
}