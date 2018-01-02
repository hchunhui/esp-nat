/**
 * NAT - NAT implementation for lwIP supporting TCP/UDP and ICMP.
 * Copyright (c) 2009 Christian Walter, ?Embedded Solutions, Vienna 2009.
 *
 * Copyright (c) 2010 lwIP project ;-)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 */

/*
 * TODOS:
 *  - we should decide if we want to use static tables for NAT or a linked
 *    list.
 *  - we should allocate icmp ping id if multiple clients are sending
 *    ping requests.
 *  - maybe we could hash the identifiers for TCP, ICMP and UDP and use
 *    a single table structure. This would reduce the code amount although
 *    it will cost performance.
 *  - NAT code must check for broadcast addresses and NOT forward
 *    them.
 *
 *  - netif_remove must notify NAT code when a NAT'ed interface is removed
 *  - allocate NAT entries from a new memp pool instead of the heap
 *  - let ttl be ticks, not seconds
 *
 * HOWTO USE:
 *
 * Shows how to create NAT between a PPP interface and an internal NIC.
 * In this case the network 213.129.231.168/29 is nat'ed when packets
 * are sent to the destination network 10.0.0.0/24 (untypical example -
 * most users will have the other way around).
 *
 * Step 1) Execute when network interfaces are ready.
 *
 * new_nat_entry.out_if = (struct netif *)&PPP_IF;
 * new_nat_entry.in_if = (struct netif *)&EMAC_if;
 * IP4_ADDR(&new_nat_entry.source_net, 213, 129, 231, 168);
 * IP4_ADDR(&new_nat_entry.source_netmask, 255, 255, 255, 248);
 * IP4_ADDR(&new_nat_entry.dest_net, 10, 0, 0, 0);
 * IP4_ADDR(&new_nat_entry.source_netmask, 255, 0, 0, 0);
 * ip_nat_add(&new_nat_entry);
 */

#include "lwip/ipv4_nat.h"
#include "lwip/opt.h"

#ifdef IP_NAT

#include "lwip/ip.h"
#include "lwip/inet.h"
#include "lwip/netif.h"
#include "lwip/ip_addr.h"
#include "lwip/icmp.h"
#include "lwip/tcp_impl.h"
#include "lwip/udp.h"
#include "lwip/mem.h"
#include "lwip/sys.h"
#include "lwip/timers.h"
#include "netif/etharp.h"

#include <limits.h>
#include <string.h>

#include "netif/wlan_lwip_if.h"

#define LWIP_NAT_TTL_INFINITE                    (INT_MAX)
#define LWIP_NAT_DEFAULT_TTL_SECONDS             (30)
#define LWIP_NAT_LONG_TTL_SECONDS                (600)

#define LWIP_NAT_DEFAULT_STATE_TABLES_ICMP       (10)
#define LWIP_NAT_DEFAULT_STATE_TABLES_TCP        (100)
#define LWIP_NAT_DEFAULT_STATE_TABLES_UDP        (100)

#define LWIP_NAT_DEFAULT_TCP_SOURCE_PORT         (10000)
#define LWIP_NAT_DEFAULT_UDP_SOURCE_PORT         (10000)

static int counter;

#define IPNAT_ENTRY_RESET(x) do { \
  (x)->ttl = 0; \
} while(0)

typedef struct ip_nat_entry_common
{
  s32_t           ttl;
  ip_addr_t       source;
  ip_addr_t       dest;
} ip_nat_entry_common_t;

typedef struct ip_nat_entries_icmp
{
  ip_nat_entry_common_t common;
  u16_t                 id;
  u16_t                 seqno;
} ip_nat_entries_icmp_t;

typedef struct ip_nat_entries
{
  ip_nat_entry_common_t common;
  u16_t                 state;
  u16_t                 nport;
  u16_t                 sport;
  u16_t                 dport;
} ip_nat_entries_t;

static ip_nat_entries_icmp_t ip_nat_icmp_table[LWIP_NAT_DEFAULT_STATE_TABLES_ICMP];
static ip_nat_entries_t ip_nat_tcp_table[LWIP_NAT_DEFAULT_STATE_TABLES_TCP];
static ip_nat_entries_t ip_nat_udp_table[LWIP_NAT_DEFAULT_STATE_TABLES_UDP];

/* ----------------------- Static functions (COMMON) --------------------*/
static void     ip_nat_chksum_adjust(u8_t *chksum, const u8_t *optr, s16_t olen, const u8_t *nptr, s16_t nlen);
static void     ip_nat_cmn_init(const struct ip_hdr *iphdr, ip_nat_entry_common_t *nat_entry);

/* ----------------------- Static functions (TCP) -----------------------*/
static ip_nat_entries_t *ip_nat_tcp_lookup_incoming(const struct ip_hdr *iphdr, const struct tcp_hdr *tcphdr);
static ip_nat_entries_t *ip_nat_tcp_lookup_outgoing(const struct ip_hdr *iphdr, const struct tcp_hdr *tcphdr);

/* ----------------------- Static functions (UDP) -----------------------*/
static ip_nat_entries_t *ip_nat_udp_lookup_incoming(const struct ip_hdr *iphdr, const struct udp_hdr *udphdr);
static ip_nat_entries_t *ip_nat_udp_lookup_outgoing(const struct ip_hdr *iphdr, const struct udp_hdr *udphdr);

/**
 * Timer callback function that calls ip_nat_tmr() and reschedules itself.
 *
 * @param arg unused argument
 */
static void
nat_timer(void *arg)
{
  LWIP_UNUSED_ARG(arg);
  ip_nat_tmr();
  sys_timeout(LWIP_NAT_TMR_INTERVAL_SEC*1000, nat_timer, NULL);
}

/** Initialize this module */
void
ip_nat_init(void)
{
  int i;
  extern void lwip_ip_input_set_hook(int (*hook)(struct pbuf *p, struct netif *inp));

  for (i = 0; i < LWIP_NAT_DEFAULT_STATE_TABLES_ICMP; i++) {
    IPNAT_ENTRY_RESET(&ip_nat_icmp_table[i].common);
  }
  for (i = 0; i < LWIP_NAT_DEFAULT_STATE_TABLES_TCP; i++) {
    IPNAT_ENTRY_RESET(&ip_nat_tcp_table[i].common);
  }
  for (i = 0; i < LWIP_NAT_DEFAULT_STATE_TABLES_UDP; i++) {
    IPNAT_ENTRY_RESET(&ip_nat_udp_table[i].common);
  }

  sys_timeout(LWIP_NAT_TMR_INTERVAL_SEC*1000, nat_timer, NULL);
}

/** Check if the IP header can be hidden and if the remaining packet
 * is long enough. p->payload is reset to the IP header on return.
 *
 * @param p received packet, p->payload pointing to IP header
 * @param min_size minimum p->tot_len after hiding IP header
 * @return a pointer to the next header (after IP header),
 *         NULL if hiding IP header fails or the packet is too short
 */
static void*
ip_nat_check_header(struct pbuf *p, u16_t min_size)
{
  struct ip_hdr  *iphdr = (struct ip_hdr*)p->payload;
  s16_t iphdr_len = IPH_HL(iphdr) * 4;

  if(p->tot_len >= min_size + iphdr_len)
    return (u8_t *)p->payload + iphdr_len;
  else
    return NULL;
}

static void tcp_refresh_entry(const struct tcp_hdr *tcphdr, ip_nat_entries_t *nat_entry)
{
  nat_entry->common.ttl = LWIP_NAT_DEFAULT_TTL_SECONDS;

  if (TCPH_FLAGS(tcphdr) & (TCP_FIN)) {
    nat_entry->state = 1;
  }

  if (!(TCPH_FLAGS(tcphdr) & (TCP_FIN|TCP_SYN|TCP_RST)) &&
    nat_entry->state == 0)
    nat_entry->common.ttl = LWIP_NAT_LONG_TTL_SECONDS;
}

static void udp_refresh_entry(const struct udp_hdr *udphdr, ip_nat_entries_t *nat_entry)
{
  nat_entry->common.ttl = LWIP_NAT_DEFAULT_TTL_SECONDS;
}

/** Input processing: check if a received packet belongs to a NAT entry
 * and if so, translated it and send it on.
 *
 * @param p received packet
 * @return 1 if the packet has been consumed (it was a NAT packet),
 *         0 if the packet has not been consumed (no NAT packet)
 */
u8_t
ip_nat_input(struct pbuf *p)
{
  struct ip_hdr        *iphdr = (struct ip_hdr*)p->payload;
  struct tcp_hdr       *tcphdr;
  struct udp_hdr       *udphdr;
  struct icmp_echo_hdr *icmphdr;
  err_t                 err;
  u8_t                  consumed = 0;
  int                   i;
  struct netif         *out_if = eagle_lwip_getif(0);
  struct netif         *in_if = eagle_lwip_getif(1);
  ip_addr_t ipdest;
  u32_t source_addr;

  switch (IPH_PROTO(iphdr)) {
    case IP_PROTO_TCP:
      tcphdr = (struct tcp_hdr*)ip_nat_check_header(p, sizeof(struct tcp_hdr));
      if (tcphdr) {
        ip_nat_entries_t *tcp_entry = ip_nat_tcp_lookup_incoming(iphdr, tcphdr);
        if (tcp_entry != NULL) {
          tcp_refresh_entry(tcphdr, tcp_entry);
          tcphdr->dest = tcp_entry->sport;
          /* Adjust TCP checksum for changed destination port */
          ip_nat_chksum_adjust((u8_t *)&(tcphdr->chksum),
            (u8_t *)&(tcp_entry->nport), 2, (u8_t *)&(tcphdr->dest), 2);
          /* Adjust TCP checksum for changing dest IP address */
          ip_nat_chksum_adjust((u8_t *)&(tcphdr->chksum),
            (u8_t *)&(out_if->ip_addr.addr), 4,
            (u8_t *)&(tcp_entry->common.source.addr), 4);

          consumed = 1;
          source_addr = tcp_entry->common.source.addr;
        }
      }
      break;

    case IP_PROTO_UDP:
      udphdr = (struct udp_hdr *)ip_nat_check_header(p, sizeof(struct udp_hdr));
      if (udphdr) {
        ip_nat_entries_t *udp_entry = ip_nat_udp_lookup_incoming(iphdr, udphdr);
        if (udp_entry != NULL) {
          udp_refresh_entry(udphdr, udp_entry);
          udphdr->dest = udp_entry->sport;
          /* Adjust UDP checksum for changed destination port */
          ip_nat_chksum_adjust((u8_t *)&(udphdr->chksum),
            (u8_t *)&(udp_entry->nport), 2, (u8_t *)&(udphdr->dest), 2);
          /* Adjust UDP checksum for changing dest IP address */
          ip_nat_chksum_adjust((u8_t *)&(udphdr->chksum),
            (u8_t *)&(out_if->ip_addr.addr), 4,
            (u8_t *)&(udp_entry->common.source.addr), 4);

          consumed = 1;
          source_addr = udp_entry->common.source.addr;
        }
      }
      break;

    case IP_PROTO_ICMP:
      icmphdr = (struct icmp_echo_hdr *)ip_nat_check_header(p, sizeof(struct icmp_echo_hdr));
      if (icmphdr) {
        if (ICMP_ER == ICMPH_TYPE(icmphdr)) {
          for (i = 0; i < LWIP_NAT_DEFAULT_STATE_TABLES_ICMP; i++) {
            ip_nat_entries_icmp_t *icmp_entry = &ip_nat_icmp_table[i];
            if ((icmp_entry->common.ttl) &&
                (iphdr->src.addr == icmp_entry->common.dest.addr) &&
                (icmp_entry->id == icmphdr->id) &&
                (icmp_entry->seqno == icmphdr->seqno)) {
              consumed = 1;
              source_addr = icmp_entry->common.source.addr;
              IPNAT_ENTRY_RESET(&(icmp_entry->common));
              break;
            }
          }
        }
      }
      break;

    default:
      break;
  }

  if(consumed) {
    /* packet consumed, send it out on in_if */
    iphdr->dest.addr = source_addr;
    ip_nat_chksum_adjust((u8_t *) & IPH_CHKSUM(iphdr),
      (u8_t *) & (out_if->ip_addr.addr), 4,
      (u8_t *) & (iphdr->dest.addr), 4);

    ip_addr_copy(ipdest, iphdr->dest);
    err = in_if->output(in_if, p, &ipdest);

    if(err != ERR_OK) {
      os_printf("ip_nat_input: failed to send rewritten packet: %d\n", err);
    }

    pbuf_free(p);
  }

  return consumed;
}

/** Check if one NAT entry timed out */
static int
ip_nat_check_timeout(ip_nat_entry_common_t *nat_entry)
{
  if(nat_entry->ttl > 0) {
    if(nat_entry->ttl != LWIP_NAT_TTL_INFINITE) {
      /* this is not a 'no-timeout' entry */
      if(nat_entry->ttl > LWIP_NAT_TMR_INTERVAL_SEC) {
        nat_entry->ttl -= LWIP_NAT_TMR_INTERVAL_SEC;
      } else {
        nat_entry->ttl = 0;
        return 1;
      }
    }
  }
  return 0;
}

/** The NAT timer function, to be called at an interval of
 * LWIP_NAT_TMR_INTERVAL_SEC seconds.
 */
void
ip_nat_tmr(void)
{
  int i;

  int c = 0;

  for(i = 0; i < LWIP_NAT_DEFAULT_STATE_TABLES_ICMP; i++) {
    c += ip_nat_check_timeout((ip_nat_entry_common_t *) & ip_nat_icmp_table[i]);
  }
  os_printf("free %d ICMP\n", c);

  c = 0;
  for(i = 0; i < LWIP_NAT_DEFAULT_STATE_TABLES_TCP; i++) {
    c += ip_nat_check_timeout((ip_nat_entry_common_t *) & ip_nat_tcp_table[i]);
  }
  os_printf("free %d TCP\n", c);

  c = 0;
  for(i = 0; i < LWIP_NAT_DEFAULT_STATE_TABLES_UDP; i++) {
    c += ip_nat_check_timeout((ip_nat_entry_common_t *) & ip_nat_udp_table[i]);
  }
  os_printf("free %d UDP\n", c);
}

/** Check if we want to perform NAT with this packet. If so, send it out on
 * the correct interface.
 *
 * @param p the packet to test/send
 * @return 1: the packet has been sent using NAT,
 *         0: the packet did not belong to a NAT entry
 */
u8_t
ip_nat_out(struct pbuf *p)
{
  u8_t                  sent = 0;
  err_t                 err;
  struct ip_hdr        *iphdr = p->payload;
  struct icmp_echo_hdr *icmphdr;
  struct tcp_hdr       *tcphdr;
  struct udp_hdr       *udphdr;
  int             i;
  struct netif         *out_if = eagle_lwip_getif(0);
  struct netif         *in_if = eagle_lwip_getif(1);
  ip_addr_t ipdest;
  u8_t found = 0;
  u32_t source_addr;

  ip_addr_copy(ipdest, iphdr->dest);

  /* Check if this packet should be routed or should be translated */
  if (ip_route(&ipdest) == out_if) {
      switch (IPH_PROTO(iphdr))
      {
      case IP_PROTO_TCP:
        tcphdr = (struct tcp_hdr *)ip_nat_check_header(p, sizeof(struct tcp_hdr));
        if (tcphdr) {
          ip_nat_entries_t *tcp_entry = ip_nat_tcp_lookup_outgoing(iphdr, tcphdr);
          if (tcp_entry != NULL) {
            tcp_refresh_entry(tcphdr, tcp_entry);
            /* Adjust TCP checksum for changing source port */
            tcphdr->src = tcp_entry->nport;
            ip_nat_chksum_adjust((u8_t *)&(tcphdr->chksum),
              (u8_t *)&(tcp_entry->sport), 2, (u8_t *)&(tcphdr->src), 2);
            /* Adjust TCP checksum for changing source IP address */
            ip_nat_chksum_adjust((u8_t *)&(tcphdr->chksum),
              (u8_t *)&(tcp_entry->common.source.addr), 4,
              (u8_t *)&(out_if->ip_addr.addr), 4);
            source_addr = tcp_entry->common.source.addr;
            found = 1;
          }
        }
        break;

      case IP_PROTO_UDP:
        udphdr = (struct udp_hdr *)ip_nat_check_header(p, sizeof(struct udp_hdr));
        if (udphdr) {
          ip_nat_entries_t *udp_entry = ip_nat_udp_lookup_outgoing(iphdr, udphdr);
          if (udp_entry != NULL) {
            udp_refresh_entry(udphdr, udp_entry);
            /* Adjust UDP checksum for changing source port */
            udphdr->src = udp_entry->nport;
            ip_nat_chksum_adjust((u8_t *)&(udphdr->chksum),
              (u8_t *)&(udp_entry->sport), 2, (u8_t *) & (udphdr->src), 2);
            /* Adjust UDP checksum for changing source IP address */
            ip_nat_chksum_adjust((u8_t *)&(udphdr->chksum),
              (u8_t *)&(udp_entry->common.source.addr), 4,
              (u8_t *)&(out_if->ip_addr.addr), 4);
            source_addr = udp_entry->common.source.addr;
            found = 1;
          }
        }
        break;

      case IP_PROTO_ICMP:
        icmphdr = (struct icmp_echo_hdr *)ip_nat_check_header(p, sizeof(struct icmp_echo_hdr));
        if(icmphdr) {
          ip_nat_entries_icmp_t *icmp_entry = NULL;
          if (ICMPH_TYPE(icmphdr) == ICMP_ECHO) {
            for (i = 0; i < LWIP_NAT_DEFAULT_STATE_TABLES_ICMP; i++) {
              if (!ip_nat_icmp_table[i].common.ttl) {
                icmp_entry = &ip_nat_icmp_table[i];
                ip_nat_cmn_init(iphdr, &(icmp_entry->common));
                icmp_entry->id = icmphdr->id;
                icmp_entry->seqno = icmphdr->seqno;
                source_addr = icmp_entry->common.source.addr;
                found = 1;
                break;
              }
            }
            if (NULL == icmp_entry)
              os_printf("icmp table full\n");
          }
        }
        break;
      default:
        break;
      }

      if (found) {
        /* Exchange the IP source address with the address of the interface
        * where the packet will be sent.
        */
        /* @todo: check nat_config->entry.out_if agains nat_entry.cmn->cfg->entry.out_if */
        iphdr->src.addr = out_if->ip_addr.addr;
        ip_nat_chksum_adjust((u8_t *) & IPH_CHKSUM(iphdr),
          (u8_t *) &source_addr, 4, (u8_t *) & iphdr->src.addr, 4);

        err = out_if->output(out_if, p, &ipdest);
        if (err != ERR_OK) {
            os_printf("ip_nat_out: failed to send rewritten packet: %d\n", err);
        } else {
          sent = 1;
        }
      }
  }

  return sent;
}

/** Initialize common parts of a NAT entry
 *
 * @param iphdr IP header from which to initialize the entry
 * @param nat_entry entry to initialize
 */
static void
ip_nat_cmn_init(const struct ip_hdr *iphdr, ip_nat_entry_common_t *nat_entry)
{
  LWIP_ASSERT("NULL != nat_entry", NULL != nat_entry);
  LWIP_ASSERT("NULL != iphdr", NULL != iphdr);
  ip_addr_copy(nat_entry->dest, iphdr->dest);
  ip_addr_copy(nat_entry->source, iphdr->src);
  nat_entry->ttl = LWIP_NAT_DEFAULT_TTL_SECONDS;
}

/**
 * This function checks for incoming packets if we already have a NAT entry.
 * If yes a pointer to the NAT entry is returned. Otherwise NULL.
 *
 * @param iphdr The IP header.
 * @param udphdr The UDP header.
 * @return A pointer to an existing NAT entry or
 *         NULL if none is found.
 */
static ip_nat_entries_t *
ip_nat_udp_lookup_incoming(const struct ip_hdr *iphdr, const struct udp_hdr *udphdr)
{
  int i;
  ip_nat_entries_t *nat_entry = NULL;

  if (ntohs(udphdr->dest) < LWIP_NAT_DEFAULT_UDP_SOURCE_PORT)
    return NULL;

  for (i = 0; i < LWIP_NAT_DEFAULT_STATE_TABLES_UDP; i++) {
    if (ip_nat_udp_table[i].common.ttl) {
      if ((iphdr->src.addr == ip_nat_udp_table[i].common.dest.addr) &&
          (udphdr->src == ip_nat_udp_table[i].dport) &&
          (udphdr->dest == ip_nat_udp_table[i].nport)) {
        nat_entry = &ip_nat_udp_table[i];
        break;
      }
    }
  }
  return nat_entry;
}

/**
 * This function checks if we already have a NAT entry for this UDP connection.
 * If yes the a pointer to this NAT entry is returned.
 *
 * @param iphdr The IP header.
 * @param udphdr The UDP header.
 */
static ip_nat_entries_t *
ip_nat_udp_lookup_outgoing(const struct ip_hdr *iphdr, const struct udp_hdr *udphdr)
{
  int i;
  ip_nat_entries_t *nat_entry = NULL;
  int first_free = -1;

  for (i = 0; i < LWIP_NAT_DEFAULT_STATE_TABLES_UDP; i++) {
    if (ip_nat_udp_table[i].common.ttl) {
      if ((iphdr->src.addr == ip_nat_udp_table[i].common.source.addr) &&
          (iphdr->dest.addr == ip_nat_udp_table[i].common.dest.addr) &&
          (udphdr->src == ip_nat_udp_table[i].sport) &&
          (udphdr->dest == ip_nat_udp_table[i].dport)) {
        nat_entry = &ip_nat_udp_table[i];
        break;
      }
    } else if (first_free == -1) {
        first_free = i;
    }
  }
  if (nat_entry == NULL) {
      if (first_free != -1) {
        nat_entry = &ip_nat_udp_table[first_free];
        nat_entry->nport = htons((u16_t) (LWIP_NAT_DEFAULT_UDP_SOURCE_PORT + (counter++)%1024));
        nat_entry->sport = udphdr->src;
        nat_entry->dport = udphdr->dest;
        ip_nat_cmn_init(iphdr, &(nat_entry->common));
      } else {
        os_printf("udp_table full\n");
      }
  }
  return nat_entry;
}

/**
 * This function checks for incoming packets if we already have a NAT entry.
 * If yes a pointer to the NAT entry is returned. Otherwise NULL.
 *
 * @param iphdr The IP header.
 * @param tcphdr The TCP header.
 * @return A pointer to an existing NAT entry or NULL if none is found.
 */
static ip_nat_entries_t *
ip_nat_tcp_lookup_incoming(const struct ip_hdr *iphdr, const struct tcp_hdr *tcphdr)
{
  int i;
  ip_nat_entries_t *nat_entry = NULL;

  if (ntohs(tcphdr->dest) < LWIP_NAT_DEFAULT_TCP_SOURCE_PORT)
    return NULL;

  for (i = 0; i < LWIP_NAT_DEFAULT_STATE_TABLES_TCP; i++) {
    if (ip_nat_tcp_table[i].common.ttl) {
      if ((iphdr->src.addr == ip_nat_tcp_table[i].common.dest.addr) &&
          (tcphdr->src == ip_nat_tcp_table[i].dport) &&
          (tcphdr->dest == ip_nat_tcp_table[i].nport)) {
        nat_entry = &ip_nat_tcp_table[i];
        break;
      }
    }
  }
  return nat_entry;
}

/**
 * This function checks if we already have a NAT entry for this TCP connection.
 * If yes the a pointer to this NAT entry is returned.
 *
 * @param iphdr The IP header.
 * @param tcphdr The TCP header.
 */
static ip_nat_entries_t *
ip_nat_tcp_lookup_outgoing(const struct ip_hdr *iphdr, const struct tcp_hdr *tcphdr)
{
  int i;
  ip_nat_entries_t *nat_entry = NULL;
  int first_free = -1;

  for (i = 0; i < LWIP_NAT_DEFAULT_STATE_TABLES_TCP; i++) {
    if (ip_nat_tcp_table[i].common.ttl) {
      if ((iphdr->src.addr == ip_nat_tcp_table[i].common.source.addr) &&
          (iphdr->dest.addr == ip_nat_tcp_table[i].common.dest.addr) &&
          (tcphdr->src == ip_nat_tcp_table[i].sport) &&
          (tcphdr->dest == ip_nat_tcp_table[i].dport)) {
        nat_entry = &ip_nat_tcp_table[i];
        break;
      }
    } else if (first_free == -1) {
        first_free = i;
    }
  }
  if (nat_entry == NULL) {
    if (TCPH_FLAGS(tcphdr) & TCP_SYN) {
      if (first_free != -1) {
        nat_entry = &ip_nat_tcp_table[first_free];
        nat_entry->state = 0;
        nat_entry->nport = htons((u16_t) (LWIP_NAT_DEFAULT_TCP_SOURCE_PORT + (counter++)%1024));
        nat_entry->sport = tcphdr->src;
        nat_entry->dport = tcphdr->dest;
        ip_nat_cmn_init(iphdr, &(nat_entry->common));
      } else {
        os_printf("tcp table full\n");
      }
    }
  }
  return nat_entry;
}

/** Adjusts the checksum of a NAT'ed packet without having to completely recalculate it
 * @todo: verify this works for little- and big-endian
 *
 * @param chksum points to the chksum in the packet
 * @param optr points to the old data in the packet
 * @param olen length of old data
 * @param nptr points to the new data in the packet
 * @param nlen length of new data
 */
static void
ip_nat_chksum_adjust(u8_t *chksum, const u8_t *optr, s16_t olen, const u8_t *nptr, s16_t nlen)
{
  s32_t x, oldval, newval;

  x = chksum[0] * 256 + chksum[1];
  x = ~x & 0xFFFF;
  while (olen) {
    oldval = optr[0] * 256 + optr[1];
    optr += 2;
    x -= oldval & 0xffff;
    if (x <= 0) {
      x--;
      x &= 0xffff;
    }
    olen -= 2;
  }
  while (nlen) {
    newval = nptr[0] * 256 + nptr[1];
    nptr += 2;
    x += newval & 0xffff;
    if (x & 0x10000) {
      x++;
      x &= 0xffff;
    }
    nlen -= 2;
  }
  x = ~x & 0xFFFF;
  chksum[0] = x / 256;
  chksum[1] = x & 0xff;
}

#endif /* IP_NAT */
