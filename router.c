#include "queue.h"
#include "skel.h"

int main(int argc, char *argv[])
{

	setvbuf(stdout, NULL, _IONBF, 0);
	packet m;
	int rc;

	// Do not modify this line
	init(argc - 2, argv + 2);

	// Allocation of the routing table with maximum 100000 entries
	struct route_table_entry *rtable = malloc(sizeof(struct route_table_entry) * 100000);
	DIE(rtable == NULL, "memory");

	// Allocation of the arp table with maximum 100000 entries
	struct arp_entry *arp_table = malloc(sizeof(struct arp_entry) * 100000);
	DIE(arp_table == NULL, "memory");


	// Parsing of the routing table and extracting the length
	uint32_t rtable_len = read_rtable(argv[1], rtable);

	// Length of the arp table is initially 0
	uint32_t arp_table_len = 0;

	// Queue used to store packets
	queue queue = queue_create();

	qsort(rtable, rtable_len, sizeof(struct route_table_entry), compare);

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_packet");
		/* TODO */

		// Extracts the ethernet header from packet
		struct ether_header *eth = (struct ether_header *) m.payload;
		struct iphdr *iph;

		uint32_t dest_ip;

		// IPv4 protocol case
		if (ntohs(eth->ether_type) == 0x0800) {

			// Extracts the ip header from packet
			iph = (struct iphdr *)(m.payload + sizeof(struct ether_header));

			// Destionation ip address of the packet
			dest_ip = iph->daddr;

			// The router ip is the destination ip
			if (dest_ip == inet_addr(get_interface_ip(m.interface))) {
				
				// The packet respects the ICMP protocol
				if (iph->protocol == 1) {
					// Send a ICMP reply
					send_icmp(iph->saddr, iph->daddr, eth->ether_dhost, eth->ether_shost, 0, 0, m.interface);
				} else {
					continue;
				}
			} else {
				
				// Verify if the checksum is correct
				if (ip_checksum((uint8_t *) iph, sizeof(struct iphdr)) != 0) {
					continue;
				}

				// Verify the time to leave field
				if (iph->ttl <= 1) {
					send_icmp_error(iph->saddr, iph->daddr, eth->ether_dhost, eth->ether_shost, 11, 0, m.interface);
					continue;
				}

				// Search the routing table and extract the next hop address
				struct route_table_entry *route = get_best_route_binary_search(dest_ip, rtable_len, rtable);
				if (route == NULL) {
					send_icmp_error(iph->saddr, iph->daddr, eth->ether_dhost, eth->ether_shost, 3, 0, m.interface);
					continue;
				}

				// Recalculate the checksum and decrement the time to leave field
				incremental_checksum(iph);
				
				// Sets the source address to the interface address
				get_interface_mac(route->interface, eth->ether_shost);

				// Search for the next hop address using ARP protocol
				int ok = 0;

				for (int i = 0; i < arp_table_len && ok == 0; i++) {
					if (route->next_hop == arp_table[i].ip) {
						for (int j = 0; j < 6; j++) {
							eth->ether_dhost[j] = arp_table[i].mac[j];
						}
						ok = 1;
						break;
					}
				}
				// No address found in the arp table
				if (ok == 0) {
					queue_packet q_packet;
					packet new_packet;
					memcpy(&new_packet, &m, sizeof(packet));
					q_packet.packet = new_packet;
					q_packet.route = route;

					queue_packet new_qpacket;
					memcpy(&new_qpacket, &q_packet, sizeof(queue_packet));
					// Memorize packet and best route in the queue
					queue_enq(queue, &new_qpacket);
					// Send arp request for the next hop address
					packet arp_packet = get_arp_request(route->next_hop, route->interface, eth);
					send_packet(&arp_packet);
					continue;

				} else {
					m.interface = route->interface;
					send_packet(&m);
				}
			}
		// ARP protocol case	
		} else if (ntohs(eth->ether_type) == 0x0806) {
			// Exctract arp header from packet
			struct arp_header *arp_hdr = (struct arp_header *)(m.payload + sizeof(struct ether_header));

			// ARP REQUEST received, sending ARP REPLY
			if (ntohs(arp_hdr->op) == 1) {
				
				// Construct arp header for the reply
				uint32_t ip_addr_sender = arp_hdr->spa;
				uint8_t mac_addr_sender[6];
				for (int i = 0; i < 6; i++) {
					mac_addr_sender[i] = arp_hdr->sha[i];
				}
				uint32_t ip_addr_target = arp_hdr->tpa;
				uint8_t mac_addr_target[6];
				get_interface_mac(m.interface, mac_addr_target);
				arp_hdr->op = htons(2);
				for (int i = 0; i < 6; i++) {
					arp_hdr->sha[i] = mac_addr_target[i];
					arp_hdr->tha[i] = mac_addr_sender[i];
				}
				arp_hdr->spa = ip_addr_target;
				arp_hdr->tpa = ip_addr_sender;
				for (int i = 0; i < 6; i++) {
					eth->ether_dhost[i] = mac_addr_sender[i];
					eth->ether_shost[i] = mac_addr_target[i];
				}
				send_packet(&m);
				
			// ARP REPLY received
			} else if (ntohs(arp_hdr->op) == 2) {
				uint32_t ip_addr_sender = arp_hdr->spa;
				uint8_t mac_addr_sender[6];
				for (int i = 0; i < 6; i++) {
					mac_addr_sender[i] = arp_hdr->sha[i];
				}
				// construct new entry in arp table
				struct arp_entry new_entry;
				new_entry.ip = ip_addr_sender;
				for (int i = 0; i < 6; i++) {
					new_entry.mac[i] = mac_addr_sender[i];
				}
				arp_table[arp_table_len] = new_entry;
				arp_table_len++;

				queue_packet arr[100];
				int arr_len = 0;

				// Find packets with known next hop address
				while(!queue_empty(queue)) {
					queue_packet *m = (queue_packet *)(queue_deq(queue));
					struct ether_header *eth = (struct ether_header *) m->packet.payload;

					if (m->route->next_hop == new_entry.ip) {
						for (int i = 0; i < 6; i++) {
							eth->ether_dhost[i] = new_entry.mac[i];
						}
						get_interface_mac(m->route->interface, eth->ether_shost);
						send_packet(&(m->packet));
					} else {
						arr[arr_len] = *m;
						arr_len++;
					}
				}
				for (int i = 0; i < arr_len; i++) {
					queue_enq(queue, &arr[i]);
				}
			}
		} else {
			continue;
		}

	}
}
