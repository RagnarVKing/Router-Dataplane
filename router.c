#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>
#include <string.h>

struct route_table_entry *route_table;
int route_table_len;

struct arp_table_entry *arp_table;
int arp_table_len;

queue q;

struct route_table_entry *get_best_route(uint32_t ip_dest) {
	int left = 0;
    int right = route_table_len - 1;
    int mid;
	struct route_table_entry *best_route = NULL;

    while (left <= right) {
        mid = left + (right - left) / 2;

        if ((ip_dest & route_table[mid].mask) == route_table[mid].prefix && (best_route == NULL || ntohl(route_table[mid].mask) > ntohl(best_route->mask))) {
			best_route = &route_table[mid];
        }

        if ((ntohl(ip_dest)) < ntohl(route_table[mid].prefix)) {
            right = mid - 1;
        } else {
            left = mid + 1;
        }
    }

    return best_route;
}

struct arp_table_entry* get_arp_entry(uint32_t given_ip) {
	for (int i = 0; i < arp_table_len; i++) {
		if (arp_table[i].ip == given_ip) {
			return &arp_table[i];
		}
	}
	return NULL;
}

int compare_entries(const void *a, const void *b) {
    const struct route_table_entry *entry1 = (const struct route_table_entry *)a;
    const struct route_table_entry *entry2 = (const struct route_table_entry *)b;

    if (ntohl(entry1->prefix) > ntohl(entry2->prefix)) return 1;
    if (ntohl(entry1->prefix) == ntohl(entry2->prefix) && ntohl(entry1->mask) > ntohl(entry2->mask)) return 1;

    return -1;
}

void host_unreachable(int interface, char *buf, size_t len) {

	struct ether_header *eth_hdr = (struct ether_header *)buf;
    memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
	get_interface_mac(interface, eth_hdr->ether_shost);
	eth_hdr->ether_type = htons(ETHERTYPE_IP);



	struct iphdr *ip_hdr_1 = (struct iphdr *)(buf + sizeof(struct ether_header));

	ip_hdr_1->check = 0;
	ip_hdr_1->check = htons(checksum((uint16_t *)ip_hdr_1, sizeof(struct iphdr)));
	ip_hdr_1->protocol = IPPROTO_ICMP;
	ip_hdr_1->tot_len = htons(sizeof(struct iphdr) + sizeof(struct iphdr) + sizeof(struct icmphdr) + 8);


    ip_hdr_1->daddr = ip_hdr_1->saddr;
    ip_hdr_1->saddr = inet_addr(get_interface_ip(interface));



	len += sizeof(struct icmphdr);



	struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
    icmp_hdr->type = ICMP_DEST_UNREACH;
    icmp_hdr->code = ICMP_NET_UNREACH;

	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr) + sizeof(struct iphdr) + 8));



	struct iphdr *ip_hdr_2 = (struct iphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr));
	memcpy(ip_hdr_2, buf + sizeof(struct ether_header), sizeof(struct iphdr));

	len += sizeof(struct iphdr);

	char *payload = buf + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
	size_t payload_len = len - sizeof(struct ether_header) - sizeof(struct iphdr) - sizeof(struct icmphdr);
    memmove(buf + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), payload, payload_len);

    send_to_link(interface, buf, sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + payload_len);
}

void timeout(int interface, char *buf, size_t len) {
	struct ether_header *eth_hdr = (struct ether_header *)buf;
    memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
	get_interface_mac(interface, eth_hdr->ether_shost);
	eth_hdr->ether_type = htons(ETHERTYPE_IP);



	struct iphdr *ip_hdr_1 = (struct iphdr *)(buf + sizeof(struct ether_header));

	ip_hdr_1->protocol = IPPROTO_ICMP;
	ip_hdr_1->tot_len = htons(sizeof(struct iphdr) + sizeof(struct iphdr) + sizeof(struct icmphdr) + 8);

    ip_hdr_1->daddr = ip_hdr_1->saddr;
    ip_hdr_1->saddr = inet_addr(get_interface_ip(interface));



	len += sizeof(struct icmphdr);



	struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
    icmp_hdr->type = ICMP_TIME_OUT;
    icmp_hdr->code = ICMP_NET_UNREACH;

	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr) + sizeof(struct iphdr) + 8));



	struct iphdr *ip_hdr_2 = (struct iphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr));
	memcpy(ip_hdr_2, buf + sizeof(struct ether_header), sizeof(struct iphdr));

	len += sizeof(struct iphdr);

	char *payload = buf + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
	size_t payload_len = len - sizeof(struct ether_header) - sizeof(struct iphdr) - sizeof(struct icmphdr);
    memmove(buf + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), payload, payload_len);

    send_to_link(interface, buf, sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + payload_len);
}

void icmp(int interface, char *buf, size_t len) {
	struct ether_header *eth_hdr = (struct ether_header *)buf;
    memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
	get_interface_mac(interface, eth_hdr->ether_shost);
	eth_hdr->ether_type = htons(ETHERTYPE_IP);


	struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));



	ip_hdr->tot_len = htons(ntohs(ip_hdr->tot_len) + sizeof(struct icmphdr));
	ip_hdr->protocol = IPPROTO_ICMP;

	struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));

    icmp_hdr->type = ICMP_NET_UNREACH;
    icmp_hdr->code = ICMP_NET_UNREACH;


    ip_hdr->daddr = ip_hdr->saddr;
    ip_hdr->saddr = inet_addr(get_interface_ip(interface));

    icmp_hdr->checksum = 0;
    icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, len - sizeof(struct ether_header) - sizeof(struct iphdr)));;

	send_to_link(interface, buf, len);
}

void arp_request(int interface, char *buf, size_t len)
{
	// struct ether_header *eth_hdr = (struct ether_header *) buf;

	// len += sizeof(struct ether_header);

	// struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));

	// len += sizeof(struct arp_header);

	// arp_hdr->op = htons(2);
	// for(int i = 0; i < 6; i++) {
	// 	arp_hdr->tha[i] = arp_hdr->sha[i];
	// }

	// get_interface_mac(interface, arp_hdr->sha);

	// arp_hdr->tpa = arp_hdr->spa;
	// arp_hdr->spa = inet_addr(get_interface_ip(interface));

	// for(int i = 0; i < 6; i++) {
	// 	eth_hdr->ether_dhost[i] = eth_hdr->ether_shost[i];
	// }

	// get_interface_mac(interface, eth_hdr->ether_shost);

	// send_to_link(interface, buf, len);
}

void arp_reply(int interface, char *buf, size_t len)
{
	// struct ether_header *eth_hdr = (struct ether_header *) buf;
	// for(int i = 0; i < 6; i++) {
	// 	eth_hdr->ether_dhost[i] = eth_hdr->ether_shost[i];
	// }
	// get_interface_mac(interface, eth_hdr->ether_shost);

	// // swap arp header

	// struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));

	// arp_hdr->op = htons(2);

	// for(int i = 0; i < 6; i++) {
	// 	arp_hdr->tha[i] = arp_hdr->sha[i];
	// }

	// get_interface_mac(interface, arp_hdr->sha);

	// arp_hdr->tpa = arp_hdr->spa;

	// arp_hdr->spa = inet_addr(get_interface_ip(interface));

	// send_to_link(interface, buf, len);

}

void send_arp_request(char *buf, struct route_table_entry *route)
{
	// struct ether_header *eth_hdr = (struct ether_header *) buf;
	// struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));

	// eth_hdr->ether_type = htons(ETHERTYPE_ARP);

	// arp_hdr->htype = htons(1);
	// arp_hdr->ptype = htons(ETHERTYPE_IP);
	// arp_hdr->hlen = 6;
	// arp_hdr->plen = 4;
	// arp_hdr->op = htons(1);

	// for(int i = 0; i < 6; i++) {
	// 	arp_hdr->tha[i] = 0;
	// }

	// arp_hdr->tpa = route->next_hop;

	// send_to_link(route->interface, buf, sizeof(struct ether_header) + sizeof(struct arp_header));
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	route_table = malloc(sizeof(struct route_table_entry) * 80000);
	DIE(route_table == NULL, "memory");

	arp_table = malloc(sizeof(struct arp_table_entry) * 100);
	DIE(arp_table == NULL, "memory");

	route_table_len = read_rtable(argv[1], route_table);
	arp_table_len = parse_arp_table("arp_table.txt", arp_table);


	qsort(route_table, route_table_len, sizeof(struct route_table_entry), compare_entries);

	q = queue_create();

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");
		printf("We have received a message\n");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

		if (eth_hdr->ether_type != ntohs(ETHERTYPE_IP)) {
			if (eth_hdr->ether_type != ntohs(ETHERTYPE_ARP)) {
				printf("Ignored non-IPv4 packet\n");
				continue;
			}
			struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));
			uint16_t arp_hdr_op = htons(1);
			if (arp_hdr->op != arp_hdr_op) {
				arp_reply(interface, buf, len);
			} else {
				arp_request(interface, buf, len);
			}
			continue;
		}

		if (ip_hdr->protocol == IPPROTO_ICMP) {
			struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr)); 
			if (icmp_hdr->type == IPPROTO_EGP && inet_addr(get_interface_ip(interface)) == ip_hdr->daddr) {
				icmp(interface, buf, len);
				continue;
			}
		}

		uint16_t checksum1 = ntohs(ip_hdr->check);
		ip_hdr->check = 0;
		uint16_t checksum2 = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));

		if (checksum1 != checksum2) {
			printf("Wrong checksum\n");
			continue;
		}

		struct route_table_entry *route = get_best_route(ip_hdr->daddr);
		if (route == NULL) {
			host_unreachable(interface, buf, len);
			continue;
		}

		if (ip_hdr->ttl > 1) {
			ip_hdr->ttl--;
		} else {
			timeout(interface, buf, len);
			continue;
		}

		ip_hdr->check = 0;
		uint16_t checksum3 = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));
		ip_hdr->check = checksum3;

		uint8_t mac[6];
		get_interface_mac(route->interface, mac);
		struct arp_table_entry *ret = get_arp_entry(route->next_hop);

		if (ret == NULL) {
			send_arp_request(buf, route);
		}

		for (int i = 0; i < 6; i++) {
			eth_hdr->ether_shost[i] = mac[i];
			eth_hdr->ether_dhost[i] = ret->mac[i];
		}
		send_to_link(route->interface, buf, len);
	}

	free(route_table);
	free(arp_table);

}

