#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <string.h>
#include <netinet/in.h>

struct route_table_entry *rtable;
int rtable_len;
struct arp_table_entry *arp_table;
int arp_table_size = 0;
queue q;

struct packet {
	char* payload;
	size_t size;
	int interface;

};

struct packet *create_packet(char *buf, size_t size, int interface) {
	struct packet *new_packet = malloc(sizeof (struct packet));
	new_packet->interface = interface;
	new_packet->payload = buf;
	new_packet->size = size;
	return new_packet;
}

struct arp_table_entry* get_arp_entry (uint32_t ip) {
	for (int i = 0; i < arp_table_size; i++) {
		if (arp_table[i].ip == ip)
			return arp_table + i;
	}
	return NULL;
}

struct trie_route {
	struct route_table_entry *key;
	struct trie_route *left;
	struct trie_route *right;
};

struct trie_route *new_node() {
	struct trie_route *node = (struct trie_route*) malloc(sizeof(struct trie_route));
	node->left = NULL;
	node->right = NULL;
	return node;
}

struct trie_route *root = NULL;

void add_node(struct trie_route *root, struct route_table_entry *entry) {
	struct trie_route *current = root;
	for (int i  = 31; i >= 0; i--) {
		int bit = (entry->prefix >> i) & 1;
		if (bit == 0) {
			if (!current->left)
				current->left = new_node();
			current = current->left;
		}
		if (!current->right)
			current->right = new_node();
		current = current->right;
	}
	current->key = entry;
}

struct route_table_entry *search_route(uint32_t ip_dest, struct trie_route *root) {
    struct trie_route *current = root;
    for (int i = 31; i >= 0 && current; i--) {
        int bit = (ip_dest >> i) & 1;
        if (bit == 0)
            current = current->left;
        else
            current = current->right;
    }
    return current ? current->key : NULL;
}

struct route_table_entry *get_best_route(uint32_t ip_dest)
{
	for (int i = 0; i < rtable_len; i++) {
		if ((ip_dest & rtable[i].mask) == rtable[i].prefix) {
			return rtable + i;
		}
	}
	return NULL;
}

void forwarding(struct packet *packet) {
	struct ether_header *eth_hdr = (struct ether_header*) (packet->payload);
	struct iphdr *ip_hdr = (struct iphdr*) (packet->payload + sizeof (struct ether_header));
	int interface = packet->interface;
	size_t size = packet->size;
	char* buf = packet->payload;

	uint16_t original_csum = ip_hdr->check;
	ip_hdr->check = 0;
	uint16_t new_checksum = ntohs(checksum((uint16_t*) ip_hdr, sizeof (struct iphdr)));

	if (original_csum != new_checksum) {
		printf("bad checksum\n");
		return;
	}
	struct route_table_entry *best_route = search_route(ip_hdr->daddr, root);
	if (best_route == NULL) {
		return;
	}
	if (ip_hdr->ttl < 1) {
		printf("no more hops to be made\n");
		return;
	}
	ip_hdr->ttl--;
	ip_hdr->check = 0;
	new_checksum = htons(checksum((uint16_t *) ip_hdr, sizeof(struct iphdr)));
	ip_hdr->check = new_checksum;
	// verifici daca urmatorul hop se afla in tabela arp
	struct arp_table_entry *arp_entry = get_arp_entry(best_route->next_hop);
	if (arp_entry == NULL) {
		printf("%d\n", arp_table_size);
		// struct packet *temp = malloc(sizeof(struct packet));
		// memcpy(temp, &packet, sizeof(packet));
		// eth_hdr->ether_type = htons(ETHERTYPE_ARP);
		// for (int i = 0; i < 6; i++) {
		// 	eth_hdr->ether_dhost[i] = 0xFF;
		// }
		// get_interface_mac(best_route->interface, eth_hdr->ether_shost);
		// queue_enq(q, temp);
		// // aici trebuie facut un send_arp
		return;
	}
	get_interface_mac(best_route->interface, eth_hdr->ether_shost);
	memcpy(eth_hdr->ether_dhost, arp_entry->mac, sizeof(arp_entry->mac));
	// memcpy(eth_hdr->ether_shost, arp_entry->mac, sizeof(arp_entry->mac));
	send_to_link(best_route->interface, buf, size);
}

uint32_t convert_ip(char *ip) {
	char bytes[4];
	char* token = strtok (ip, ".");
	int i = 0;
	while(token != NULL) {
		bytes[i] = (uint32_t) atoi(token);
		token = strtok (NULL, ".");
		i++;
	}
    uint32_t result = (uint32_t)((bytes[0] << 24) |
				(bytes[1] << 16) | (bytes[2] << 8) | bytes[3]);
	return result;
}

int comparator (const struct route_table_entry *entry1, const struct route_table_entry *entry2) {
	if (entry1->mask > entry2->mask)
		return -1;
	if (entry1->mask < entry2->mask)
		return 1;
	if (entry1->prefix > entry2->prefix)
		return -1;
	if (entry1->prefix < entry2->mask)
		return 1;
	return 0;
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	rtable = malloc(sizeof(struct route_table_entry) * 80000);
	DIE(rtable == NULL, "memory incorrect allocated");
	arp_table = malloc(sizeof(struct arp_table_entry) * 100);
	DIE(arp_table == NULL, "memory incorrect allocated");

	q = queue_create();
	rtable_len = read_rtable(argv[1], rtable);
	qsort(rtable, rtable_len, sizeof(struct route_table_entry), (int (*)(const void*, const void*))comparator);
	arp_table_size = parse_arp_table("arp_table.txt", arp_table);
	
	DIE(rtable_len < 0, "error");

	root = new_node();
	for (int i = 0; i < rtable_len; i++) {
		add_node(root, &rtable[i]);
	}

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */
		struct iphdr *ip_hdr = (struct iphdr*) (buf + sizeof(struct ether_header));
		// if I'm sending an ipv4 protocol than verify if the router is the destination
		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
			if (ip_hdr->daddr == convert_ip(get_interface_ip(interface))) {
				continue;
			} else {
				struct packet *new_packet = create_packet(buf, len, interface);
				forwarding(new_packet);
			}
		} else {
			continue;
		}

	}
}

