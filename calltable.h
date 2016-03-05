/*
    This file is part of pcapsipdump

    pcapsipdump is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    pcapsipdump is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Foobar; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

    ---

    Project's home: http://pcapsipdump.sf.net/
*/

#include <pcap.h>
#include <map>
#include <string>
#include <arpa/inet.h>

#define calltable_max 10240
#define calltable_max_ip_per_call 4

struct calltable_element {
	unsigned char is_used;
	unsigned char had_bye;
	unsigned char had_t38;
	char call_id[32];
	unsigned long call_id_len ;
	in_addr_t ip[calltable_max_ip_per_call];
        uint16_t port[calltable_max_ip_per_call];
        uint32_t ssrc[calltable_max_ip_per_call];
	int ip_n;
	time_t last_packet_time;
	pcap_dumper_t *f_pcap;
	FILE *f;
	char fn_pcap[128];
};
class rtp_key{
private:
	in_addr_t ip;
    uint16_t port;
public:
    rtp_key(in_addr_t rip, uint16_t rport) {
        ip = rip;
        port = rport;
    }

    bool operator < (const rtp_key& rhs) const {
        int cmp = *(unsigned int*)(&ip) - *(unsigned int*)(&(rhs.ip));
        if (cmp < 0) {
            return true;
        } else if (cmp > 0){
            return false;        
        } else {
            return port < rhs.port;
        }
    }
};

typedef std::map<rtp_key, int> rtp_idx;
typedef std::map<std::string, int> callid_idx;

class calltable
{
    public:
	calltable();
	int add(
	    char *call_id,
	    unsigned long call_id_len,
	    time_t time);
	int find_by_call_id(
	    char *call_id,
	    unsigned long call_id_len);
	int add_ip_port(
	    int call_idx,
	    in_addr_t addr,
	    unsigned short port);
	int find_ip_port(
	    in_addr_t addr,
	    unsigned short port);
        int find_ip_port_ssrc(
            in_addr_t addr,
            unsigned short port,
            uint32_t ssrc,
            int *idx_leg,
            int *idx_rtp);
	int do_cleanup( time_t currtime );
	calltable_element *table;
	bool erase_non_t38;
    private:
	unsigned long table_size;
	time_t global_last_packet_time;
    rtp_idx rtp_to_idx;
    callid_idx callid_to_idx;
};
