# Copyright 2022 National Technology & Engineering Solutions of Sandia, LLC
# (NTESS). Under the terms of Contract DE-NA0003525 with NTESS, the U.S.
# Government retains certain rights in this software.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# (1) Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
# (2) Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
#
# (3) Neither the name of the University of California, Lawrence Berkeley
#     National Laboratory, U.S. Dept. of Energy, International Computer
#     Science Institute, nor the names of contributors may be used to endorse
#     or promote products derived from this software without specific prior
#     written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
#
#Collect TCP attributes useful for OS fingerprinting, connection provenance
#
#Currently doesn't collect IP options, ToS
#Currently doesn't collect ECN
#
#Getting TCP options list is very ugly, very unreliable, and ineffecient. The most direct and simple way to make this efficient would be to have SYN_packet include string that comprises the raw tcp options.
#Alternatively, if there was simple way to get header offsets of raw packet, it would make parsing the packet easier.

module tcp_attrs;

redef record Conn::Info += {
    orig_win_size:      count &optional &log;
    orig_win_scale:     int &optional &log;
    resp_win_size:      count &optional &log;
    resp_win_scale:     int &optional &log;
    orig_mss:           count &optional &log;
    resp_mss:           count &optional &log;
    orig_ttl:           count &optional &log;
    resp_ttl:           count &optional &log;
    orig_df:            bool &optional &log;
    resp_df:            bool &optional &log;
    orig_tcp_options:   string &optional &log;
    resp_tcp_options:   string &optional &log;
};

redef record connection += {
    orig_win_size:      count &optional;
    orig_win_scale:     int &optional;
    resp_win_size:      count &optional;
    resp_win_scale:     int &optional;
    orig_mss:           count &optional;
    resp_mss:           count &optional;
    orig_ttl:           count &optional;
    resp_ttl:           count &optional;
    orig_df:            bool &optional;
    resp_df:            bool &optional;
    orig_tcp_options:   string &optional;
    resp_tcp_options:   string &optional;
};

#returns CSV representation of tcp options
function tcp_options_kinds(): string
{
    local kinds: vector of string;
    local hdr: raw_pkt_hdr = get_current_packet_header();
    local pkt: pcap_packet;
    local opts_end: count;
    local offset = 0;
    local kind: count;
    
    #only process if there are tcp options
    if (hdr?$tcp && hdr$tcp$hl > 20)
    {
        pkt = get_current_packet();

        #assume ethernet
        offset += 14;
        
        if (hdr$l2?$vlan)
        {
            offset += 4;
        }
        if (hdr$l2?$inner_vlan)
        {
            offset += 4;
        }
        if (hdr?$ip)
        {
            offset += hdr$ip$hl;
        }
        if (hdr?$ip6)
        {
            offset += 40; 
        }

        #check ports and cap_len
        local sport = bytestring_to_count(pkt$data[offset:offset+2],F);
        local dport = bytestring_to_count(pkt$data[offset+2:offset+4],F);

        opts_end = hdr$tcp$hl + offset;
        if (sport == port_to_count(hdr$tcp$sport) && dport == port_to_count(hdr$tcp$dport) && opts_end <= hdr$l2$cap_len)
        {
            #skip to options of tcp header
            offset += 20;
            while (offset < opts_end)
            {
                kind = bytestring_to_count(pkt$data[offset],F);
                kinds += cat(kind);
                if (kind > 1 && offset + 1 < opts_end)
                {
                    offset += bytestring_to_count(pkt$data[offset+1],F);
                } else 
                {
                   #intentionally don't end processing if type is 0 (padding patterns/oddities useful for fingerprinting)
                    offset += 1;
                }
            }               
        } else
        {
            #couldn't find tcp header, giving up, send back 255 indicating errror
            kinds += "255";
        }
    }
    return join_string_vec(kinds, ",");
}


event connection_SYN_packet(c: connection, pkt: SYN_packet)
{
    local kinds: string;

    #make sure this is first SYN packet in each side of connection
    if (pkt$is_orig == T && c$orig$num_pkts == 0)
    {
        c$orig_win_size = pkt$win_size;
        if (pkt$win_scale > -1)
        {
            c$orig_win_scale = pkt$win_scale;
        }
        c$orig_ttl = pkt$ttl;
        c$orig_df = pkt$DF;
        if (pkt$MSS > 0)
        {
            c$orig_mss = pkt$MSS;
        }
        kinds = tcp_options_kinds();
        if (kinds != "")
        {
            c$orig_tcp_options = kinds;
        }
    }
    
    if (pkt$is_orig == F && c$resp$num_pkts == 0)
    {
        c$resp_win_size = pkt$win_size;
        if (pkt$win_scale > -1)
        {
            c$resp_win_scale = pkt$win_scale;
        }
        c$resp_ttl = pkt$ttl;
        c$resp_df = pkt$DF;
        if (pkt$MSS > 0)
        {
            c$resp_mss = pkt$MSS;
        }
        kinds = tcp_options_kinds();
        if (kinds != "")
        {
            c$resp_tcp_options = kinds;
        }
    }
}

event connection_state_remove(c: connection)
{
    if (c?$orig_win_size)
    {
        c$conn$orig_win_size = c$orig_win_size;
    }
    if (c?$orig_win_scale)
    {
        c$conn$orig_win_scale = c$orig_win_scale;
    }
    if (c?$resp_win_size)
    {
        c$conn$resp_win_size = c$resp_win_size;
    }
    if (c?$resp_win_scale)
    {
        c$conn$resp_win_scale = c$resp_win_scale;
    }
    if (c?$orig_mss)
    {
        c$conn$orig_mss = c$orig_mss;
    }
    if (c?$resp_mss)
    {
        c$conn$resp_mss = c$resp_mss;
    }
    if (c?$orig_ttl)
    {
        c$conn$orig_ttl = c$orig_ttl;
    }
    if (c?$resp_ttl)
    {
        c$conn$resp_ttl = c$resp_ttl;
    }
    if (c?$orig_df)
    {
        c$conn$orig_df = c$orig_df;
    }
    if (c?$resp_df)
    {
        c$conn$resp_df = c$resp_df;
    }
    if (c?$orig_tcp_options)
    {
        c$conn$orig_tcp_options = c$orig_tcp_options;
    }
    if (c?$resp_tcp_options)
    {
        c$conn$resp_tcp_options = c$resp_tcp_options;
    }
}






