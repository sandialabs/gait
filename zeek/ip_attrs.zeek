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
#add IP TTL to conn log for non-TCP connections
#
#Current doesn't collect ECN, ToS, etc
#Currently doesn't address IP options
#
#Currently, DF flag is not collected due to lack of convienent interface to retrieve it
#
#This implemenation is possibly somewhat expensive (memory use) due to use of connection threshold
#This can be disabled by commenting the threshold related code, at expense of not collecting resp_ttl
#this could be avoided with a callback that fired on first packet from resp (when bi-directional traffic is observed)

#for additions to conn log
@load ./tcp_attrs.zeek

module ip_ttl;

#Uncomment to use without tcp_attr script
#redef record Conn::Info += 
#{
#    orig_ttl: count &optional &log;
#    resp_ttl: count &optional &log;
#};

#Uncomment to use without tcp_attr script
#redef record connection += 
#{
#    orig_ttl: count &optional;
#    resp_ttl: count &optional;
#};

event new_connection(c: connection)
{
    local hdr: raw_pkt_hdr;
    
    #skip TCP connections, they get different treatment
    #if (get_conn_transport_proto(c$id) != tcp)
    if (get_port_transport_proto(c$id$orig_p) != tcp)
    {
        #conns that aren't tcp
        hdr = get_current_packet_header();
        if (hdr?$ip)
        {
            c$orig_ttl = hdr$ip$ttl;
        } else if (hdr?$ip6)
        {
            c$orig_ttl = hdr$ip6$hlim;
        }
        #Comment line below to disable resp_ttl collection (expensive)
        #ConnThreshold::set_packets_threshold(c, 1, F);
    }
}

#Comment callback below to disable resp_ttl collection (expensive)
#event ConnThreshold::packets_threshold_crossed(c: connection, threshold: count, is_orig: bool)
#{
#    local hdr: raw_pkt_hdr;
#    hdr = get_current_packet_header();
#    if (hdr?$ip)
#    {
#        c$resp_ttl = hdr$ip$ttl;
#    } else if (hdr?$ip6)
#    {
#        c$resp_ttl = hdr$ip6$hlim;
#    }
#}

#Uncomment to use without tcp_attr script
#event connection_state_remove(c: connection)
#{
#    if (c?$orig_ttl)
#    {
#        c$conn$orig_ttl = c$orig_ttl;
#    }
#    if (c?$resp_ttl)
#    {
#        c$conn$resp_ttl = c$resp_ttl;
#    }
#}

