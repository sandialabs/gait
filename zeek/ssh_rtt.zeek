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
#Collect SSH handshake timing data
#SSH timing is very tricky because messages between client and server are not necessarily sequential--both client and server can send version without waiting for each other
#RTT calculation relies on encrypted messages with presumption of synchronous communications and limited delay on each endpoint. It would be nice if there was callback for pre-encrypted packets as well.
#orig_ver_delay is relevant in layer 4 proxies (ex. SOCKS) where the SSH data is blocked closer to client than TCP exit node

#tcp_rtt needed for tcp_handshake_duration
@load ./tcp_rtt.zeek

module ssh_rtt;

type SSH_RTT: record 
{
    current_start:      time  &optional;
    current_end:        time  &optional;
    last_end:           time  &optional;
    current_dir:        bool  &default=T;
};

#Is there are reliable way to delete this from conn when at end of SSH processing?
redef record connection += 
{
    ssh_rtt: SSH_RTT &optional;
};

redef record SSH::Info += 
{
    #lowest full RTT found in encrypted messages,
    min_rtt:                interval    &optional   &log;
    #Delta between tcp handshake duration and min_rtt for ssh
    delta_rtt_tcp_ssh:           interval    &optional   &log;
    #time between end of TCP connection and observation of client version.
    orig_ver_delay:       interval      &optional   &log;
    #From end of TCP handshake to auth attempted callback, if observed
    auth_duration:          interval    &optional   &log;
};

event ssh_client_version(c: connection, version: string)
{
	if(c?$tcp_handshake_duration)
	{
    	c$ssh$orig_ver_delay = network_time() - (c$start_time + c$tcp_handshake_duration);
    	}			
}

event ssh_encrypted_packet(c: connection, is_orig: bool, len: count)
{
    if ( ! c?$ssh_rtt )
    {
        c$ssh_rtt = SSH_RTT();
    }
    

    #transition state if callback direction doesn't match current direction
    if (is_orig != c$ssh_rtt$current_dir || !c$ssh_rtt?$current_end )
    {
        local current_rtt: interval;
        current_rtt = 0sec;

        
        #we have full RTT (last, current, callback), calc time
        if (c$ssh_rtt?$last_end)
        {
            current_rtt = network_time() - c$ssh_rtt$last_end - (c$ssh_rtt$current_end - c$ssh_rtt$current_start);
            if (c$ssh?$min_rtt)
            {
                if (current_rtt < c$ssh$min_rtt)
                {
                    c$ssh$min_rtt = current_rtt;
                    if(c?$tcp_handshake_duration)
                    {
                        c$ssh$delta_rtt_tcp_ssh = c$ssh$min_rtt - c$tcp_handshake_duration;
                    }
                }
            } else
            {
                c$ssh$min_rtt = current_rtt;
                if(c?$tcp_handshake_duration)
                {
                    c$ssh$delta_rtt_tcp_ssh = c$ssh$min_rtt - c$tcp_handshake_duration;
                }
            }
        }
        
        #transition state
        if (c$ssh_rtt?$current_end)
        {
            c$ssh_rtt$last_end = c$ssh_rtt$current_end;
        }
        c$ssh_rtt$current_start = network_time();
        c$ssh_rtt$current_end = network_time();
        c$ssh_rtt$current_dir = is_orig;

    } else 
    {
        #another record in same direction/trip
        c$ssh_rtt$current_end = network_time();
    }
    #print fmt("%-17s %s %2.6f %2d %2d %s %d", network_time(), is_orig, current_rtt, c$orig$num_pkts, c$resp$num_pkts, c$id, len);
}

event ssh_auth_attempted(c: connection, authenticated: bool)
{
	if(c?$tcp_handshake_duration)
        {
    		c$ssh$auth_duration = network_time() - (c$start_time + c$tcp_handshake_duration);
	}
}

