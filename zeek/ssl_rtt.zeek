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
#Collect SSL handshake timing data
#
#

#tcp_rtt needed for tcp_handshake_duration
@load ./tcp_rtt.zeek

module ssl_rtt;

type SSL_RTT: record 
{
    state:              count &default=0;
    current_start:      time  &optional;
    current_end:        time  &optional;
    last_end:           time  &optional;
};

redef record connection += 
{
    ssl_rtt: SSL_RTT &optional;
};

redef record SSL::Info += 
{   
    #lowest full RTT found in TCP handshake, excludes calculated Hello delays. Requires C -> S -> C messages, 0-RTT doesn't have full RTT
    min_rtt:                interval &optional  &log;
    #Duration SSL handshake, until SSL established. Includes pre-SSL timestamp client Hello delay, if calculated
    #Only recorded if full handshake can be observed
    ssl_handshake_duration: interval &optional  &log;
    #Delta between tcp handshake duration and min_rtt for ssh
    delta_rtt_tcp_ssl:           interval    &optional   &log;
    #Time between end of TCP connection and observation of Client Hello. Since this is traffic in same direction, this delta should be very low
    orig_hello_delay:       interval &optional  &log;

};

event ssl_plaintext_data(c: connection, is_orig: bool, record_version: count, content_type: count, length: count)
{
    if ( ! c?$ssl_rtt )
    {
        c$ssl_rtt = SSL_RTT();
    }
        
    if (|is_orig| != (c$ssl_rtt$state % 2))
    {
        #state (direction) change
        if (c$ssl_rtt$state == 0)
        {
            #see if end of tcp connection is set
            if (c?$tcp_handshake_duration)
            {
                c$ssl$orig_hello_delay = network_time() - (c$start_time + c$tcp_handshake_duration);
            }
        }
        
        if (c$ssl_rtt$state >= 2)
        {
            local current_rtt: interval;
            current_rtt = network_time() - c$ssl_rtt$last_end - (c$ssl_rtt$current_end - c$ssl_rtt$current_start);
            if (c$ssl?$min_rtt)
            {
                if (current_rtt < c$ssl$min_rtt)
                {
                    c$ssl$min_rtt = current_rtt;
                    if(c?$tcp_handshake_duration)
                    {
                        c$ssl$delta_rtt_tcp_ssl = c$ssl$min_rtt - c$tcp_handshake_duration;
                    }
                }
            } 
            else
            {
                c$ssl$min_rtt = current_rtt;
                if(c?$tcp_handshake_duration)
                {
                    c$ssl$delta_rtt_tcp_ssl = c$ssl$min_rtt - c$tcp_handshake_duration;
                }
            }
        }
        
        #transition state
        if (c$ssl_rtt?$current_end)
        {            
            c$ssl_rtt$last_end = c$ssl_rtt$current_end;
        }
        c$ssl_rtt$current_start = network_time();
        c$ssl_rtt$current_end = network_time();
        c$ssl_rtt$state += 1;

    } else 
    {
        #another record in same direction/trip
        c$ssl_rtt$current_end = network_time();
    }
}

event ssl_established(c: connection)
{
    if (c$ssl?$orig_hello_delay)
    {
        c$ssl$ssl_handshake_duration = network_time() - c$ssl$ts + c$ssl$orig_hello_delay;
    } else 
    {
        c$ssl$ssl_handshake_duration = network_time() - c$ssl$ts;
    }
    
    delete c$ssl_rtt;
}
