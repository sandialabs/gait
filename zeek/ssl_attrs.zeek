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
#Collect additional TLS attributes useful for OS/software fingerprinting, connection provenance
#
#This is similar to ssl-log-ext, but is meant to complement ja3
#
#

module ssl_attrs;


type SSL_ATTRS: record 
{
    orig_apln:                      string_vec  &optional;
    resp_apln:                      string      &optional;
    orig_supported_versions:        index_vec   &optional;
    resp_supported_version:         count       &optional;
    orig_record_size_limit:         count       &optional;
    resp_record_size_limit:         count       &optional;
    orig_psk_hello_ids_md5:         string_vec  &optional;
    resp_psk_hello_id:              count       &optional;
    orig_key_share_curves:          index_vec   &optional;
    resp_key_share_curve:           count       &optional;
    orig_psk_key_exchange_modes:    index_vec   &optional;
    orig_comp_methods:              index_vec   &optional;
    resp_comp_method:               count       &optional;
    resp_ticket_lifetime_hint:      count       &optional;
    orig_sig_hash_algos:            index_vec   &optional;
};

redef record connection += 
{
    ssl_attrs: SSL_ATTRS &optional;
};

redef record SSL::Info += 
{
    orig_apln:                      string_vec  &optional &log;
    resp_apln:                      string      &optional &log;
    orig_supported_versions:        index_vec   &optional &log;
    resp_supported_version:         count       &optional &log;
    orig_record_size_limit:         count       &optional &log;
    resp_record_size_limit:         count       &optional &log;
    orig_psk_hello_ids_md5:         string_vec  &optional &log;
    resp_psk_hello_id:              count       &optional &log;
    orig_key_share_curves:          index_vec   &optional &log;
    resp_key_share_curve:           count       &optional &log;
    orig_psk_key_exchange_modes:    index_vec   &optional &log;
    orig_comp_methods:              index_vec   &optional &log;
    resp_comp_method:               count       &optional &log;
    resp_ticket_lifetime_hint:      count       &optional &log;
    orig_sig_hash_algos:            index_vec   &optional &log;
};

const grease_values: set[count] = 
{
    2570,
    6682,
    10794,
    14906,
    19018,
    23130,
    27242,
    31354,
    35466,
    39578,
    43690,
    47802,
    51914,
    56026,
    60138,
    64250
};

const grease_psk_modes: set[count] =
{
    11,
    42,
    73,
    104,
    135,
    166,
    197,
    228
};    
    
function filter_grease(input: index_vec, psk: bool &default=F): index_vec
{
    local filtered: index_vec;
    filtered = vector();
    
    for ( i in input )
    {
        if (psk)
        {
            if (! (input[i] in grease_psk_modes))
            {
                filtered += input[i];
            }
        } else
        {
            if (! (input[i] in grease_values))
            {
                filtered += input[i];
            }
        }
    }
    return filtered;
}

function filter_grease_str(input: string_vec): string_vec
{
    local filtered: string_vec;
    filtered = vector();
    for ( i in input )
    {
        if (input[i][:7] != "ignore/")
        {
            filtered += input[i];
        }
    }
    return filtered;
}

event ssl_extension(c: connection, is_orig: bool, code: count, val: string)
{
    if ( ! c?$ssl_attrs )
    {
        c$ssl_attrs = SSL_ATTRS();
    }
    
    if (code == 28)
    {
        if (is_orig)
        {
            c$ssl_attrs$orig_record_size_limit = bytestring_to_count(val,F);
        } else
        {
            c$ssl_attrs$resp_record_size_limit = bytestring_to_count(val,F);
        }
    }
}

event ssl_extension_application_layer_protocol_negotiation(c: connection, is_orig: bool, protocols: string_vec)
{
    if ( ! c?$ssl_attrs )
    {
        c$ssl_attrs = SSL_ATTRS();
    }
    
    if (is_orig)
    {
        c$ssl_attrs$orig_apln = filter_grease_str(protocols);
    } else
    {
        c$ssl_attrs$resp_apln = protocols[0];
    }
}

event ssl_extension_supported_versions(c: connection, is_orig: bool, versions: index_vec)
{
    if ( ! c?$ssl_attrs )
    {
        c$ssl_attrs = SSL_ATTRS();
    }
    
    if (is_orig)
    {
        c$ssl_attrs$orig_supported_versions = filter_grease(versions);
        
    } else
    {
        c$ssl_attrs$resp_supported_version = versions[0];
    }
}

event ssl_extension_pre_shared_key_client_hello(c: connection, is_orig: bool, identities: psk_identity_vec, binders: string_vec)
{
    if ( ! c?$ssl_attrs )
    {
        c$ssl_attrs = SSL_ATTRS();
    }
    
    if ( ! c$ssl_attrs?$orig_psk_hello_ids_md5 )
    {
        c$ssl_attrs$orig_psk_hello_ids_md5 = vector();
    }

    for ( i in identities )
    {
        c$ssl_attrs$orig_psk_hello_ids_md5 += md5_hash(identities[i]$identity);
    }
}

event ssl_extension_pre_shared_key_server_hello(c: connection, is_orig: bool, selected_identity: count)
{
    if ( ! c?$ssl_attrs )
    {
        c$ssl_attrs = SSL_ATTRS();
    }
    
    c$ssl_attrs$resp_psk_hello_id = selected_identity;
}

event ssl_extension_key_share(c: connection, is_orig: bool, curves: index_vec)
{
    if ( ! c?$ssl_attrs )
    {
        c$ssl_attrs = SSL_ATTRS();
    }
    
    if (is_orig)
    {
        c$ssl_attrs$orig_key_share_curves = filter_grease(curves);
        
    } else
    {
        c$ssl_attrs$resp_key_share_curve = curves[0];
    }
}

event ssl_extension_psk_key_exchange_modes(c: connection, is_orig: bool, modes: index_vec)
{
    if ( ! c?$ssl_attrs )
    {
        c$ssl_attrs = SSL_ATTRS();
    }
    
    if (is_orig)
    {
        c$ssl_attrs$orig_psk_key_exchange_modes = filter_grease(modes, T);
    }
}

event ssl_session_ticket_handshake(c: connection, ticket_lifetime_hint: count, ticket: string)
{
    if ( ! c?$ssl_attrs )
    {
        c$ssl_attrs = SSL_ATTRS();
    }
    
    c$ssl_attrs$resp_ticket_lifetime_hint = ticket_lifetime_hint;
}

event ssl_extension_signature_algorithm(c: connection, is_orig: bool, signature_algorithms: signature_and_hashalgorithm_vec)
{
    local algo: count;
    
    if ( ! c?$ssl_attrs )
    {
        c$ssl_attrs = SSL_ATTRS();
    }
    
    if ( ! (c$ssl_attrs?$orig_sig_hash_algos) )
    {   
        c$ssl_attrs$orig_sig_hash_algos = vector();
    }

    for ( i in signature_algorithms )
    {
        algo = signature_algorithms[i]$SignatureAlgorithm*256 + signature_algorithms[i]$HashAlgorithm;
        if (!(algo in grease_values))
        {
            c$ssl_attrs$orig_sig_hash_algos += algo;
        }
    }
}

event ssl_client_hello(c: connection, version: count, record_version: count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec, comp_methods: index_vec)
{
    if ( ! c?$ssl_attrs )
    {
        c$ssl_attrs = SSL_ATTRS();
    }
    
    c$ssl_attrs$orig_comp_methods = comp_methods;
}

event ssl_server_hello(c: connection, version: count, record_version: count, possible_ts: time, server_random: string, session_id: string, cipher: count, comp_method: count)
{
    if ( ! c?$ssl_attrs )
    {
        c$ssl_attrs = SSL_ATTRS();
    }
    
    c$ssl_attrs$resp_comp_method = comp_method;
}

event ssl_established(c: connection)
{
    
    if ( ! c?$ssl_attrs )
    {
        return;
    }
    
    if ( c$ssl_attrs?$orig_apln )
    {
        c$ssl$orig_apln = c$ssl_attrs$orig_apln;
    }
    
    if ( c$ssl_attrs?$resp_apln )
    {
        c$ssl$resp_apln = c$ssl_attrs$resp_apln;
    }
    
    if ( c$ssl_attrs?$orig_supported_versions )
    {
        c$ssl$orig_supported_versions = c$ssl_attrs$orig_supported_versions;
    }
    
    if ( c$ssl_attrs?$resp_supported_version )
    {
        c$ssl$resp_supported_version = c$ssl_attrs$resp_supported_version;
    }
    
    if ( c$ssl_attrs?$orig_record_size_limit )
    {
        c$ssl$orig_record_size_limit = c$ssl_attrs$orig_record_size_limit;
    }
    
    if ( c$ssl_attrs?$resp_record_size_limit )
    {
        c$ssl$resp_record_size_limit = c$ssl_attrs$resp_record_size_limit;
    }
    
    if ( c$ssl_attrs?$orig_psk_hello_ids_md5 )
    {
        c$ssl$orig_psk_hello_ids_md5 = c$ssl_attrs$orig_psk_hello_ids_md5;
    }
    
    if ( c$ssl_attrs?$resp_psk_hello_id )
    {
        c$ssl$resp_psk_hello_id = c$ssl_attrs$resp_psk_hello_id;
    }
    
    if ( c$ssl_attrs?$orig_key_share_curves )
    {
        c$ssl$orig_key_share_curves = c$ssl_attrs$orig_key_share_curves;
    }
    
    if ( c$ssl_attrs?$resp_key_share_curve )
    {
        c$ssl$resp_key_share_curve = c$ssl_attrs$resp_key_share_curve;
    }
    
    if ( c$ssl_attrs?$orig_psk_key_exchange_modes )
    {
        c$ssl$orig_psk_key_exchange_modes = c$ssl_attrs$orig_psk_key_exchange_modes;
    }
    
    if ( c$ssl_attrs?$orig_comp_methods )
    {
        c$ssl$orig_comp_methods = c$ssl_attrs$orig_comp_methods;
    }
    
    if ( c$ssl_attrs?$resp_comp_method )
    {
        c$ssl$resp_comp_method = c$ssl_attrs$resp_comp_method;
    }

    if ( c$ssl_attrs?$resp_ticket_lifetime_hint )
    {
        c$ssl$resp_ticket_lifetime_hint = c$ssl_attrs$resp_ticket_lifetime_hint;
    }
    
    if ( c$ssl_attrs?$orig_sig_hash_algos )
    {
        c$ssl$orig_sig_hash_algos = c$ssl_attrs$orig_sig_hash_algos;
    }
    
    delete c$ssl_attrs;
}
