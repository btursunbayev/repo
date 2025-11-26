#!/bin/bash

S2P0=$1
S2P1=$2
S2P2=$3
S2P3=$4
H21_MAC=$5
H22_MAC=$6
H23_MAC=$7
H21_IP=$8
H22_IP=$9
H23_IP=${10}
S1_IP=${11}
S1P0=${12}
SUBNET1=${13}

simple_switch_CLI << _EOF_
table_set_default send_frame _drop
table_set_default forward6 _drop
table_set_default ipv6_lpm _drop
table_add send_frame rewrite_mac 0 => $S2P0
table_add send_frame rewrite_mac 1 => $S2P1
table_add send_frame rewrite_mac 2 => $S2P2
table_add send_frame rewrite_mac 3 => $S2P3
table_add forward6 set_dmac $S1_IP => $S1P0
table_add forward6 set_dmac $H21_IP => $H21_MAC
table_add forward6 set_dmac $H22_IP => $H22_MAC
table_add forward6 set_dmac $H23_IP => $H23_MAC
table_add ipv6_lpm set_nhop6 $SUBNET1 => $S1_IP 0
table_add ipv6_lpm set_nhop6 $H21_IP/128 => $H21_IP 1
table_add ipv6_lpm set_nhop6 $H22_IP/128 => $H22_IP 2
table_add ipv6_lpm set_nhop6 $H23_IP/128 => $H23_IP 3
_EOF_
