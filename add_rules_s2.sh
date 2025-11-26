#!/bin/bash

simple_switch_CLI << _EOF_

table_add ipv6_host forward 2001:db8:347c:d902::840:5a3b => c4:9b:87:6c:82:15 1
table_add ipv6_host forward 2001:db8:347c:d902::9610:d3ec => d4:bb:4e:80:f5:23 2

table_add ipv6_lpm forward 2001:db8:28fe:5613::/64 => 7c:ee:f9:5d:ba:3a 4

table_add port_filter allow_port 45 =>
table_add port_filter allow_port 178 =>
table_add port_filter allow_port 885 =>
table_add port_filter allow_port 988 =>

table_add port_filter_dst allow_port 45 =>
table_add port_filter_dst allow_port 178 =>
table_add port_filter_dst allow_port 885 =>
table_add port_filter_dst allow_port 988 =>

table_add udp_port_filter allow_port 45 =>
table_add udp_port_filter allow_port 178 =>
table_add udp_port_filter allow_port 885 =>
table_add udp_port_filter allow_port 988 =>

table_add udp_port_filter_dst allow_port 45 =>
table_add udp_port_filter_dst allow_port 178 =>
table_add udp_port_filter_dst allow_port 885 =>
table_add udp_port_filter_dst allow_port 988 =>

_EOF_
