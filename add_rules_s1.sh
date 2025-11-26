#!/bin/bash

simple_switch_CLI << _EOF_

table_add ipv6_host forward 2001:db8:28fe:5613::3e2d:df8e => 1c:88:18:16:d2:41 1
table_add ipv6_host forward 2001:db8:28fe:5613::fb6c:822 => 04:66:be:6a:81:dc 2
table_add ipv6_host forward 2001:db8:28fe:5613::c28e:73e3 => d0:71:79:3d:7e:0a 3

table_add ipv6_lpm forward 2001:db8:347c:d902::/64 => 80:ce:01:83:8c:e4 4

table_add port_filter allow_port 517 =>
table_add port_filter allow_port 648 =>
table_add port_filter allow_port 676 =>
table_add port_filter allow_port 849 =>

table_add port_filter_dst allow_port 517 =>
table_add port_filter_dst allow_port 648 =>
table_add port_filter_dst allow_port 676 =>
table_add port_filter_dst allow_port 849 =>

table_add udp_port_filter allow_port 517 =>
table_add udp_port_filter allow_port 648 =>
table_add udp_port_filter allow_port 676 =>
table_add udp_port_filter allow_port 849 =>

table_add udp_port_filter_dst allow_port 517 =>
table_add udp_port_filter_dst allow_port 648 =>
table_add udp_port_filter_dst allow_port 676 =>
table_add udp_port_filter_dst allow_port 849 =>

_EOF_
