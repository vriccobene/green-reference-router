#!/usr/bin/perl
# vim:set shiftwidth=4 softtabstop=4 expandtab:
#
# Author: Michael Ciesla <mick.ciesla@gmail.com>
#  (based on test_packet_forwarding)
#
# Description
#
#  Verifies that the following 4 types of packets don't get duplicated:
#     1. ip_len < MIN_LEN, proto == TCP
#     2. ip_len < MIN_LEN, proto != TCP
#     3. ip_len > MIN_LEN, proto != TCP
#     4. ip_len > MIN_LEN, proto == TCP, dst port != 80
#
#  * MIN_LEN  = 20(ip) + 32(unix tcp hdr) + 4 (get request method) = 56B. 


use strict;
use NF2::RegressLib;
use NF2::PacketLib;
use RegressRouterLib;
        
use reg_defines_reference_router;

my @interfaces = ("nf2c0", "nf2c1", "nf2c2", "nf2c3", "eth1", "eth2");
nftest_init(\@ARGV,\@interfaces,);
nftest_start(\@interfaces);

my $routerMAC0 = "00:ca:fe:00:00:01";
my $routerMAC1 = "00:ca:fe:00:00:02";
my $routerMAC2 = "00:ca:fe:00:00:03";
my $routerMAC3 = "00:ca:fe:00:00:04";

my $routerIP0 = "192.168.0.40";
my $routerIP1 = "192.168.1.40";
my $routerIP2 = "192.168.2.40";
my $routerIP3 = "192.168.3.40";

# clear LPM table
for (my $i = 0; $i < 32; $i++)
{
  nftest_invalidate_LPM_table_entry('nf2c0', $i);
}

# clear ARP table
for (my $i = 0; $i < 32; $i++)
{
  nftest_invalidate_ARP_table_entry('nf2c0', $i);
}

# Write the mac and IP addresses
nftest_add_dst_ip_filter_entry ('nf2c0', 0, $routerIP0);
nftest_add_dst_ip_filter_entry ('nf2c1', 1, $routerIP1);
nftest_add_dst_ip_filter_entry ('nf2c2', 2, $routerIP2);
nftest_add_dst_ip_filter_entry ('nf2c3', 3, $routerIP3);

nftest_set_router_MAC ('nf2c0', $routerMAC0);
nftest_set_router_MAC ('nf2c1', $routerMAC1);
nftest_set_router_MAC ('nf2c2', $routerMAC2);
nftest_set_router_MAC ('nf2c3', $routerMAC3);

# tcp hdr. used to test type 1 packets. 20B in length.
my @DATA1 = (0xc8, 0x40, 0x00, 0x50, 0xce, 0xbd, 
0x72, 0xac, 0xff, 0x9a, 0x1d, 0xcf, 0x50, 0x10, 
0xff, 0xff, 0x7c, 0x57, 0x00, 0x00);

# tcp hdr and payload. dst port != 80. 40B in length.
my @DATA2 = (0x00, 0x50, 0xc5, 0x67, 0x8f, 0xa6, 
0xfc, 0xdf, 0x56, 0x81, 0x7c, 0x76, 0xa0, 0x12, 
0x16, 0xa0, 0x2c, 0x6d, 0x00, 0x00, 0x02, 0x04, 
0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a, 0x30, 0x9d, 
0x87, 0x58, 0x3a, 0xf2, 0x33, 0x63, 0x01, 0x03, 
0x03, 0x09);


# add an entry in the routing table:
my $index = 0;
my $subnetIP = "192.168.2.0";
my $subnetIP2 = "192.168.1.0";
my $subnetMask = "255.255.255.0";
my $subnetMask2 = "255.255.255.0";
my $nextHopIP = "192.168.1.54";
my $nextHopIP2 = "192.168.3.12";
my $outPort = 0x1; # output on MAC0
my $outPort2 = 0x4;
my $nextHopMAC = "dd:55:dd:66:dd:77";

nftest_add_LPM_table_entry ('nf2c0',
			    1,
			    $subnetIP,
			    $subnetMask,
			    $nextHopIP,
			    $outPort);

nftest_add_LPM_table_entry ('nf2c0',
			    0,
			    $subnetIP2,
			    $subnetMask2,
			    $nextHopIP2,
			    $outPort2);


# add an entry in the ARP table
nftest_add_ARP_table_entry('nf2c0',
			   $index,
			   $nextHopIP,
			   $nextHopMAC);

# add an entry in the ARP table
nftest_add_ARP_table_entry('nf2c0',
			   1,
			   $nextHopIP2,
			   $nextHopMAC);

my $total_errors = 0;
my $temp_error_val = 0;

#clear the num pkts forwarded reg
nftest_regwrite('nf2c0', ROUTER_OP_LUT_NUM_PKTS_FORWARDED_REG, 0);

# send pkt type 1 from eth1 to eth2. loop 20 times. 
for (my $i = 0; $i < 20; $i++) {
	# set parameters
	my $DA = $routerMAC0;
	my $SA = "aa:bb:cc:dd:ee:ff";
	my $TTL = 64;
	my $proto = 0x06; # tcp
	my $DST_IP = "192.168.1.1"; 
	my $SRC_IP = "192.168.0.1";
	my $nextHopMAC = "dd:55:dd:66:dd:77";
	
	# create mac header
	my $MAC_hdr = NF2::Ethernet_hdr->new(DA => $DA,
					        SA => $SA,
						Ethertype => 0x800
					        );
	
	# create packet filling.... (IP PDU)
	my $PDU = NF2::PDU->new();
	$PDU->set_bytes(@DATA1);
	my $PDU_len = $PDU->length_in_bytes();
	
	#create IP header
	my $IP_hdr = NF2::IP_hdr->new(ttl => $TTL,
	                                proto => $proto,
	                                src_ip => $SRC_IP,
	                                dst_ip => $DST_IP,
					dgram_len => 20 + $PDU_len, # IP hdr is 20 bytes.
	                               );
	
	$IP_hdr->checksum(0);  # make sure its zero before we calculate it.
	$IP_hdr->checksum($IP_hdr->calc_checksum);
	
	# get packed packet string
	my $sent_pkt = $MAC_hdr->packed . $IP_hdr->packed . $PDU->packed;
	
	# create the expected packet
	my $MAC_hdr2 = NF2::Ethernet_hdr->new(DA => $nextHopMAC,
						SA => $routerMAC1,
						Ethertype => 0x800
					    	);
	
	
	$IP_hdr->ttl($TTL-1);
	$IP_hdr->checksum(0);  # make sure its zero before we calculate it.
	$IP_hdr->checksum($IP_hdr->calc_checksum);
	
	my $expected_pkt = $MAC_hdr2->packed . $IP_hdr->packed . $PDU->packed;
	
	# send packet out of eth1->eth2 and nf2c0 (duplicated)
	nftest_send('eth1', $sent_pkt);
	nftest_expect('eth2', $expected_pkt);
	`usleep 500`;
}

# send pkt type 1 from eth2 to eth1. loop for 20 packets. 
for (my $i = 0; $i < 20; $i++)
{
	# set parameters
	my $DA = $routerMAC1;
	my $SA = "aa:bb:cc:dd:ee:ff";
	my $TTL = 64;
	my $proto = 0x06; # tcp
	my $DST_IP = "192.168.2.1"; 
	my $SRC_IP = "192.168.0.1";
	my $nextHopMAC = "dd:55:dd:66:dd:77";

	# create mac header
	my $MAC_hdr = NF2::Ethernet_hdr->new(DA => $DA,
					        SA => $SA,
						Ethertype => 0x800
					        );
	
	# create packet filling.... (IP PDU)
	my $PDU = NF2::PDU->new();
	$PDU->set_bytes(@DATA1);
	my $PDU_len = $PDU->length_in_bytes();
	
	#create IP header
	my $IP_hdr = NF2::IP_hdr->new(ttl => $TTL,
	                                proto => $proto,
	                                src_ip => $SRC_IP,
	                                dst_ip => $DST_IP,
					dgram_len => 20 + $PDU_len, # IP hdr is 20 bytes.
	                               );
	
	$IP_hdr->checksum(0);  # make sure its zero before we calculate it.
	$IP_hdr->checksum($IP_hdr->calc_checksum);
	
	# get packed packet string
	my $sent_pkt = $MAC_hdr->packed . $IP_hdr->packed . $PDU->packed;
	
	# create the expected packet
	my $MAC_hdr2 = NF2::Ethernet_hdr->new(DA => $nextHopMAC,
						SA => $routerMAC0,
						Ethertype => 0x800
					    	);
	
	
	$IP_hdr->ttl($TTL-1);
	$IP_hdr->checksum(0);  # make sure its zero before we calculate it.
	$IP_hdr->checksum($IP_hdr->calc_checksum);
	
	my $expected_pkt = $MAC_hdr2->packed . $IP_hdr->packed . $PDU->packed;

	# send packet out of eth2 -> eth1 & nf2c0 
	nftest_send('eth2', $sent_pkt);
	nftest_expect('eth1', $expected_pkt);
	`usleep 500`;  
}

# send pkt type 2 from eth1 to eth2. loop 20 times. 
for (my $i = 0; $i < 20; $i++)
{
	# set parameters
	my $DA = $routerMAC0;
	my $SA = "aa:bb:cc:dd:ee:ff";
	my $TTL = 64;
        my $PROTO = 0x11; # UDP
	my $DST_IP = "192.168.1.1"; 
	my $SRC_IP = "192.168.0.1";
	my $len = 50;
	my $nextHopMAC = "dd:55:dd:66:dd:77";

	# create mac header
	my $MAC_hdr = NF2::Ethernet_hdr->new(DA => $DA,
						     SA => $SA,
						     Ethertype => 0x800
				    		);

	#create IP header
	my $IP_hdr = NF2::IP_hdr->new(ttl => $TTL,
                                              proto => $PROTO,
					      src_ip => $SRC_IP,
					      dst_ip => $DST_IP,
                                              dgram_len => $len
			    		 );

	$IP_hdr->checksum(0);  # make sure its zero before we calculate it.
	$IP_hdr->checksum($IP_hdr->calc_checksum);

	# create packet filling.... (IP PDU)
	my $PDU = NF2::PDU->new($len - $MAC_hdr->length_in_bytes() - $IP_hdr->length_in_bytes() );
	my $start_val = $MAC_hdr->length_in_bytes() + $IP_hdr->length_in_bytes()+1;
	my @data = ($start_val..$len);
	for (@data) {$_ %= 100}
	$PDU->set_bytes(@data);

	# get packed packet string
	my $sent_pkt = $MAC_hdr->packed . $IP_hdr->packed . $PDU->packed;

	# create the expected packet
	my $MAC_hdr2 = NF2::Ethernet_hdr->new(DA => $nextHopMAC,
						     SA => $routerMAC1,
						     Ethertype => 0x800
				    		);


	$IP_hdr->ttl($TTL-1);
	$IP_hdr->checksum(0);  # make sure its zero before we calculate it.
	$IP_hdr->checksum($IP_hdr->calc_checksum);

	my $expected_pkt = $MAC_hdr2->packed . $IP_hdr->packed . $PDU->packed;

	# send packet out of eth1->nf2c0 
	nftest_send('eth1', $sent_pkt);
	nftest_expect('eth2', $expected_pkt);
  `usleep 500`;
}

# send pkt type 2 from eth2 to eth1. loop 20 times. 
for (my $i = 0; $i < 20; $i++)
{
	# set parameters
	my $DA = $routerMAC1;
	my $SA = "aa:bb:cc:dd:ee:ff";
	my $TTL = 64;
        my $PROTO = 0x11; # UDP
	my $DST_IP = "192.168.2.1"; 
	my $SRC_IP = "192.168.0.1";
	my $len = 50;
	my $nextHopMAC = "dd:55:dd:66:dd:77";

	# create mac header
	my $MAC_hdr = NF2::Ethernet_hdr->new(DA => $DA,
						     SA => $SA,
						     Ethertype => 0x800
				    		);

	#create IP header
	my $IP_hdr = NF2::IP_hdr->new(ttl => $TTL,
                                              proto => $PROTO,
					      src_ip => $SRC_IP,
					      dst_ip => $DST_IP,
                                              dgram_len => $len
			    		 );

	$IP_hdr->checksum(0);  # make sure its zero before we calculate it.
	$IP_hdr->checksum($IP_hdr->calc_checksum);

	# create packet filling.... (IP PDU)
	my $PDU = NF2::PDU->new($len - $MAC_hdr->length_in_bytes() - $IP_hdr->length_in_bytes() );
	my $start_val = $MAC_hdr->length_in_bytes() + $IP_hdr->length_in_bytes()+1;
	my @data = ($start_val..$len);
	for (@data) {$_ %= 100}
	$PDU->set_bytes(@data);

	# get packed packet string
	my $sent_pkt = $MAC_hdr->packed . $IP_hdr->packed . $PDU->packed;

	# create the expected packet
	my $MAC_hdr2 = NF2::Ethernet_hdr->new(DA => $nextHopMAC,
						     SA => $routerMAC0,
						     Ethertype => 0x800
				    		);


	$IP_hdr->ttl($TTL-1);
	$IP_hdr->checksum(0);  # make sure its zero before we calculate it.
	$IP_hdr->checksum($IP_hdr->calc_checksum);

	my $expected_pkt = $MAC_hdr2->packed . $IP_hdr->packed . $PDU->packed;

	# send packet out of eth1->nf2c0 
	nftest_send('eth2', $sent_pkt);
	nftest_expect('eth1', $expected_pkt);
	`usleep 500`;  
}


# send pkt type 3 from eth1 to eth2. loop 20 times. 
for (my $i = 0; $i < 20; $i++)
{
	# set parameters
	my $DA = $routerMAC0;
	my $SA = "aa:bb:cc:dd:ee:ff";
	my $TTL = 64;
        my $PROTO = 0x11; # UDP
	my $DST_IP = "192.168.1.1"; 
	my $SRC_IP = "192.168.0.1";
	my $len = 100;
	my $nextHopMAC = "dd:55:dd:66:dd:77";

	# create mac header
	my $MAC_hdr = NF2::Ethernet_hdr->new(DA => $DA,
						     SA => $SA,
						     Ethertype => 0x800
				    		);

	#create IP header
	my $IP_hdr = NF2::IP_hdr->new(ttl => $TTL,
                                              proto => $PROTO,
					      src_ip => $SRC_IP,
					      dst_ip => $DST_IP,
                                              dgram_len => $len
			    		 );

	$IP_hdr->checksum(0);  # make sure its zero before we calculate it.
	$IP_hdr->checksum($IP_hdr->calc_checksum);

	# create packet filling.... (IP PDU)
	my $PDU = NF2::PDU->new($len - $MAC_hdr->length_in_bytes() - $IP_hdr->length_in_bytes() );
	my $start_val = $MAC_hdr->length_in_bytes() + $IP_hdr->length_in_bytes()+1;
	my @data = ($start_val..$len);
	for (@data) {$_ %= 100}
	$PDU->set_bytes(@data);

	# get packed packet string
	my $sent_pkt = $MAC_hdr->packed . $IP_hdr->packed . $PDU->packed;

	# create the expected packet
	my $MAC_hdr2 = NF2::Ethernet_hdr->new(DA => $nextHopMAC,
						     SA => $routerMAC1,
						     Ethertype => 0x800
				    		);


	$IP_hdr->ttl($TTL-1);
	$IP_hdr->checksum(0);  # make sure its zero before we calculate it.
	$IP_hdr->checksum($IP_hdr->calc_checksum);

	my $expected_pkt = $MAC_hdr2->packed . $IP_hdr->packed . $PDU->packed;

	# send packet out of eth1->nf2c0 
	nftest_send('eth1', $sent_pkt);
	nftest_expect('eth2', $expected_pkt);
  `usleep 500`;
}

# send pkt type 3 from eth2 to eth1. loop 20 times. 
for (my $i = 0; $i < 20; $i++)
{
	# set parameters
	my $DA = $routerMAC1;
	my $SA = "aa:bb:cc:dd:ee:ff";
	my $TTL = 64;
        my $PROTO = 0x11; # UDP
	my $DST_IP = "192.168.2.1"; 
	my $SRC_IP = "192.168.0.1";
	my $len = 100;
	my $nextHopMAC = "dd:55:dd:66:dd:77";

	# create mac header
	my $MAC_hdr = NF2::Ethernet_hdr->new(DA => $DA,
						     SA => $SA,
						     Ethertype => 0x800
				    		);

	#create IP header
	my $IP_hdr = NF2::IP_hdr->new(ttl => $TTL,
                                              proto => $PROTO,
					      src_ip => $SRC_IP,
					      dst_ip => $DST_IP,
                                              dgram => $len
			    		 );

	$IP_hdr->checksum(0);  # make sure its zero before we calculate it.
	$IP_hdr->checksum($IP_hdr->calc_checksum);

	# create packet filling.... (IP PDU)
	my $PDU = NF2::PDU->new($len - $MAC_hdr->length_in_bytes() - $IP_hdr->length_in_bytes() );
	my $start_val = $MAC_hdr->length_in_bytes() + $IP_hdr->length_in_bytes()+1;
	my @data = ($start_val..$len);
	for (@data) {$_ %= 100}
	$PDU->set_bytes(@data);

	# get packed packet string
	my $sent_pkt = $MAC_hdr->packed . $IP_hdr->packed . $PDU->packed;

	# create the expected packet
	my $MAC_hdr2 = NF2::Ethernet_hdr->new(DA => $nextHopMAC,
						     SA => $routerMAC0,
						     Ethertype => 0x800
				    		);


	$IP_hdr->ttl($TTL-1);
	$IP_hdr->checksum(0);  # make sure its zero before we calculate it.
	$IP_hdr->checksum($IP_hdr->calc_checksum);

	my $expected_pkt = $MAC_hdr2->packed . $IP_hdr->packed . $PDU->packed;

	# send packet out of eth1->nf2c0 
	nftest_send('eth2', $sent_pkt);
	nftest_expect('eth1', $expected_pkt);
	`usleep 500`;  
}

# send pkt type 4 from eth1 to eth2. loop 20 times. 
for (my $i = 0; $i < 20; $i++) {
	# set parameters
	my $DA = $routerMAC0;
	my $SA = "aa:bb:cc:dd:ee:ff";
	my $TTL = 64;
	my $proto = 0x06; # tcp
	my $DST_IP = "192.168.1.1"; 
	my $SRC_IP = "192.168.0.1";
	my $nextHopMAC = "dd:55:dd:66:dd:77";
	
	# create mac header
	my $MAC_hdr = NF2::Ethernet_hdr->new(DA => $DA,
					        SA => $SA,
						Ethertype => 0x800
					        );
	
	# create packet filling.... (IP PDU)
	my $PDU = NF2::PDU->new();
	$PDU->set_bytes(@DATA2);
	my $PDU_len = $PDU->length_in_bytes();
	
	#create IP header
	my $IP_hdr = NF2::IP_hdr->new(ttl => $TTL,
	                                proto => $proto,
	                                src_ip => $SRC_IP,
	                                dst_ip => $DST_IP,
					dgram_len => 20 + $PDU_len, # IP hdr is 20 bytes.
	                               );
	
	$IP_hdr->checksum(0);  # make sure its zero before we calculate it.
	$IP_hdr->checksum($IP_hdr->calc_checksum);
	
	# get packed packet string
	my $sent_pkt = $MAC_hdr->packed . $IP_hdr->packed . $PDU->packed;
	
	# create the expected packet
	my $MAC_hdr2 = NF2::Ethernet_hdr->new(DA => $nextHopMAC,
						SA => $routerMAC1,
						Ethertype => 0x800
					    	);
	
	
	$IP_hdr->ttl($TTL-1);
	$IP_hdr->checksum(0);  # make sure its zero before we calculate it.
	$IP_hdr->checksum($IP_hdr->calc_checksum);
	
	my $expected_pkt = $MAC_hdr2->packed . $IP_hdr->packed . $PDU->packed;
	
	# send packet out of eth1->eth2 and nf2c0 (duplicated)
	nftest_send('eth1', $sent_pkt);
	nftest_expect('eth2', $expected_pkt);
	`usleep 500`;
}

# send pkt type 4 from eth2 to eth1. loop for 20 packets. 
for (my $i = 0; $i < 20; $i++)
{
	# set parameters
	my $DA = $routerMAC1;
	my $SA = "aa:bb:cc:dd:ee:ff";
	my $TTL = 64;
	my $proto = 0x06; # tcp
	my $DST_IP = "192.168.2.1"; 
	my $SRC_IP = "192.168.0.1";
	my $nextHopMAC = "dd:55:dd:66:dd:77";

	# create mac header
	my $MAC_hdr = NF2::Ethernet_hdr->new(DA => $DA,
					        SA => $SA,
						Ethertype => 0x800
					        );
	
	# create packet filling.... (IP PDU)
	my $PDU = NF2::PDU->new();
	$PDU->set_bytes(@DATA2);
	my $PDU_len = $PDU->length_in_bytes();
	
	#create IP header
	my $IP_hdr = NF2::IP_hdr->new(ttl => $TTL,
	                                proto => $proto,
	                                src_ip => $SRC_IP,
	                                dst_ip => $DST_IP,
					dgram_len => 20 + $PDU_len, # IP hdr is 20 bytes.
	                               );
	
	$IP_hdr->checksum(0);  # make sure its zero before we calculate it.
	$IP_hdr->checksum($IP_hdr->calc_checksum);
	
	# get packed packet string
	my $sent_pkt = $MAC_hdr->packed . $IP_hdr->packed . $PDU->packed;
	
	# create the expected packet
	my $MAC_hdr2 = NF2::Ethernet_hdr->new(DA => $nextHopMAC,
						SA => $routerMAC0,
						Ethertype => 0x800
					    	);
	
	
	$IP_hdr->ttl($TTL-1);
	$IP_hdr->checksum(0);  # make sure its zero before we calculate it.
	$IP_hdr->checksum($IP_hdr->calc_checksum);
	
	my $expected_pkt = $MAC_hdr2->packed . $IP_hdr->packed . $PDU->packed;

	# send packet out of eth2 -> eth1 & nf2c0 
	nftest_send('eth2', $sent_pkt);
	nftest_expect('eth1', $expected_pkt);
	`usleep 500`;  
}

sleep 1;
my $unmatched_hoh = nftest_finish();
$total_errors += nftest_print_errors($unmatched_hoh);

# Check registers to see how many packets have been forwarded
$temp_error_val += nftest_regread_expect('nf2c0', ROUTER_OP_LUT_NUM_PKTS_FORWARDED_REG, 160);

if ($temp_error_val == 160 && $total_errors == 0) {
  print "SUCCESS!\n";
	exit 0;
}
elsif ($temp_error_val != 160) {
  print "Expected 160 packets forwarded. Forwarded $temp_error_val\n";
	exit 1;
}
else {
	print "Failed: $total_errors $temp_error_val errors\n";	
	exit 1;
}

