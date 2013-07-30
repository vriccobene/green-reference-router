#!/usr/bin/perl
# vim:set shiftwidth=4 softtabstop=4 expandtab:
#
# File: test_get_unix.pl
# Date: 7 July 2009
# Author: Michael Ciesla <mick.ciesla@gmail.com>
#  (based on test_packet_forwarding)
#
# Description
#
#  Verifies that the Unix (TCP hdr = 32B) HTTP GET packets are duplicated. 
#
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

# packet payload - tcp hdr and http get request method
my @TCP_HTTP_GET = (
0xCF, 0xE7, 0x00, 0x50, 0xDF, 0xBE, 0x5E, 0xD5, 0x32, 0xBF, 0x7E, 0x31, 0x80, 0x18, 0xFF, 0xFF,
0xEF, 0xFE, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0A, 0x3A, 0xF6, 0x46, 0xA2, 0x29, 0x19, 0x14, 0x75,
0x47, 0x45, 0x54, 0x20, 0x2F, 0x69, 0x63, 0x6F, 0x6E, 0x73, 0x2F, 0x61, 0x70, 0x61, 0x63, 0x68,
0x65, 0x5F, 0x70, 0x62, 0x32, 0x2E, 0x67, 0x69, 0x66, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2F, 0x31,
0x2E, 0x31, 0x0D, 0x0A, 0x48, 0x6F, 0x73, 0x74, 0x3A, 0x20, 0x6E, 0x66, 0x32, 0x0D, 0x0A, 0x55,
0x73, 0x65, 0x72, 0x2D, 0x41, 0x67, 0x65, 0x6E, 0x74, 0x3A, 0x20, 0x4D, 0x6F, 0x7A, 0x69, 0x6C,
0x6C, 0x61, 0x2F, 0x35, 0x2E, 0x30, 0x20, 0x28, 0x4D, 0x61, 0x63, 0x69, 0x6E, 0x74, 0x6F, 0x73,
0x68, 0x3B, 0x20, 0x55, 0x3B, 0x20, 0x50, 0x50, 0x43, 0x20, 0x4D, 0x61, 0x63, 0x20, 0x4F, 0x53,
0x20, 0x58, 0x20, 0x31, 0x30, 0x2E, 0x35, 0x3B, 0x20, 0x65, 0x6E, 0x2D, 0x55, 0x53, 0x3B, 0x20,
0x72, 0x76, 0x3A, 0x31, 0x2E, 0x39, 0x2E, 0x30, 0x2E, 0x37, 0x29, 0x20, 0x47, 0x65, 0x63, 0x6B,
0x6F, 0x2F, 0x32, 0x30, 0x30, 0x39, 0x30, 0x32, 0x31, 0x39, 0x30, 0x36, 0x20, 0x46, 0x69, 0x72,
0x65, 0x66, 0x6F, 0x78, 0x2F, 0x33, 0x2E, 0x30, 0x2E, 0x37, 0x0D, 0x0A, 0x41, 0x63, 0x63, 0x65,
0x70, 0x74, 0x3A, 0x20, 0x69, 0x6D, 0x61, 0x67, 0x65, 0x2F, 0x70, 0x6E, 0x67, 0x2C, 0x69, 0x6D,
0x61, 0x67, 0x65, 0x2F, 0x2A, 0x3B, 0x71, 0x3D, 0x30, 0x2E, 0x38, 0x2C, 0x2A, 0x2F, 0x2A, 0x3B,
0x71, 0x3D, 0x30, 0x2E, 0x35, 0x0D, 0x0A, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x2D, 0x4C, 0x61,
0x6E, 0x67, 0x75, 0x61, 0x67, 0x65, 0x3A, 0x20, 0x65, 0x6E, 0x2D, 0x75, 0x73, 0x2C, 0x65, 0x6E,
0x3B, 0x71, 0x3D, 0x30, 0x2E, 0x35, 0x0D, 0x0A, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x2D, 0x45,
0x6E, 0x63, 0x6F, 0x64, 0x69, 0x6E, 0x67, 0x3A, 0x20, 0x67, 0x7A, 0x69, 0x70, 0x2C, 0x64, 0x65,
0x66, 0x6C, 0x61, 0x74, 0x65, 0x0D, 0x0A, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x2D, 0x43, 0x68,
0x61, 0x72, 0x73, 0x65, 0x74, 0x3A, 0x20, 0x49, 0x53, 0x4F, 0x2D, 0x38, 0x38, 0x35, 0x39, 0x2D,
0x31, 0x2C, 0x75, 0x74, 0x66, 0x2D, 0x38, 0x3B, 0x71, 0x3D, 0x30, 0x2E, 0x37, 0x2C, 0x2A, 0x3B,
0x71, 0x3D, 0x30, 0x2E, 0x37, 0x0D, 0x0A, 0x4B, 0x65, 0x65, 0x70, 0x2D, 0x41, 0x6C, 0x69, 0x76,
0x65, 0x3A, 0x20, 0x33, 0x30, 0x30, 0x0D, 0x0A, 0x43, 0x6F, 0x6E, 0x6E, 0x65, 0x63, 0x74, 0x69,
0x6F, 0x6E, 0x3A, 0x20, 0x6B, 0x65, 0x65, 0x70, 0x2D, 0x61, 0x6C, 0x69, 0x76, 0x65, 0x0D, 0x0A,
0x52, 0x65, 0x66, 0x65, 0x72, 0x65, 0x72, 0x3A, 0x20, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F,
0x6E, 0x66, 0x32, 0x2F, 0x0D, 0x0A, 0x0D, 0x0A);

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

for (my $i = 0; $i < 20; $i++) {
	# Send HTTP GET packet from eth1 to eth2
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
	$PDU->set_bytes(@TCP_HTTP_GET);
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
	nftest_expect('nf2c0', $expected_pkt);
	`usleep 500`;
}

# loop for 20 packets from eth2 to eth1
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
	$PDU->set_bytes(@TCP_HTTP_GET);
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
	nftest_expect('nf2c0', $expected_pkt);
	`usleep 500`;  
}

sleep 1;
my $unmatched_hoh = nftest_finish();
$total_errors += nftest_print_errors($unmatched_hoh);

# Check registers to see how many packets have been forwarded
$temp_error_val += nftest_regread_expect('nf2c0', ROUTER_OP_LUT_NUM_PKTS_FORWARDED_REG, 40);

if ($temp_error_val == 40 && $total_errors == 0) {
  print "SUCCESS!\n";
	exit 0;
}
elsif ($temp_error_val != 40) {
  print "Expected 40 packets forwarded. Forwarded $temp_error_val\n";
	exit 1;
}
else {
	print "Failed: $total_errors $temp_error_val errors\n";	
	exit 1;
}

