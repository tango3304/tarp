# Coding: UTF-8
# Python Version: 3.2 Onwards
# install Module: pip install scapy
from re import compile
from sys import exit, exc_info
from traceback import print_tb, format_exception_only
import socket
from datetime import datetime
from scapy.layers.l2 import Ether
from subprocess import run


def check_address(source_macaddress, source_ipaddress, destination_ipaddress):
	# Check MACaddress [MACアドレス確認]
	# [0-9]: 0,1,2,3,4,5,6,7,8,9
	# [A-F]: ABCDEF
	# [a-f]: abcdef
	check_macaddress = compile(r'^((([0-9]|[A-F]|[a-f]){2}):){5}([0-9]|[A-F]|[a-f]){2}$')
	if check_macaddress.fullmatch(source_macaddress) == None:
		print(f"\n  Invalid MACaddress: {source_macaddress}  [無効なMACアドレス: {source_macaddress}]\n")
		exit(1)
	
	# Check IPaddress [IPアドレス確認]
	#    0-99: [1-9]?[0-9]
	# 100-199: 1[0-9]{2}(1[0-9][0-9])
	# 200-249: 2[0-4][0-9]
	# 250-255: 25[0-5]
	check_ipaddress = compile(r'^(([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$')
	ip_list = source_ipaddress,destination_ipaddress
	for ipaddress in ip_list:
		if check_ipaddress.fullmatch(ipaddress) == None:
			print(f"\n  Invalid IPaddress: {ipaddress}  [無効なIPアドレス: {ipaddress}]\n")
			exit(1)


# MACaddress and IPaddress Convert from ByteType [MACアドレスとIPアドレスをバイト型に変換]
def hexadecimal_conversion(value, protocol):
	try:
	# Initialization Variables [変数初期化]
		bytes_values = b''

	# MACaddress and IPaddress Processing branch [MACアドレスとIPアドレスの処理分岐]
		if protocol == 'mac':
		# Extract Each Delimiter from {:} Convert from StringType → IntegerType → ByteType [ {:}の区切り文字ずつ取り出し、文字列型 → 整数型 → バイト型 に変換]
			for position_value in value.split(':'):
				bytes_values += int(position_value, base=16).to_bytes(1, 'big')
			return bytes_values
		elif protocol == 'ip':
		# Extract Each Delimiter from {:} Convert from StringType → IntegerType → ByteType [ {:}の区切り文字ずつ取り出し、文字列型 → 整数型 → バイト型 に変換]
			for position_value in value.split('.'):
				bytes_values += int(position_value).to_bytes(1, 'big')
			return bytes_values
	except:
	# Get ErrorMessage [エラーメッセージ取得]
		exc_type, exc_message, exc_object = exc_info()
		exc_list = format_exception_only(exc_type, exc_message)
		error_message = ''.join(exc_message for exc_message in exc_list)
		print_tb(exc_object)
		print(f'{error_message}')
		exit(1)


# Initialization Variables [変数初期化]
ETH_P_ALL = 3# ALL Packet receive(0X0003) [全パケットを受信(0X0003)]
SOCKET_RECEIVE_BUFSIZE = 4096

interface = ''		# Source Interface [送信元インターフェース]

common_source_mac = ''	# Source MACaddress [送信元MACアドレス]
arp_sender_ip = ''	# Source IPaddress [送信元IPアドレス]
arp_target_ip = ''	# Destination IPaddress [宛先IPアドレス]
check_address(common_source_mac, arp_sender_ip, arp_target_ip)


# EthernetII Field Variables [EthernetIIフィールド値]
DESTINATION_MAC_ADDRESS = hexadecimal_conversion('ff:ff:ff:ff:ff:ff', 'mac')
source_mac_address = hexadecimal_conversion(common_source_mac, 'mac')
ETHII_TYPE = b'\x08\x06'
ethII_data = DESTINATION_MAC_ADDRESS + source_mac_address + ETHII_TYPE


# ARP Message Variables [ARPメッセージ値]
HARDWARE_TYPE = b'\x00\x01'
PROTOCOL_TYPE = b'\x08\x00'
HARDWARE_SIZE = b'\x06'
PROTOCOL_SIZE = b'\x04'
OPERATION_CODE = b'\x00\x01'
sender_mac_address = hexadecimal_conversion(common_source_mac, 'mac')
sender_ip_address = hexadecimal_conversion(arp_sender_ip, 'ip')
TARGET_MAC_ADDRESS = hexadecimal_conversion('00:00:00:00:00:00', 'mac')
target_ip_address = hexadecimal_conversion(arp_target_ip, 'ip')
arp_messages = HARDWARE_TYPE + PROTOCOL_TYPE + HARDWARE_SIZE + PROTOCOL_SIZE + OPERATION_CODE + sender_mac_address + sender_ip_address + TARGET_MAC_ADDRESS + target_ip_address


# ARP Packet Variables [ARPパケット値]
arp_request_packet = ethII_data + arp_messages


# ARP Table Confirmation [ARPテーブルを確認]
before_arp_table_confirmation_time = datetime.now()
print(f'\n\n ARP Table Confirmation: {before_arp_table_confirmation_time}  (Target:{arp_target_ip})')
run(['arp', '-a', arp_target_ip])

# ARP Packet Request Send [ARPパケットリクエスト送信]
with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL)) as arp_socket:
	arp_socket.bind((interface, 0))

# ARP Request Packet Send [ARP要求パケット送信]
	arp_socket.send(arp_request_packet)
	send_time = datetime.now()
	print(f'\n\n ARP Request Send Time: {send_time}')
	Ether(arp_request_packet).show()

# ARP Response Packet Receive [ARP応答パケット受信]
	arp_response_packet = arp_socket.recv(SOCKET_RECEIVE_BUFSIZE)
	receive_time = datetime.now()
	print(f'\n ARP Respons Receive Time: {receive_time}')
	Ether(arp_response_packet).show()



# ARP Table Write [ARPテーブルに書き込む]
arp_hwdst = Ether(arp_response_packet).hwdst
run(['arp', '-i', interface, '-s', arp_target_ip, arp_hwdst])
arp_table_write_time = datetime.now()
print(f'\n ARP Table Write:        {arp_table_write_time}')

after_arp_table_confirmation_time = datetime.now()
print(f'\n ARP Table Confirmation: {after_arp_table_confirmation_time}  (Target:{arp_target_ip})')
run(['arp', '-a', arp_target_ip])
print()
