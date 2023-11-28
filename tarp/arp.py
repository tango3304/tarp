# Coding: UTF-8
# Python Version: 3.2 Onwards
from re import compile
from sys import exit, exc_info
from traceback import print_tb, format_exception_only
import socket
from datetime import datetime


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
interface = ''			# Source Interface [送信元インターフェース]

common_source_mac = ''	# Source MACaddress [送信元MACアドレス]
arp_sender_ip = ''		# Source IPaddress [送信元IPアドレス]
arp_target_ip = ''		# Destination IPaddress [宛先IPアドレス]
check_address(common_source_mac, arp_sender_ip, arp_target_ip)


# EthernetII Field Variables [EthernetIIフィールド値]
destination_macaddress = hexadecimal_conversion('ff:ff:ff:ff:ff:ff', 'mac')
source_mac_address = hexadecimal_conversion(common_source_mac, 'mac')
ethII_type = b'\x08\x06'
ethII_data = destination_macaddress + source_mac_address + ethII_type


# ARP Message Variables [ARPメッセージ値]
hardware_type = b'\x00\x01'
protocol_type = b'\x08\x00'
hardware_size = b'\x06'
protocol_size = b'\x04'
operation_code = b'\x00\x01'
sender_mac_address = hexadecimal_conversion(common_source_mac, 'mac')
sender_ip_address = hexadecimal_conversion(arp_sender_ip, 'ip')
target_mac_address = hexadecimal_conversion('00:00:00:00:00:00', 'mac')
target_ip_address = hexadecimal_conversion(arp_target_ip, 'ip')
arp_messages = hardware_type + protocol_type + hardware_size + protocol_size + operation_code + sender_mac_address + sender_ip_address + target_mac_address + target_ip_address


# ARP Packet Variables [ARPパケット値]
arp_packet = ethII_data + arp_messages


# ARP Packet Request Send [ARPパケットリクエスト送信]
with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as arp_socket:
	arp_socket.bind((interface, 0))
	a = datetime.now()
	print(f'\n\n  ARP Request Send Process START')
	arp_socket.send(arp_packet)
	print(f'   ARP Request Send Time: {a}')
	print(f'  ARP Request Send Process END\n\n')
	