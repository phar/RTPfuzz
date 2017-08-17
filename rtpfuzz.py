from bitstring import BitArray,ConstBitStream
import random
import hexdump
import time
import argparse
import os

max_file_len = 65535

rtp_packet_types = {
	'version':1,
	'padding':1,
	'crsc_count':4,
	'extension':1,
	'marker':1,
	'payload_type':7,
	'sequence_number':16,
	'timev':32,
	'ssrc_id':32,
	'csrc_id':32,
	'extension':16,
	'profile_extension_id':16,
	'extension_header_length':16,
	'payload':-1
}

empty_rtp_template = {
	'version':None,
	'padding':None,
	'extension':None,
	'marker':None,
	'payload_type':None,
	'sequence_number':None,
	'timev':None,
	'ssrc_id':None,
	'csrc_id':[],
	'extension':None,
	'profile_extension_id':None,
	'extension_header_length':None,
	'payload':'*'
}

def RTPPrint(outgoing):
	printstr = "---------------------------------------------------------------------------------------\n"
	printstr +=  "Version:\t%d\n" % outgoing['version']
	printstr += "Padding:\t%d\n" % outgoing['padding']
	printstr += "Extension:\t%d\n" % outgoing['extension']
	printstr += "CRSC Count:\t%d\n" % outgoing['crsc_count']
	printstr += "Marker:\t\t%d\n" % outgoing['marker']
	printstr += "Payload Type:\t%d\n" % outgoing['payload_type']
	printstr += "Sequence:\t%d\n" % outgoing['sequence_number']
	printstr += "Timestamp:\t%d\n" % outgoing['timev']
	printstr += "SSRC ID:\t%d\n" % outgoing['ssrc_id']
	
	printstr += "CSRC IDs:\t%s\n" % outgoing['csrc_id']

	if outgoing['extension']:
		printstr += "Extension ID:\t%d\n" % outgoing['profile_extension_id']
		printstr += "\extension_header_length:\t%d\n" % outgoing['extension_header_length']
		printstr += "\extension_header:\t%d\n" % outgoing['extension_header']

	printstr += "Payload: \n%s\n" % hexdump.hexdump(outgoing['payload'], result='return')
	return printstr


def RTPBuild(outgoing):
	rtp_packet = BitArray()
	rtp_packet += 'uint:2=%d' % outgoing['version']
	rtp_packet += 'uint:1=%d' % outgoing['padding']
	rtp_packet += 'uint:1=%d' % outgoing['extension']
	rtp_packet += 'uint:4=%d' % outgoing['crsc_count']
	rtp_packet += 'uint:1=%d' % outgoing['marker']
	rtp_packet += 'uint:7=%d' % outgoing['payload_type']
	rtp_packet += 'uint:16=%d' % outgoing['sequence_number']
	rtp_packet += 'uint:32=%d' % outgoing['timev']
	rtp_packet += 'uint:32=%d' % outgoing['ssrc_id']
	
	for i in xrange(outgoing['crsc_count']):
		try:
			rtp_packet += 'uint:32=%d' % outgoing['csrc_id'][i]
		except IndexError:
			rtp_packet += 'uint:32=%d' % random.randint(0,0xffffffff) #if we promised the data but dont have it, make it up

	if outgoing['extension']:
		rtp_packet += 'uint:16=%d' % outgoing['profile_extension_id']
		rtp_packet += 'uint:16=%d' % outgoing['extension_header_length']
		for i in xrange(outgoing['crsc_count']):
			rtp_packet += 'uint:32=%d' % outgoing['csrc_id'][i]

	for i in xrange(len(outgoing['payload'])):
		try:
			rtp_packet += 'uint:8=%d' %  outgoing['payload'][i]
		except IndexError:
			pass #just pass this on since missing data here doesnt foul the structure

	return rtp_packet


def RTPParse(incoming):
	rtp_packet = {}
	read_packet = ConstBitStream(bytes=incoming)
	rtp_packet['version']  = read_packet.read('uint:2')
	rtp_packet['padding'] = read_packet.read('uint:1')
	rtp_packet['extension'] = read_packet.read('uint:1')
	rtp_packet['crsc_count']  = read_packet.read('uint:4')
	rtp_packet['marker'] = read_packet.read('uint:1')
	rtp_packet['payload_type']  = read_packet.read('uint:7')
	rtp_packet['sequence_number']  = read_packet.read('uint:16')
	rtp_packet['timev']  = read_packet.read('uint:32')
	rtp_packet['ssrc_id']  = read_packet.read('uint:32')
	rtp_packet['csrc_id'] = []
	for i in xrange(rtp_packet['crsc_count'] ):
		rtp_packet['csrc_id'].append(read_packet.read('uint:32'))
	if rtp_packet['extension']:
		rtp_packet['profile_extension_id']  = read_packet.read('uint:16')
		rtp_packet['extension_header_length'] = read_packet.read('uint:16')
		rtp_packet['extension_header'] = []
		for i in xrange(rtp_packet['extension_header_length'] ):
			rtp_packet['extension_header'].append(read_packet.read('uint:32'))
	rtp_packet['payload'] = read_packet.tobytes()
	return rtp_packet


def RTPFuzz(outgoing, items=3):
	
	for i in xrange(items):
		if random.randint(0,100) < 20: #20 % of the fuzz cases are against the payload not the RTP structure
			fc = random.choice(outgoing.keys())
		else:
			fc = "payload"
		
		if rtp_packet_types[fc] != -1:
			s = ConstBitStream(random.randint(0, 2**32 - 1))
			outgoing[fc] =  s.read('uint:%d' % rtp_packet_types[fc])
		else:
			if(random.randint(0,100) < 5): #5% fo the cases are just random garbage
				outgoing[fc] = os.urandom(random.randint(0,2048))
			else:
				c = random.randint(0,5)
				b = list(outgoing[fc])
				rs =random.randint(0,len(outgoing[fc]))
				if c == 0 :
					b[rs] = chr(0xff)
				elif c == 1:
					b[rs] = chr(0x00)
				elif c == 2:
					b[rs] = chr(random.randint(0,255))
				elif c == 3:
					b[rs] = chr(ord(b[rs]) | 1 << random.randint(0,7))
				elif c == 4:
					b[rs] = chr(ord(b[rs]) ^ 1 << random.randint(0,7))
				elif c == 5:
					b[rs] = chr(ord(b[rs])  & 1 << random.randint(0,7))
				outgoing[fc] = "".join(b)
	return outgoing



parser = argparse.ArgumentParser(description="RTP Fuzzer Tool")

parser = argparse.ArgumentParser()

parser.add_argument("-b","--bind_host", action="store_true", default="0.0.0.0", help="which IP to bind our ports on (0.0.0.0) by default")
parser.add_argument("-r","--host", action="store_true", default="127.0.0.1", help="RTP target host")
parser.add_argument("-p","--port", type=int, default=42010, help="RTP port number to use")
parser.add_argument("-f","--mutate_port", type=int, default=42010, help="port used by legit RTP source")
parser.add_argument("-t","--template", action="store_true", default="rtp_template", help="RTP fuzz template")
parser.add_argument("-m","--mode", default="parse", choices=['proxy', 'template','parse'], help="RTP fuzzer mode")
parser.add_argument("-c","--count", default=1, help="Number of mutations to introduce per message")
parser.add_argument("-d","--delay", default=0, help="Delay seconds before transmitting fuzz packet")

args = parser.parse_args()

if args.mode == 'parse':
	f = open(args.template)
	rtp_template = f.read(max_file_len)
	f.close()
	parsed = RTPParse(rtp_template)
	parsed = RTPFuzz(parsed)
	print RTPPrint(parsed)

elif args.mode == 'proxy':
	sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM) # UDP
	if args.mutate_port == args.port:
		sock.bind((args.bind_host, args))
	else:
		sock.bind((args.port, args))
	print "ready! (ctrl+c to exit)"
	while(1):
		data, addr = sock.recvfrom(max_file_len)
		parsed = RTPParse(data)
		parsed = RTPFuzz(parsed, args.count)
		rebuilt = RTPBuild(parsed)
		time.sleep(args.delay)
		sock.sendto(rebuilt, (args.host, args.port))
		print "Sent:"
		print RTPPrint(RTPParse(rebuilt))

elif args.mode == 'template':
	f = open(args.template)
	rtp_template = f.read(max_file_len)
	f.close()
	parsed = RTPParse(rtp_template)
	print "ready! (ctrl+c to exit)"
	while 1:
		fuzzed = RTPFuzz(parsed, args.count)
		rebuilt = RTPBuild(fuzzed)
		sock.sendto(rebuilt, (args.host, args.port))
		print "Sent:"
		print RTPPrint(RTPParse(rebuilt))
		time.sleep(args.delay)
