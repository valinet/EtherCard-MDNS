/*
 * EtherCard-MDNS
 * 
 * Copyright (c) 2013 Arno Moonen <info@arnom.nl>
 * Copyright (c) 2013 Tony DiCola (tony@tonydicola.com)
 * Copyright (c) 2020 Valentin-Gabriel Radu <valentingabrielradu@gmail.com>
 *
 * This code is based on the CC3000 Multicast DNS library,
 * created by Tony DiCola <tony@tonydicola.com>.
 *
 * This code is based on the original EtherCard-MDNS library,
 * created by Arno Moonen <arno@moonen.xyz>.
 *
 * Project details: https://github.com/valinet/EtherCard-MDNS
 *
 * License (MIT license):
 *   Permission is hereby granted, free of charge, to any person obtaining a copy
 *   of this software and associated documentation files (the "Software"), to deal
 *   in the Software without restriction, including without limitation the rights
 *   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *   copies of the Software, and to permit persons to whom the Software is
 *   furnished to do so, subject to the following conditions:
 * 
 *   The above copyright notice and this permission notice shall be included in
 *   all copies or substantial portions of the Software.
 *   
 *   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 *   THE SOFTWARE.
 */
//#define MDNS_DEBUG
//#define SEND_SOA_ON_AAAA_ERROR
//#define SEND_NSEC_WITH_A_RECORD
#define TYPE_A 1
#define TYPE_AAAA 28
#define TYPE_PTR 12
#define TYPE_TXT 16
#define TYPE_SRV 33
#define TYPE_SOA 6

#define RESPONSE_DOMAIN_LOCAL TYPE_A
#define RESPONSE_SERVICES_QUERY 120
#define RESPONSE_SERVICE_INSTANCE 121
#define RESPONSE_SERVICE_SRV TYPE_SRV
#define RESPONSE_SERVICE_TXT TYPE_TXT

#include "EC_MDNSResponder.h"

#define MDNS_ADDR {224, 0, 0, 251}
#define MDNS_PORT 5353
#define HEADER_SIZE 12
#define QDCOUNT_OFFSET 4
#define A_RECORD_SIZE 14
#define NSEC_RECORD_SIZE 20
#define TTL_OFFSET 4
#define IP_OFFSET 10


uint8_t EC_MDNSResponder::_queryFQDN[INSTANCE_LENGTH];
int EC_MDNSResponder::_queryFQDNLen = 0;
uint8_t EC_MDNSResponder::_querySN[SERVICE_LENGTH];
int EC_MDNSResponder::_querySNLen = 0;

uint8_t* EC_MDNSResponder::_current = NULL;
int EC_MDNSResponder::_currentLen = 0;
int EC_MDNSResponder::_index = 0;
uint8_t EC_MDNSResponder::_FQDNcount = 0;
uint32_t EC_MDNSResponder::_ttlSeconds = 0;
uint16_t EC_MDNSResponder::_port = 80;

const uint8_t dip[] = MDNS_ADDR;

const char service_type_enumeration_P[] PROGMEM = {
	9, '_', 's', 'e', 'r', 'v', 'i', 'c', 'e', 's',
	7, '_', 'd', 'n', 's', '-', 's', 'd',
	4, '_', 'u', 'd', 'p',
	5, 'l', 'o', 'c', 'a', 'l',
	0
};

#ifdef SEND_SOA_ON_AAAA_ERROR
const uint8_t soaAAAA[] PROGMEM = 
{
	0xc0, 0x0c, 				// pointer to previous name
	0x00, 0x06, 				// type = SOA
	0x00, 0x01, 				// class = Internet
	0x00, 0xff, 0xff, 0xff, 	// TTL
	0x00, 0x18, 				// data length
	0xc0, 0x0c, 				// mname pointer
	0xc0, 0x0c, 				// rname pointer
	0x00, 0x00, 0x00, 0x01, 	// serial
	0x00, 0xff, 0xff, 0xff, 	// refresh
	0x00, 0x00, 0x00, 0x00, 	// retry
	0x00, 0xff, 0xff, 0xff, 	// expire
	0x00, 0xff, 0xff, 0xff  	// minimum
};
#endif

#ifdef SEND_NSEC_WITH_A_RECORD
const uint8_t nsecRecord[] PROGMEM = 
{  
	0xC0, 0x0C,                	// Name offset
	0x00, 0x2F,                	// Type = 47, NSEC (overloaded by MDNS)
	0x80, 0x01,                	// Class = Internet, with cache flush bit
	0x00, 0x00, 0x00, 0x00,    	// TTL in seconds, to be filled in later
	0x00, 0x08,                	// Length of record
	0xC0, 0x0C,                	// Next domain = offset to FQDN
	0x00,                      	// Block number = 0
	0x04,                      	// Length of bitmap = 4 bytes
	0x40, 0x00, 0x00, 0x00     	// Bitmap value = Only first bit (A record/IPV4) is set
};
#endif

uint8_t EC_MDNSResponder::begin(
	EtherCard& ether,
	const char* szInstance,
	const char* szService,
	uint16_t port,
	uint32_t ttlSeconds
)
{
	_port = port;
	_ttlSeconds = ttlSeconds;
	etherCard = ether;
	uint8_t n = 0;
	
	// Construct names
	
	
	// _queryFQDN (_queryFQDNLen) represents:
	// * the instance name of this service (e.g. <homepi>._workstation._tcp)
	// * the local domain name of this service (e.g. <homepi>.local)
	n = strlen(szInstance);
	if (n > sizeof(uint8_t) * 255) 
	{
		return 1;
	}
	// 8 = sizeof(byte specifing domain length) + // = 1
	//     sizeof(byte specifing local suffix length) + // = 1
	//     strlen("local") + // 5
	//     sizeof(null terminator) // = 1
	_queryFQDNLen = 8 + n;
	// Populate instance name like this:
	// first char means number of bytes, second means type of data
	//
	// 1.d.domain_length : ?.c.domain_characters : 1.d.5 : 5.c.'local' : 1:c:0
	_queryFQDN[0] = (uint8_t)n;
	for (uint8_t i = 0; i < n; ++i) {
		_queryFQDN[1 + i] = tolower(szInstance[i]);
	}
	_queryFQDN[1 + n + 0] = 5;
	_queryFQDN[1 + n + 1] = 'l';
	_queryFQDN[1 + n + 2] = 'o';
	_queryFQDN[1 + n + 3] = 'c';
	_queryFQDN[1 + n + 4] = 'a';
	_queryFQDN[1 + n + 5] = 'l';
	_queryFQDN[1 + n + 6] = 0;
#ifdef MDNS_DEBUG
	Serial.print("Instance:");
	for (uint8_t i = 0; i < _queryFQDNLen; ++i)
	{
		Serial.print(" 0x");
		Serial.print((uint8_t)_queryFQDN[i], HEX);
	}
	Serial.print("\n");
#endif


	// _querySN (_querySNLen) represents:
	// * the service name of this service (e.g. homepi.<_workstation._tcp>.local)
	n = strlen(szService);
	if (n > sizeof(uint8_t) * 255 * 2 + 1)
	{
		return 2;
	}
	memcpy(_querySN + 1, szService, n);
	// check if the service name includes a dot so that the expected
	// format is validated
	uint8_t* pSeparator = (uint8_t*)strchr((char*)_querySN + 1, '.');
	if (!pSeparator)
	{
		return 3;
	}
	_querySN[0] = pSeparator - _querySN - 1;
	pSeparator[0] = (_querySN + n - pSeparator);
	_querySN[1 + n + 0] = 5;
	_querySN[1 + n + 1] = 'l';
	_querySN[1 + n + 2] = 'o';
	_querySN[1 + n + 3] = 'c';
	_querySN[1 + n + 4] = 'a';
	_querySN[1 + n + 5] = 'l';
	_querySN[1 + n + 6] = 0;
	_querySNLen = n + 8;
#ifdef MDNS_DEBUG
	Serial.print("Service: ");
	for (uint8_t i = 0; i < _querySNLen; ++i)
	{
		Serial.print(" 0x");
		Serial.println((uint8_t)_querySN[i], HEX);
	}
	Serial.print("\n");
#endif


	// Register callback with EtherCard instance
	ether.disableMulticast(); // Disable multicast filter (necessary)
	uint8_t addr[4] = MDNS_ADDR;
	ether.udpServerListen(
		onUdpReceive, 
		addr, 
		MDNS_PORT, 
		false
	);

	return 0;
}

void EC_MDNSResponder::onUdpReceive(
	uint8_t dest_ip[IP_LEN], 
	uint16_t dest_port, 
	uint8_t src_ip[IP_LEN], 
	uint16_t src_port, 
	const char *data, 
	uint16_t len
)
{
	// we expect DNS packet to be at least this long
	if (len < HEADER_SIZE)
	{
		return;
	}
	// filter out almost all uninteresting DNS packets
	if (
		data[2] & 0b11111011 || // QR == 0, Opcode == 0, TC == 0, RD == 0
		data[4] || !data[5] || 					   	      // QDCOUNT != 0
		data[6] || data[7] ||      					      // ANCOUNT == 0
		data[8] || data[9]         					      // NSCOUNT == 0
	)
	{
		return;
	}
	// obtain end of name label
	uint8_t length = 0;
	while (length < len - HEADER_SIZE)
	{
		if (!data[length + HEADER_SIZE])
		{
			break;
		}
		length++;
	}
	length += 2;
	if (length > len)
	{
		return;
	}
	uint8_t id0 = data[0];
	uint8_t id1 = data[1];
	// compare name label to expected labels
	const char* name = data + HEADER_SIZE;
	uint8_t type = (uint8_t)*(name + length);
	if (type == TYPE_A && !strcmp(name, (char*)_queryFQDN))
	{
		sendResponse(RESPONSE_DOMAIN_LOCAL, id0, id1);
	}
	else if (type == TYPE_PTR && !strcmp_P(name, service_type_enumeration_P))
	{
		sendResponse(RESPONSE_SERVICES_QUERY, id0, id1);
	}
	else if (type == TYPE_PTR && !strcmp(name, (char*)_querySN))
	{
		sendResponse(RESPONSE_SERVICE_INSTANCE, id0, id1);
	}
	else if (type == TYPE_SRV || type == TYPE_TXT)
	{
		if (
			!strncmp(name, (char*)_queryFQDN, _queryFQDNLen - 7) &&
			!strcmp(name + _queryFQDNLen - 7, (char*)_querySN)
		)
		{
			sendResponse(type, id0, id1);
		}
	}
	#ifdef SEND_SOA_ON_AAAA_ERROR
	else if (type == TYPE_AAAA && !strcmp(name, (char*)_queryFQDN))
	{
		// for requests of IPv6 address, we return back the query
		// and an additional SOA RR where we try to force the client
		// to cache the reply for as long as possible to avoid
		// future unnecessary queries
		ether.udpPrepare(MDNS_PORT, dip, MDNS_PORT);
		char* _response = (char*)ether.buffer + UDP_DATA_P;
		_response[2] |= (1 << 7); // set QR to response
		_response[9] = 0x1; // 1 authority RR
		memcpy_P(
			_response + len,
			soaAAAA,
			sizeof(soaAAAA)
		);
		ether.udpTransmit(len + sizeof(soaAAAA));
	}
	#endif
	//Serial.println(type);
}

void EC_MDNSResponder::sendResponse(
	uint8_t type,
	uint8_t id0,
	uint8_t id1
) {
	unsigned int _responseLen = 0;
	char* records = NULL;
	uint8_t ttl[4] = { (uint8_t)(_ttlSeconds >> 24), (uint8_t)(_ttlSeconds >> 16), (uint8_t)(_ttlSeconds >> 8), (uint8_t)_ttlSeconds };

	if (type == RESPONSE_DOMAIN_LOCAL)
	{
#ifdef MDNS_DEBUG
		Serial.println("Requesting .local domain info.");
#endif
		_responseLen = 
			HEADER_SIZE + 
			_queryFQDNLen + 
			A_RECORD_SIZE;
#ifdef SEND_NSEC_WITH_A_RECORD
		_responseLen += NSEC_RECORD_SIZE;
#endif
	}
	else if (type == RESPONSE_SERVICES_QUERY)
	{
#ifdef MDNS_DEBUG
		Serial.println("Requesting all services.");
#endif
		_responseLen = 
			HEADER_SIZE + 
			sizeof(service_type_enumeration_P) +
			IP_OFFSET +
			_querySNLen;
	}
	else if (type == RESPONSE_SERVICE_INSTANCE)
	{
#ifdef MDNS_DEBUG
		Serial.println("Requesting instance of registered service.");
#endif
		_responseLen =
			HEADER_SIZE + 
			_querySNLen +
			IP_OFFSET +
			_queryFQDNLen - 7 + // remove .local from this
			_querySNLen;
	}
	else if (type == RESPONSE_SERVICE_SRV)
	{
#ifdef MDNS_DEBUG
		Serial.println("Requesting SRV of instance.");
#endif
		_responseLen =
			HEADER_SIZE +
			_queryFQDNLen - 7 + // remove .local from this
			_querySNLen +
			IP_OFFSET +
			2 + // Priority
			2 + // Weight
			2 + // Port number
			_queryFQDNLen;
	}
	else if (type == RESPONSE_SERVICE_TXT)
	{
#ifdef MDNS_DEBUG
		Serial.println("Requesting TXT of instance.");
#endif
		_responseLen =
			HEADER_SIZE +
			_queryFQDNLen - 7 +
			_querySNLen +
			IP_OFFSET +
			_queryFQDNLen - 1;
	}
	
	// Prepare library
	ether.udpPrepare(MDNS_PORT, dip, MDNS_PORT);
	char* _response = (char*)ether.buffer + UDP_DATA_P;

	// Copy header in response
	memset(_response, 0, HEADER_SIZE);
	_response[0] = id0; // keep ID the same as request
	_response[1] = id1;
	_response[2] = 0x84; // authoritative answer
	_response[7] = 0x1; // 1 answer
	
	
	if (type == RESPONSE_DOMAIN_LOCAL)
	{
#ifdef SEND_NSEC_WITH_A_RECORD
		// Increase header additional records with 1.
		_response[11]++;
#endif
		// Copy owner name
		memcpy(
			_response + HEADER_SIZE, 
			_queryFQDN, 
			_queryFQDNLen
		);
		// Pointer to remaining of record(s)
		records = _response + HEADER_SIZE + _queryFQDNLen;
		
		// Zeroize RR
		memset(records, 0, IP_OFFSET);
		
		// Set class to Internet, with flush bit
		*(records + 2) = 0x80;
		*(records + 3) = 0x01;
		
		// Change record type
		*(records + 1) = 0x01;
		
		// Change length
		*(records + 9) = 0x04;
		
		// Copy NSEC record struct
#ifdef SEND_NSEC_WITH_A_RECORD
		memcpy_P(
			records + A_RECORD_SIZE, 
			nsecRecord, 
			NSEC_RECORD_SIZE
		);
#endif
		// Add TTL to records.
		memcpy(
			records + TTL_OFFSET, 
			ttl, 
			4
		);
		memcpy(
			records + A_RECORD_SIZE + 2 + TTL_OFFSET, 
			ttl, 
			4
		);
		// Add IPv4 address to response
		for(byte z = 0; z < 4; z++) {
			records[IP_OFFSET + z] = ether.myip[z];
		}
	}
	else if (
		type == RESPONSE_SERVICES_QUERY || 
		type == RESPONSE_SERVICE_INSTANCE ||
		type == RESPONSE_SERVICE_SRV ||
		type == RESPONSE_SERVICE_TXT
	)
	{
		// Pointer to remaining of record(s)
		records = _response + HEADER_SIZE;
		// Copy owner name
		if (type == RESPONSE_SERVICES_QUERY)
		{
			memcpy_P(
				_response + HEADER_SIZE, 
				service_type_enumeration_P, 
				sizeof(service_type_enumeration_P)
			);
			records += sizeof(service_type_enumeration_P);
		}
		else if (type == RESPONSE_SERVICE_INSTANCE)
		{
			memcpy(
				_response + HEADER_SIZE, 
				_querySN, 
				_querySNLen
			);
			records += _querySNLen;
		}
		else if (type == RESPONSE_SERVICE_SRV || type == RESPONSE_SERVICE_TXT)
		{
			memcpy(
				_response + HEADER_SIZE,
				_queryFQDN,
				_queryFQDNLen - 7
			);
			memcpy(
				_response + HEADER_SIZE + _queryFQDNLen - 7,
				_querySN,
				_querySNLen
			);
			records = _response + HEADER_SIZE + _queryFQDNLen - 7 + _querySNLen;
		}
		
		// Zeroize RR
		memset(records, 0, IP_OFFSET);
		
		// Set class to Internet, with flush bit
		*(records + 2) = 0x80;
		*(records + 3) = 0x01;

		// Change record type
		if (
			type == RESPONSE_SERVICES_QUERY || 
			type == RESPONSE_SERVICE_INSTANCE
		)
		{
			*(records + 1) = TYPE_PTR;
		}
		else if (type == RESPONSE_SERVICE_SRV)
		{
			*(records + 1) = TYPE_SRV;
		}
		else if (type == RESPONSE_SERVICE_TXT)
		{
			*(records + 1) = TYPE_TXT;
		}
		
		// Add TTL to record
		memcpy(
			records + TTL_OFFSET, 
			ttl, 
			4
		);
		
		if (type == RESPONSE_SERVICES_QUERY)
		{
			// Change length
			*(records + 9) = (char)_querySNLen;

			// Copy PTR data
			memcpy(
				records + IP_OFFSET,
				_querySN,
				_querySNLen
			);
		}
		else if (type == RESPONSE_SERVICE_INSTANCE)
		{
			// Change length
			*(records + 9) = (char)(_queryFQDNLen - 7 + _querySNLen);

			// Copy PTR data
			memcpy(
				records + IP_OFFSET,
				_queryFQDN,
				_queryFQDNLen - 7
			);
			memcpy(
				records + IP_OFFSET + _queryFQDNLen - 7,
				_querySN,
				_querySNLen
			);
		}
		else if (type == RESPONSE_SERVICE_SRV)
		{
			// Change length
			*(records + 9) = (char)(_queryFQDNLen + 2 + 2 + 2);
			
			// Set port of service
			*(records + 15) = _port & 0xff;
			*(records + 14) = (_port >> 8);
			
			// Copy SRV data
			memcpy(
				records + 16,
				_queryFQDN,
				_queryFQDNLen
			);
		}
		else if (type == RESPONSE_SERVICE_TXT)
		{
			// Change length
			*(records + 9) = (char)_queryFQDNLen - 1;
			
			uint8_t dot = _queryFQDN[0];
			memcpy(
				records + IP_OFFSET,
				_queryFQDN + 1,
				_queryFQDNLen - 1
			);
			records[dot] = '.';
		}
	}
	
	// Off it goes
	ether.udpTransmit(_responseLen);
}