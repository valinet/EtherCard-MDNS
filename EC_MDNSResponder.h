/*
 * ENC38J60 Multicast DNS
 * 
 * Copyright (c) 2013, Arno Moonen <info@arnom.nl>
 * Copyright (c) 2013 Tony DiCola (tony@tonydicola.com)
 *
 * This code is based on the CC3000 Multicast DNS library,
 * created by Tony DiCola <tony@tonydicola.com>.
 *
 * This is a simple implementation of multicast DNS query support for an Arduino
 * and ENC28J60 ethernet module. Only support for resolving address queries is
 * currently implemented.
 *
 * Requirements:
 * - EtherCard (with UDP enhancements): https://github.com/itavero/ethercard/tree/enhancements
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

#ifndef EtherCard_MDNS_h
#define EtherCard_MDNS_h

#if ARDUINO >= 100
  #include <Arduino.h> // Arduino 1.0
#else
  #include <WProgram.h> // Arduino 0022
#endif

#include "../EtherCard/src/EtherCard.h"

#define INSTANCE_LENGTH 20
#define SERVICE_LENGTH 30

class EC_MDNSResponder {
	public:
		static uint8_t begin(
			EtherCard& ether,
			const char* szInstance,
			const char* szService,
			uint16_t port,
			uint32_t ttlSeconds = 3600
		);
		// Callback
		static void onUdpReceive(uint8_t dest_ip[4], uint16_t dest_port, uint8_t src_ip[4], uint16_t src_port, const char *data, uint16_t len);

	private:
	
		static EtherCard etherCard;
	
		// Expected query values
		static uint8_t _queryHeader[];
		static uint8_t _queryFQDN[INSTANCE_LENGTH];
		static int _queryFQDNLen;
		static uint8_t _querySN[SERVICE_LENGTH];
		static int _querySNLen;

		// Current parsing state
		static uint8_t* _current;
		static int _currentLen;
		static int _index;
		static uint8_t _FQDNcount;
		static uint32_t _ttlSeconds;
		static uint16_t _port;

		static void changeState(uint8_t* state);
		static void sendResponse(uint8_t type);
};

extern EC_MDNSResponder mdns;

#endif