// 2011-01-30 <jc@wippler.nl> http://opensource.org/licenses/mit-license.php
// 2013-11-03 Arno Moonen <info@arnom.nl>
 
#include <EtherCard.h>
#include <EC_MDNSResponder.h>

#define MDNS_NAME "arduino"
#define ETHER_CS_PIN 10
#define STATIC 0  // set to 1 to disable DHCP (adjust myip/gwip values below)

#if STATIC
// ethernet interface ip address
static byte myip[] = { 192,168,1,200 };
// gateway ip address
static byte gwip[] = { 192,168,1,1 };
#endif

// ethernet mac address - must be unique on your network
static byte mymac[] = { 0x74,0x69,0x69,0x2D,0x30,0x31 };

byte Ethernet::buffer[500]; // tcp/ip send and receive buffer

char page[] PROGMEM =
"HTTP/1.0 503 Service Unavailable\r\n"
"Content-Type: text/html\r\n"
"Retry-After: 600\r\n"
"\r\n"
"<html>"
  "<head><title>"
    "Temporarily Unavailable"
  "</title></head>"
  "<body>"
    "<h3>Service temporarily unavailable</h3>"
    "<p><em>"
      "This Arduino informs you that the main server is offline."
    "</em></p>"
  "</body>"
"</html>"
;

void setup(){
  Serial.begin(57600);
  Serial.println("\n[backSoonMDNS]");
  
  if (ether.begin(sizeof Ethernet::buffer, mymac, ETHER_CS_PIN) == 0) 
    Serial.println( "Failed to access Ethernet controller");
#if STATIC
  ether.staticSetup(myip, gwip);
#else
  if (!ether.dhcpSetup())
    Serial.println("DHCP failed");
#endif

  ether.printIp("IP:  ", ether.myip);
  ether.printIp("GW:  ", ether.gwip);  
  ether.printIp("DNS: ", ether.dnsip);
  
  // Register MDNSResponder
  if(!mdns.begin(MDNS_NAME, ether)) {
    Serial.println("Error settings up MDNS responder");
  } else {
    Serial.print("Listening on ");
    Serial.print(MDNS_NAME);
    Serial.println(".local"); 
  }
}

void loop(){
  // wait for an incoming TCP packet, but ignore its contents
  if (ether.packetLoop(ether.packetReceive())) {
    memcpy_P(ether.tcpOffset(), page, sizeof page);
    ether.httpServerReply(sizeof page - 1);
  }
}