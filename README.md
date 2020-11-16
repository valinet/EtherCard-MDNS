EtherCard-MDNS
======================

EtherCard-MDNS is a library that provides mDNS and DNS-SD capabilities for the EtherCard library that enables the usage of the ENC28J60 module on Arduino.

This library provides the following features:

* Support for resolving .local address queries
* Support for advertising a DNS-SD service
* Support for advertising a DNS-SD instance.
* Support for advertising presence when all DNS-SD devices are queried for presence.

This is the currrent and enhanced version of the original [EtherCard-MDNS](https://github.com/itavero/EtherCard-MDNS) library.

This library uses code from the [CC3000 Multicast DNS](https://github.com/adafruit/CC3000_MDNS) library, originally created by Tony DiCola.

Usage
-----
This library requires a slightly patched version of the EtherCard library that has a few UDP enhancements. At the moment, this modifications are not upstreamed, so you can find a forked EtherCard version that implements these at https://github.com/valinet/EtherCard.

To make use of the library, simply add a call like the following after you obtain an IP address for EtherCard:

```c
byte rv = mdns.begin(
    ether, 
    instance,
    service,
    servicePort,
    ttl
);
if (rv) {
    Serial.print("MDNS initialization failed with error code: ");
    Serial.println(rv);
} else {
    Serial.println("MDNS initialization succeded.");
}
```

The parameters for the begin function represent the following:

* ether - pointer to the EtherCard instance
* instance - name of the instance for this service; *instance*.local will resolve to the IP address of EtherCard if a resolver capable of mDNS is available on the client OS
* service - name of service advertised via DNS-SD; this has to be a pair of DNS labels, each beginning with an underscore; the second label usually denotes the protocol used by the application, so set it to either *\_tcp*, either *\_udp*; an example valid name is *\_workstation.\_tcp*.
* servicePort - this has to be set to the port on which the application is running
* ttl - this is optional and allows specifying a time to live for the advertisment packets, basically how long can they exist in the client's cache

The instance and service names are stored in variables whose dimensions are allocated very conservatively in order to spare dynamic memory. If you want to use longer names, make sure to change the defines responsible for these in the source code.

There is an example provided that can help you get started. For more comprehensive usage, check my homepi project: https://github.com/valinet/homepi-plus.

License
-------
Just like the original library by Tony DiCola, this library is released under a MIT license.