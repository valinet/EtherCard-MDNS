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
    ttl,
    txtData,
    txtData_P,
    txtDataLength
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
* ttl - *OPTIONAL*: allows specifying a time to live for the advertisment packets, basically how long can they exist in the client's cache
* txtData - *OPTIONAL*: a string of characters that will be sent as the data in the TXT record
* txtData_P - *OPTIONAL*: a string of characters from the program memory that will be sent as the data in the TXT record
* txtDataLen - *OPTIONAL*: the number of characters in txtData or txtData_P

Regarding the txtData* members, these allow specifying additional data that will be broadcasted when the TXT record is requested. The data can either be in RAM or program memory, you specify this by populating either of the two members with a pointer to the data and setting the other to 0 (NULL). Then, in txtDataLength, you have to specify the length of this data. If you are specifying data in RAM, you can use ``strlen`` to determine the length; if you are specifying data in program memory, use ``sizeof``. The data is made of pairs of printable US ASCII (0x20-0x7E) values, excluding '=', separated by the '=' and prefixed by the length of the pair. Here is how the data should look (both have a length of 10):

```c
const char TXTARGS[] = {3, 'a', '=', 'b', 5, 'x', 'y', '=', 't', 'z'}; // or
const char TXTARGS_P[] PROGMEM = {3, 'a', '=', 'b', 5, 'x', 'y', '=', 't', 'z'};
```

Do not specify both txtData, and txtData_P. In this unsupported case, the length will represent the length of txtData, and txtData will get sent.

These members are public, so you can set them anytime during the lifetime of the program. New TXT records that get to be sent will contain the newly set data.

The instance and service names are stored in variables whose dimensions are allocated very conservatively in order to spare dynamic memory. If you want to use longer names, make sure to change the defines responsible for these in the source code.

There is an example provided that can help you get started. For more comprehensive usage, check my homepi project: https://github.com/valinet/homepi-plus.

To view (and debug) mDNS and DNS-SD, you can use the following utilities:

* [avahi](https://www.avahi.org/) (specifically, the avahi-browse utility) on GNU/Linux
* [zeroconfServiceBrowser](https://www.tobias-erichsen.de/software/zeroconfservicebrowser.html) on Microsoft Windows
* [Discovery - DNS-SD Browser](https://apps.apple.com/us/app/discovery-dns-sd-browser/id305441017) on iOS
* [Service Browser](https://play.google.com/store/apps/details?id=com.druk.servicebrowser&hl=en_US&gl=US) on Android
* Also, VERY useful for inspecting the packets, the excellent [Wireshark](https://www.wireshark.org/)

License
-------
Just like the original library by Tony DiCola, this library is released under a MIT license.