ENC28J60 Multicast DNS
======================

This library uses code from the [CC3000 Multicast DNS](https://github.com/adafruit/CC3000_MDNS)
library, originally created by Tony DiCola.

This is a simple implementation of multicast DNS query support for an Arduino and ENC28J60
ethernet module. Only support for resolving address queries is currently implemented.

Usage
-----
To use this library, you must use a version of the EtherCard library that includes [my UDP
enhancements](https://github.com/itavero/ethercard/tree/enhancements). So be sure that add
that library as well as this one to your Arduino IDE.

After that it's as easy as including both libraries and adding the following code to the
bottom of your `setup()` method (or at least after you have  acquired an IP address):
````cpp
if(!mdns.begin("some-name", ether)) {
    Serial.println("Error settings up MDNS responder");
} else {
	Serial.print("Listening on some-name.local");
}
````
Note: the second argument (`ether`) refers to an instance of EtherCard.
Optionally, you can supply the TTL as a third argument to `mdns.begin`.

Be sure to also have a look at the example I've included.

License
-------
Just like the original library by Tony DiCola, this library is released under a
MIT license.