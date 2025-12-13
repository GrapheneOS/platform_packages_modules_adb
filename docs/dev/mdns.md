# mdns 101

Since we made the choice of writing our own mdns client (after a long history of problems with mdnsResponder and
openscreen), the least we can do is to write something to help adb maintainer ramp up on how mDNS works.

## DNS Packets

ADB only cares about listening for published services and probing them when they are about to expire. It deals with
packets containing Resource Records (RR). There are five types of RR which form a graph to describe the services
published by an Android device.

```
PTR
  name   : _adb-tls-connect._tcp.local:
  pointer: adb-43081FDAS000ST-XKzA7F._adb-tls-connect._tcp.local
```

```
A
  name: Android_GA59MQ48.local:
  addr: 192.168.86.43
```

```
AAAA
  name: Android_GA59MQ48.local:
  addr: fd37:4d9f:8983:3c54:d452:7fff:feb2:5e2
```

```
SRV
  name  : adb-43081FDAS000ST-XKzA7F._adb-tls-connect._tcp.local
  port  : 37539
  target: Android_GA59MQ48.local
```

```
TXT
  name      : adb-43081FDAS000ST-XKzA7F._adb-tls-connect._tcp.local
  attributes: <list of size prefixed key/value>
```

## Service creation

With the packets above, libadbmdns can surface to adb that service type `_adb-tls-connect._tcp` is available at ips
`192.168.86.43`/`fd37:4d9f:8983:3c54:d452:7fff:feb2:5e2` on port `37539`.

## Service deletion

There are two ways a service can "go away".

### Expiration
Each RR is tagged with a Time To Live. Usually RRs use 120s (2mn) while the PTR uses 4500s (1h15mn). Part of the mDNS
specs mandates to probe when a record is about to expire. If the device is still there, it will reponds to the probe
and libadbmdns will updates the TTLS. If the device or its services are gone, the RR will expire.

### Graceful shutdown
If a service is shutdown, the mDNS published on the device will send a "Good Bye" RR which is typically a PTR with a
TTL set to zero which will cause the RR to be deleted and the service to be considered expired.

