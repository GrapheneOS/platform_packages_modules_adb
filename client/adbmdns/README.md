# LibAdbMdns

## Why libadbmdns exists
ADB team has tried to use several mdns libraries on host. All of them lead to issues.

### Bonjour
We tried to use `Bonjour` but the architecture where adb shipped with the client
whereas Macos shipped with the daemon resulted in breakages due to version discrepancies.

Apple does not accept bug fixes which lead to us maintaining a fork which became increasingly
impossible to merge with upstream over the years.

We found the code to be spaghetti flavored, with very difficult to understand logic, "temporary fixes",
and workarounds leading to very hard debugging.

This also required users to install Bonjour for non-Apple OSes.

### Openscreen
We tried to use `openscreen` but we encountered several issues.

The development being primarely driven by Chromecast needs it was hard to engage developers
to help us with bugs fixing.

Some bugs occurred only in google3 because of special hardware in our datacenters that
Chromecast devices never encountered.

The volume of code to assimilate was also huge which, once again, made bug fixing very
hard. `openscreen` comes with dependencies totalling 540,000 lines (`openscreen` = 380,000,
`absl` = 160,000 ) of code whereas all of `adb` (including `adbd`) is 30,000 lines of code.

### Client to OS daemon
We never tried to have an OS specific relying on a client contacting the daemon usually
present (Avahi on Linux, Bonjour on Macos, and nameless on Windows). The reasons were that
we could not be sure a daemon was indeed running and an OS update could break us (or be
incompatible with our client version).

After much consideration, we decided that adb actually needed very little of mDNS. That
is, it only needs to be able to query for services to make ADB Wifi work. This resulted in
`libadbmdns` which is a partial implementation of RFC 6762. Only the service query part
without the publishing part.

## Architecture

`libadbmdn` is built around a core and a driver.

- The core (ZeroConfig) is where all the
intelligence is. It receives packets and the time from the driver (ZeroConfigDriver). From
these inputs, if infers the state of services (create, modify, delete), sends commands to
the driver to interact with the network/adb.
- The driver (ZeroConfigDriver) is the interface to the outside world. It handles opening sockets
- to interfaces, receiving packets, and executing commands from the core.

```
                            ┌────────────────┐                                       
                            │                │                                       
                            │     NETWORK    │                                       
                            │                │                                       
                            │   INTERFACES   │                                       
                            │                │                                       
                            └─────┬─────▲────┘                                       
                                  │     │                                            
                                  │     │                                            
                                  │     │                                            
                                  │     │                                            
  ┌─────┐     ┌────────┐    ┌─────▼─────┴────┐   packets + time   ┌────────────────┐ 
  │     │     │        │    │                ├────────────────────►                │ 
  │ ADB ├─────► BRIDGE ├────►     DRIVER     │                    │      CORE      │ 
  │     │     │        │    │                │                    │                │ 
  │     ◄─────┼ Rust/C ◄────┼ZeroConfigDriver│   commands         │   ZeroConfig   │ 
  │     │     │        │    │                ◄────────────────────┼                │ 
  └─────┘     └────────┘    └────────────────┘                    └────────────────┘ 
                                                                                     
```

This architecture enables better testing. By injecting synthetic packets
into the core, virtualizing its time tracking, and analyzing output commands, we can better test
it.