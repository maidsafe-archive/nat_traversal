# NAT Traversal - Change Log

## [0.3.4]
- Increase the hole punch timeout to 60 seconds.

## [0.3.3]
- Tcp mapping and punching functions time-out eagerly

## [0.3.2]
- TCP rendezvous fixes
- Windows fixes

## [0.3.1]
- Export the following symbols: `new_reusably_bound_tcp_socket`,
  `MappedTcpSocketMapError`, `MappedTcpSocketMapWarning`,
  `MappedTcpSocketNewError`, `NewReusablyBoundTcpSocketError`,
  `TcpPunchHoleWarning`, `TcpPunchHoleError`

## [0.3.0]
- Change Simple{Tcp,Udp}HolePunchServer to use `AsRef`

## [0.2.1]
- Better interoperability with `io::Error`

## [0.2.0]
- Implemented TCP hole punching
- Replaced ip::IpAddr with std::IpAddr
- Replaced CBOR with maidsafe_utilities::serialisation

## [0.1.0]
- Richer error information
- Smarter UDP hole punch logic
- Initial TCP port mapping implementation

## [0.0.0 - 0.0.3]
- Initial implementation
