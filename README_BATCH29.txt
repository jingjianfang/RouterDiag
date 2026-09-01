Batch29 - connection/login failure auto-disconnect

- Initial router connection now tracks an explicit connection/login phase.
- Control login failure automatically closes all partial router sessions.
- Initial capture-session login failure also closes the whole partial connection.
- TCP/serial transport errors or disconnects before login completes trigger the same cleanup path.
- The UI keeps the failure reason and states that the connection was automatically disconnected.
- Established-session capture reconnect behavior is unchanged.
