# Notes on the draft specification

Issues found while implementing vscp-doc-spec PR #18
(*VSCP over Bluetooth Low Energy*, branch `docs/ble5-transport-revision-2026`),
and how this implementation handles them. They should be resolved in the
specification before ratification.

## Errors

1. **F1 vector, AD Length of the second fragment (9.5).** The 223-octet
   example gives the second fragment `C = 11` and "AD Length `0x35`".
   The layout (9.2) says AD Length = `0x29 + C` = `0x34`. The first fragment
   (`0xFD`) is right. *Implementation:* `0x34` (the vectors check this).

2. **G1 event length L (6.2).** The table defines `L = 22 + N`, but the text
   says L covers "the 16-byte GUID, 2-byte head, 2-byte class, 2-byte type,
   2-byte data length, and N data octets", which is `24 + N`.
   *Implementation:* `L = 22 + N` as in the table, so the record length is
   `L + 12` (= 34 + N). Suggest defining L explicitly as the number of
   octets that follow the L field minus 2, or changing it to `24 + N`.

3. **Duplicate section number.** "8. Discovery, capabilities and
   compatibility" and "8. Interoperability and error handling" are both
   section 8.

4. **F1 fragment count range (9.2).** The table allows K = 2–8, but
   T ≤ 1024 with 212-octet chunks gives at most K = 5. Either range is safe
   (the receiver checks K = ceil(T/212)); suggest "2–5" or stating that 8 is
   reserved for a larger T in a future revision.

## Gaps

5. **No published A2 known-answer vectors.** 7.7 requires AES-CCM known
   answers for the exact nonce and AAD construction, and lists them as an
   open dependency. `tests/vectors/vectors.json` (`a2_n0`, `a2_n3`,
   `a2_max`) can be proposed for the specification; they agree across
   python3-cryptography, OpenSSL and an independent RFC 3610
   implementation.

6. **Answer to a Control message with an unsupported version (6.4/6.5).**
   UNSUPPORTED_VERSION exists, but no opcode is named for the reply when
   the version octet (and hence the opcode's meaning) is unknown.
   *Implementation:* HELLO_RESULT with UNSUPPORTED_VERSION and transaction
   ID 0.

7. **Unknown opcodes and client-only opcodes from the client.** "MUST be
   rejected", but no result message fits. *Implementation:* ATT error
   Value Not Allowed (0x13) on the write.

8. **HELLO with nonzero features.** Version 1 requires zero; the server's
   reaction is not specified. *Implementation:* HELLO_RESULT BAD_FLAGS, no
   negotiation.

9. **Capabilities before HELLO.** Not specified whether `max_event_data`
   and `max_record_size` are the server's limits or the negotiated ones.
   *Implementation:* the server's limits before HELLO, the negotiated
   values after.

10. **Fragments after a failed Event RX transaction.** A client that
    pipelines writes keeps sending fragments of a transaction the server
    already rejected; answering each with BAD_SEQUENCE floods the Control
    characteristic. *Implementation:* one EVENT_RESULT per failed
    transaction; its remaining fragments are ignored until a new FIRST.

11. **CCCD protection.** Event TX requires an "authenticated, encrypted,
    authorized subscription", but some stacks (NimBLE) cannot require
    encryption on a CCCD write. *Implementation:* events are only sent after
    an authenticated HELLO on an authorized link, whatever the CCCD state.

12. **G1 transaction IDs from the server.** Uniqueness "among in-flight
    records on that connection" is required; with one outstanding record
    per direction, a counter starting at 1 per connection is used.

13. **Observers on high-level stacks.** The ambiguity rule (reject data
    sets with more than one candidate frame) needs the raw advertising data
    set. BlueZ (and some other host stacks) only expose Manufacturer
    Specific Data per Company Identifier. The specification could note
    this, or define the rule per Company Identifier.

14. **Counter state on factory reset / NVS erase.** 5.5 and 7.4 forbid
    reuse after rollback, but a full flash erase on a device resets the
    counters. *Implementation:* the ESP32 example refuses to start instead
    of erasing NVS; the docs say a new A2 key is needed after an erase. The
    specification could require a new sender GUID (E1) or a new key (A2)
    after any counter loss.
