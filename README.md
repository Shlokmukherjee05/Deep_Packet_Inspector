# Deep Packet Inspector — Java Port

### Key language differences

- **`std::atomic<uint64_t>`** → `java.util.concurrent.atomic.AtomicLong`
- **`std::shared_mutex`** → `java.util.concurrent.locks.ReentrantReadWriteLock`
- **`std::thread`** → `java.lang.Thread` (daemon threads)
- **`ThreadSafeQueue<T>`** → `java.util.concurrent.LinkedBlockingQueue<T>`
- **`std::unique_ptr`** → regular references (GC handles memory)
- **`ntohs` / `ntohl`** → `ByteBuffer.order(ByteOrder.BIG_ENDIAN)`
- **Unsigned integers** → `Byte.toUnsignedInt()`, `Short.toUnsignedInt()`, `Integer.toUnsignedLong()`
- **`std::optional<T>`** → `java.util.Optional<T>`
- **`struct` with methods** → Java `record` or regular `class`
- **Header files** → Not needed (Java has no separate declaration/definition split)

## Build

```bash
mvn package -q
```

This produces `target/deep-packet-inspector-1.0.0.jar` (fat JAR with all dependencies).

## Run

**Simple mode** — prints each packet like the original :
```bash
java -jar target/deep-packet-inspector-1.0.0.jar capture.pcap
java -jar target/deep-packet-inspector-1.0.0.jar capture.pcap 10
```

**DPI mode** — full pipeline with blocking rules and PCAP output:
```bash
java -jar target/deep-packet-inspector-1.0.0.jar --dpi input.pcap output.pcap [rules.txt]
```

## Rules file format

One directive per line :
```
block_ip 192.168.1.100
block_app NETFLIX
block_domain *.facebook.com
block_port 6881
# comments are supported
```

## Requirements

- Java 17+
- Maven 3.6+ (build only)
#
