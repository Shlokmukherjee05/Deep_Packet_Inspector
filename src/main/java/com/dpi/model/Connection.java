package com.dpi.model;

import java.time.Instant;

/**
 * Per-flow connection entry.
 * Mirrors DPI::Connection in types.h.
 */
public class Connection {

    public enum State {
        NEW, ESTABLISHED, CLASSIFIED, BLOCKED, CLOSED
    }

    public enum Action {
        FORWARD,   // pass to internet
        DROP,      // block / drop
        INSPECT,   // needs further inspection
        LOG_ONLY   // forward but log
    }

    public final FiveTuple tuple;

    public State   state    = State.NEW;
    public AppType appType  = AppType.UNKNOWN;
    public String  sni      = "";          // Server Name Indication

    public long packetsIn  = 0;
    public long packetsOut = 0;
    public long bytesIn    = 0;
    public long bytesOut   = 0;

    public Instant firstSeen = Instant.now();
    public Instant lastSeen  = firstSeen;

    public Action action = Action.FORWARD;

    // TCP state flags
    public boolean synSeen    = false;
    public boolean synAckSeen = false;
    public boolean finSeen    = false;

    public Connection(FiveTuple tuple) {
        this.tuple = tuple;
    }
}
