package tech.stackable.trino.opa;

import io.trino.spi.security.SystemSecurityContext;

public class OpaQueryInput {
    private final SystemSecurityContext context;
    private final OpaQueryInputAction action;

    public OpaQueryInput(SystemSecurityContext context) {
        this.context = context;
        this.action = null;
    }

    public OpaQueryInput(SystemSecurityContext context, OpaQueryInputAction action) {
        this.context = context;
        this.action = action;
    }
}
