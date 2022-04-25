package tech.stackable.trino.opa;

import io.trino.spi.security.SystemSecurityContext;

public class OpaQueryInput {
    public final SystemSecurityContext context;
    public final OpaQueryInputAction action;

    public OpaQueryInput(SystemSecurityContext context, OpaQueryInputAction action) {
        this.context = context;
        this.action = action;
    }
}
