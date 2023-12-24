package tech.stackable.trino.opa;

import io.trino.spi.security.Identity;
import io.trino.spi.security.SystemSecurityContext;

public class OpaQueryInputIdentity extends OpaQueryInputGeneric {
    public final Identity identity;
    public final OpaQueryInputAction action;

    public OpaQueryInputIdentity(Identity identity, OpaQueryInputAction action) {
        this.identity = identity;
        this.action = action;
    }
}
