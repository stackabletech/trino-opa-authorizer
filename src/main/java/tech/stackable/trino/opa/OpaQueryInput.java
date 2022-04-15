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

    private OpaQueryInput(Builder builder) {
        this.context = builder.context;
        this.action = builder.action;
    }

    public static class Builder {
        private final SystemSecurityContext context;
        private OpaQueryInputAction action;
        public Builder(SystemSecurityContext context) {
            this.context = context;
        }

        public Builder action(OpaQueryInputAction action) {
            this.action = action;
            return this;
        }

        public OpaQueryInput build() {
            OpaQueryInput input = new OpaQueryInput(this);
            return input;
        }
    }
}
