package tech.stackable.trino.opa;

public abstract class OpaConfigException extends RuntimeException {
    private static final long serialVersionUID = 2627367174713287956L;

    public OpaConfigException(String message, Throwable cause) {
        super(message, cause);
    }

    public static final class UriRequired extends OpaConfigException {
        private static final long serialVersionUID = 799187669826407192L;

        public UriRequired() {
            super("No Open Policy Agent URI provided (must be set in access control property "
                    + OpaAuthorizerPlugin.CONFIG_OPA_URI + ")", null);
        }
    }

    public static final class UriInvalid extends OpaConfigException {
        private static final long serialVersionUID = 2753800944632029653L;

        public UriInvalid(String uri, Throwable cause) {
            super("Open Policy Agent URI is invalid (see access control property "
                    + OpaAuthorizerPlugin.CONFIG_OPA_URI + "): " + uri, cause);
        }
    }
}
