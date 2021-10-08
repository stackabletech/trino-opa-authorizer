package tech.stackable.trino.opa;

import java.net.http.HttpResponse;

public abstract class OpaQueryException extends RuntimeException {
    private static final long serialVersionUID = -289639728596358946L;

    public OpaQueryException(String message, Throwable cause) {
        super(message, cause);
    }

    public static final class QueryFailed extends OpaQueryException {
        private static final long serialVersionUID = -4233615238117601391L;

        public QueryFailed(Throwable cause) {
            super("Failed to query OPA backend", cause);
        }
    }

    public static final class SerializeFailed extends OpaQueryException {
        private static final long serialVersionUID = 527486287577822516L;

        public SerializeFailed(Throwable cause) {
            super("Failed to serialize OPA query context", cause);
        }
    }

    public static final class DeserializeFailed extends OpaQueryException {
        private static final long serialVersionUID = 3141599137357908279L;

        public DeserializeFailed(Throwable cause) {
            super("Failed to deserialize OPA policy response", cause);
        }
    }

    public static final class PolicyNotFound extends OpaQueryException {
        private static final long serialVersionUID = 3141599137357908279L;

        public PolicyNotFound(String policyName) {
            super("No OPA policy named " + policyName, null);
        }
    }

    public static final class OpaServerError extends OpaQueryException {
        private static final long serialVersionUID = 3141599137357908279L;

        public <T> OpaServerError(String policyName, HttpResponse<T> response) {
            super("OPA server returned status " + response.statusCode() + " when processing policy " + policyName + ": "
                    + response.body(), null);
        }
    }
}
