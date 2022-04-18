package tech.stackable.trino.opa;

public class OpaQueryInputAction {
    private final String operation;
    private final OpaQueryInputResource resource;

    public OpaQueryInputAction(String operation) {
        this.operation = operation;
        this.resource = null;
    }
    public OpaQueryInputAction(String operation, OpaQueryInputResource resource) {
        this.operation = operation;
        this.resource = resource;
    }
}
