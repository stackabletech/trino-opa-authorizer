package tech.stackable.trino.opa;

public class OpaQueryInputAction {
    public final String operation;
    public final OpaQueryInputResource resource;
    public OpaQueryInputAction(String operation) {
        this.operation = operation;
        this.resource = null;
    }
    public OpaQueryInputAction(String operation, OpaQueryInputResource resource) {
        this.operation = operation;
        this.resource = resource;
    }
}
