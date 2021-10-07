package tech.stackable.trino;

import java.util.Collections;
import java.util.Map;

import io.trino.spi.Plugin;
import io.trino.spi.security.SystemAccessControl;
import io.trino.spi.security.SystemAccessControlFactory;

public class OpaAuthorizerPlugin implements Plugin {
    @Override
    public Iterable<SystemAccessControlFactory> getSystemAccessControlFactories() {
        return Collections.singleton(new SystemAccessControlFactory() {
            @Override
            public String getName() {
                return OpaAuthorizer.class.getName();
            }

            @Override
            public SystemAccessControl create(Map<String, String> config) {
                return new OpaAuthorizer();
            }
        });
    }
}
