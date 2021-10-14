package tech.stackable.trino.opa;

import java.net.URI;
import java.util.Collections;
import java.util.Map;

import io.trino.spi.Plugin;
import io.trino.spi.security.SystemAccessControl;
import io.trino.spi.security.SystemAccessControlFactory;

public class OpaAuthorizerPlugin implements Plugin {
    static final String CONFIG_OPA_POLICY_URI = "opa.policy.uri";

    @Override
    public Iterable<SystemAccessControlFactory> getSystemAccessControlFactories() {
        return Collections.singleton(new SystemAccessControlFactory() {
            @Override
            public String getName() {
                return OpaAuthorizer.class.getName();
            }

            @Override
            public SystemAccessControl create(Map<String, String> config) {
                String opaUriStr = config.get(CONFIG_OPA_POLICY_URI);
                if (opaUriStr == null) {
                    throw new OpaConfigException.UriRequired();
                }
                URI opaUri;
                try {
                    opaUri = URI.create(opaUriStr);
                } catch(Exception e) {
                    throw new OpaConfigException.UriInvalid(opaUriStr, e);
                }
                return new OpaAuthorizer(opaUri);
            }
        });
    }
}
