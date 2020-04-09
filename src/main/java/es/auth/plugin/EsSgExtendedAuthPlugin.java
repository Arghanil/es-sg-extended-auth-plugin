package es.auth.plugin;

import es.auth.plugin.filter.NodeInfoAccessFilter;
import org.elasticsearch.action.ActionModule;
import org.elasticsearch.plugins.AbstractPlugin;

/**
 * Define the es-sg-extended-auth plugin
 *
 * @author arghanil.mukhopadhya
 * @since 0.0.1
 */
public class EsSgExtendedAuthPlugin extends AbstractPlugin {
    public String name() {
        return "es-sg-extended-auth";
    }

    public String description() {
        return "filters _node queries based on roles";
    }

    public void onModule(final ActionModule module) {
        module.registerFilter(NodeInfoAccessFilter.class);
    }
}
