package es.auth.plugin.filter;

import com.floragunn.searchguard.authentication.User;
import com.floragunn.searchguard.authorization.ForbiddenException;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.action.admin.cluster.node.info.NodesInfoRequest;
import org.elasticsearch.action.support.ActionFilter;
import org.elasticsearch.action.support.ActionFilterChain;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;

/**
 * {@Link org.elasticsearch.action.support.ActionFilter ActionFilter} for the Node Info Access
 *
 * @author arghanil.mukhopadhya
 * @since 0.0.1
 */
public class NodeInfoAccessFilter implements ActionFilter {

    protected final ESLogger log = Loggers.getLogger(this.getClass());
    private final String[] rolesForNodeInfo;

    /**
     * Reads searchguard.node_info.role from elasticsearch.yml to find roles that can access node info.
     * If no role found, the default role is "admin"
     *
     * @param settings
     */
    @Inject
    public NodeInfoAccessFilter(final Settings settings) {
        log.info("Found searchguard.node_info.role: {}", settings.get("searchguard.node_info.role", null));
        rolesForNodeInfo = settings.get("searchguard.node_info.role", "admin").split(",");
    }

    public int order() {
        return Integer.MIN_VALUE;
    }

    /**
     * Applies filter for the access to {@Link org.elasticsearch.action.admin.cluster.node.info.NodesInfoRequest NodeInfoRequest}
     * based on roles configured in elasticsearch.yml against key searchguard.node_info.role
     *
     * @param action
     * @param request
     * @param listener
     * @param chain
     */
    public void apply(String action, ActionRequest request, ActionListener listener, ActionFilterChain chain) {
        boolean isAuthorized = false;
        if (request instanceof NodesInfoRequest) {
            final User user = request.getFromContext("searchguard_authenticated_user", null);
            log.info("Node info access request by: {}", user);
            for (String role : rolesForNodeInfo) {
                if (user.isUserInRole(role)) {
                    isAuthorized = true;
                    break;
                }
            }
            if(!isAuthorized) {
                log.error("Access Blocked to node info for: {}", user);
                throw new ForbiddenException(String.format("Forbidden access for: %s", user));
            }
        }
        chain.proceed(action, request, listener);
    }

    public void apply(String action, ActionResponse response, ActionListener listener, ActionFilterChain chain) {
        chain.proceed(action, response, listener);
    }
}
