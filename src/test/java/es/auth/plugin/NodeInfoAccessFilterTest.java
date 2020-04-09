package es.auth.plugin;

import io.searchbox.client.http.apache.HttpGetWithEntity;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.HttpUriRequest;
import org.elasticsearch.common.settings.ImmutableSettings;
import org.elasticsearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;

/**
 * @author arghanil.mukhopadhya
 * @since 0.0.1
 */

public class NodeInfoAccessFilterTest extends AbstractUnitTest {

    private final String searchUser = "searchUser";
    private final String searchUserPwd = "searchUserPwd";
    private final String[] searchUserRoles = new String[]{"readonly"};

    private final String adminUser = "adminUser";
    private final String adminUserPwd = "adminUserPwd";
    private final String[] adminUserRoles = new String[]{"admin"};

    protected final String nodeInfoRoles = "admin";

    @Test
    public void testForUnauthorizedAccessToNodeInfo() throws Exception {
        username = searchUser;
        password = searchUserPwd;
        final Settings settings = ImmutableSettings.settingsBuilder()
                .put("searchguard.node_info.role", nodeInfoRoles)
                .put(getAuthSettings(false, searchUserRoles)).build();
        // start ES and setup ACL
        startES(settings);
        setupTestData("ac_rules.json");

        // create JEST client - equivalent to using browser to access _node uri
        JestHttpClient client = getJestClient(getServerUri(false), username, password);
        String uri = getServerUri(false)+"/_nodes";
        HttpUriRequest httpUriRequest = new HttpGetWithEntity(uri);
        log.debug("Accessing: {}", httpUriRequest.getURI());

        // access _node
        final HttpResponse response =client.getHttpClient().execute(httpUriRequest);

        // get 403
        log.info("response.getStatusLine(): {}", response.getStatusLine());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusLine().getStatusCode());
    }

    @Test
    public void testForAuthorizedAccessToNodeInfo() throws Exception {
        username = adminUser;
        password = adminUserPwd;
        final Settings settings = ImmutableSettings.settingsBuilder()
                .put("searchguard.node_info.role", nodeInfoRoles)
                .put(getAuthSettings(false, adminUserRoles)).build();
        // start ES and setup ACL
        startES(settings);
        setupTestData("ac_rules.json");

        // create JEST client - equivalent to using browser to access _node uri
        JestHttpClient client = getJestClient(getServerUri(false), username, password);
        String uri = getServerUri(false)+"/_nodes";
        HttpUriRequest httpUriRequest = new HttpGetWithEntity(uri);
        log.debug("Accessing: {}", httpUriRequest.getURI());

        // access _node
        final HttpResponse response =client.getHttpClient().execute(httpUriRequest);

        // get 200
        log.info("response.getStatusLine(): {}", response.getStatusLine());
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
    }
}
