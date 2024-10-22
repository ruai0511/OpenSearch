/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.plugin.wlm.rest;

import org.opensearch.client.node.NodeClient;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.plugin.wlm.action.CreateQueryGroupAction;
import org.opensearch.plugin.wlm.action.CreateQueryGroupRequest;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;

import java.io.IOException;
import java.util.List;

import static org.opensearch.rest.RestRequest.Method.POST;
import static org.opensearch.rest.RestRequest.Method.PUT;

/**
 * Rest action to create a QueryGroup
 *
 * @opensearch.experimental
 */
public class RestCreateQueryGroupAction extends BaseRestHandler {

    /**
     * Constructor for RestCreateQueryGroupAction
     */
    public RestCreateQueryGroupAction() {}

    @Override
    public String getName() {
        return "create_query_group";
    }

    /**
     * The list of {@link Route}s that this RestHandler is responsible for handling.
     */
    @Override
    public List<Route> routes() {
        return List.of(new Route(POST, "_wlm/query_group/"), new Route(PUT, "_wlm/query_group/"));
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        try (XContentParser parser = request.contentParser()) {
            CreateQueryGroupRequest createQueryGroupRequest = CreateQueryGroupRequest.fromXContent(parser);
            createQueryGroupRequest.clusterManagerNodeTimeout(
                request.paramAsTime("cluster_manager_timeout", createQueryGroupRequest.clusterManagerNodeTimeout())
            );
            createQueryGroupRequest.timeout(request.paramAsTime("timeout", createQueryGroupRequest.timeout()));
            return channel -> client.execute(
                CreateQueryGroupAction.INSTANCE,
                createQueryGroupRequest,
                new RestToXContentListener<>(channel)
            );
        }
    }
}
