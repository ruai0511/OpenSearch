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
import org.opensearch.plugin.wlm.action.UpdateQueryGroupAction;
import org.opensearch.plugin.wlm.action.UpdateQueryGroupRequest;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;

import java.io.IOException;
import java.util.List;

import static org.opensearch.rest.RestRequest.Method.POST;
import static org.opensearch.rest.RestRequest.Method.PUT;

/**
 * Rest action to update a QueryGroup
 *
 * @opensearch.experimental
 */
public class RestUpdateQueryGroupAction extends BaseRestHandler {

    /**
     * Constructor for RestUpdateQueryGroupAction
     */
    public RestUpdateQueryGroupAction() {}

    @Override
    public String getName() {
        return "update_query_group";
    }

    /**
     * The list of {@link Route}s that this RestHandler is responsible for handling.
     */
    @Override
    public List<Route> routes() {
        return List.of(new Route(POST, "_wlm/query_group/{name}"), new Route(PUT, "_wlm/query_group/{name}"));
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        try (XContentParser parser = request.contentParser()) {
            UpdateQueryGroupRequest updateQueryGroupRequest = UpdateQueryGroupRequest.fromXContent(parser, request.param("name"));
            updateQueryGroupRequest.clusterManagerNodeTimeout(
                request.paramAsTime("cluster_manager_timeout", updateQueryGroupRequest.clusterManagerNodeTimeout())
            );
            updateQueryGroupRequest.timeout(request.paramAsTime("timeout", updateQueryGroupRequest.timeout()));
            return channel -> client.execute(
                UpdateQueryGroupAction.INSTANCE,
                updateQueryGroupRequest,
                new RestToXContentListener<>(channel)
            );
        }
    }
}
