/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.rule.rest;

import org.joda.time.Instant;
import org.opensearch.action.ActionType;
import org.opensearch.autotagging.Attribute;
import org.opensearch.autotagging.FeatureType;
import org.opensearch.autotagging.Rule;
import org.opensearch.autotagging.Rule.Builder;
import org.opensearch.client.node.NodeClient;
import org.opensearch.common.annotation.ExperimentalApi;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.rest.*;
import org.opensearch.rest.action.RestResponseListener;
import org.opensearch.rule.action.*;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.BiFunction;
import java.util.function.Function;

import static org.opensearch.autotagging.Rule._ID_STRING;

/**
 * Rest action to update a Rule
 * @opensearch.experimental
 */
@ExperimentalApi
public abstract class RestUpdateRuleAction extends BaseRestHandler {
    public RestUpdateRuleAction() {}

    @Override
    public abstract String getName();

    @Override
    public abstract List<Route> routes();

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        try (XContentParser parser = request.contentParser()) {
            Builder builder = Builder.fromXContent(parser, retrieveFeatureTypeInstance());
            UpdateRuleRequest updateRuleRequest = buildUpdateRuleRequest(request.param(_ID_STRING), builder.getDescription(), builder.getAttributeMap(), builder.getFeatureValue());
            return channel -> client.execute(retriveUpdateRuleActionInstance(), updateRuleRequest, updateRuleResponse(channel));
        }
    }

    private RestResponseListener<UpdateRuleResponse> updateRuleResponse(final RestChannel channel) {
        return new RestResponseListener<>(channel) {
            @Override
            public RestResponse buildResponse(final UpdateRuleResponse response) throws Exception {
                return new BytesRestResponse(RestStatus.OK, response.toXContent(channel.newBuilder(), ToXContent.EMPTY_PARAMS));
            }
        };
    }

    /**
     * Abstract method for subclasses to provide specific ActionType Instance
     */
    protected abstract <T extends ActionType<? extends UpdateRuleResponse>> T retriveUpdateRuleActionInstance();

    /**
     * Abstract method for subclasses to provide specific FeatureType Instance
     */
    protected abstract FeatureType retrieveFeatureTypeInstance();

    protected abstract UpdateRuleRequest buildUpdateRuleRequest(String id, String description, Map<Attribute, Set<String>> attributeMap, String featureValue);
}
