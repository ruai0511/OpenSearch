/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.plugin.wlm.rule.action;

import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;

import java.io.IOException;

/**
 * Response for the delete API for Rule
 *
 * @opensearch.experimental
 */
public class DeleteRuleResponse extends ActionResponse implements ToXContent, ToXContentObject {
    private final RestStatus restStatus;

    /**
     * Constructor for DeleteRuleResponse
     * @param restStatus - The restStatus for the response
     */
    public DeleteRuleResponse(RestStatus restStatus) {
        this.restStatus = restStatus;
    }

    /**
     * Constructor for DeleteRuleResponse
     * @param in - A {@link StreamInput} object
     */
    public DeleteRuleResponse(StreamInput in) throws IOException {
        restStatus = RestStatus.readFrom(in);
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        RestStatus.writeTo(out, restStatus);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.field("status", restStatus.name());
        builder.endObject();
        return builder;
    }

    /**
     * restStatus getter
     */
    public RestStatus getRestStatus() {
        return restStatus;
    }
}
