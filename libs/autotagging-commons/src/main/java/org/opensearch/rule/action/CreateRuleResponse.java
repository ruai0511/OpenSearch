/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.rule.action;

import org.opensearch.autotagging.Rule;
import org.opensearch.common.annotation.ExperimentalApi;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;

import java.io.IOException;
import java.util.Map;

import static org.opensearch.autotagging.Rule._ID_STRING;

/**
 * Response for the create API for Rule
 * @opensearch.experimental
 */
@ExperimentalApi
public class CreateRuleResponse extends ActionResponse implements ToXContent, ToXContentObject {
    private final String _id;
    private final Rule rule;

    public CreateRuleResponse(String id, final Rule rule) {
        this._id = id;
        this.rule = rule;
    }

    public CreateRuleResponse(StreamInput in) throws IOException {
        _id = in.readString();
        rule = new Rule(in);
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(_id);
        rule.writeTo(out);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        return rule.toXContent(builder, new MapParams(Map.of(_ID_STRING, _id)));
    }

    public Rule getRule() {
        return rule;
    }
}
