/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.rule.action;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.autotagging.FeatureType;
import org.opensearch.autotagging.Rule;
import org.opensearch.autotagging.Rule.Builder;
import org.opensearch.common.annotation.ExperimentalApi;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.XContentParser;
import org.joda.time.Instant;

import java.io.IOException;
import java.util.function.Function;

/**
 * A request for create Rule
 * @opensearch.experimental
 */
@ExperimentalApi
public class CreateRuleRequest extends ActionRequest {
    private final Rule rule;

    public CreateRuleRequest(Rule rule) {
        this.rule = rule;
    }

    public CreateRuleRequest(StreamInput in) throws IOException {
        super(in);
        rule = new Rule(in);
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        super.writeTo(out);
        rule.writeTo(out);
    }

    public Rule getRule() {
        return rule;
    }
}
