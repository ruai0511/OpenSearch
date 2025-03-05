/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.plugin.wlm.rule.action;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.support.clustermanager.ClusterManagerNodeRequest;
import org.opensearch.autotagging.AutoTaggingRegistry;
import org.opensearch.common.collect.Tuple;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.autotagging.Rule;
import org.opensearch.autotagging.Rule.Builder;
import org.opensearch.autotagging.Attribute;
import org.opensearch.plugin.wlm.rule.QueryGroupFeatureType;

import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.opensearch.autotagging.AutoTaggingRegistry.attributeRegistryMap;
import static org.opensearch.autotagging.Rule.builder;

/**
 * A request for update Rule
 * @opensearch.experimental
 */
public class UpdateRuleRequest extends ActionRequest {
    private final String _id;
    private final Map<Attribute, Set<String>> attributeMap;
    private final String label;

    /**
     * Constructor for UpdateRuleRequest
     * @param _id - Id for the Rule
     * @param attributeMap - attributeMap for the Rule
     * @param label - label for the Rule
     */
    public UpdateRuleRequest(String _id, Map<Attribute, Set<String>> attributeMap, String label) throws IOException {
        this._id = _id;
        this.attributeMap = attributeMap;
        this.label = label;
    }

    /**
     * Constructor for UpdateRuleRequest
     * @param in - A {@link StreamInput} object
     */
    UpdateRuleRequest(StreamInput in) throws IOException {
        super(in);
        _id = in.readString();
        attributeMap = Rule.readAttributeMap(in);
        label = in.readOptionalString();
    }

    /**
     * Generate a UpdateRuleRequest from XContent
     * @param parser - A {@link XContentParser} object
     */
    public static UpdateRuleRequest fromXContent(XContentParser parser, String _id) throws IOException {
        Builder<QueryGroupFeatureType> builder = Builder.fromXContent(parser, QueryGroupFeatureType.INSTANCE);
        return new UpdateRuleRequest(_id, builder.getAttributeMap(), builder.getLabel());
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(_id);
        out.writeMap(attributeMap,
            (o, a) -> {
                o.writeString(a.getClass().getName());
                o.writeString(a.getName());
            },
            StreamOutput::writeStringCollection
        );
        out.writeOptionalString(label);
    }
}
