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
import org.opensearch.autotagging.RuleValidator;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.autotagging.Rule.Builder;
import org.opensearch.autotagging.Attribute;
import org.opensearch.plugin.wlm.rule.QueryGroupFeatureType;

import java.io.IOException;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * A request for update Rule
 * @opensearch.experimental
 */
public class UpdateRuleRequest extends ActionRequest {
    private final String _id;
    private final String description;
    private final Map<Attribute, Set<String>> attributeMap;
    private final String featureValue;

    /**
     * Constructor for UpdateRuleRequest
     * @param _id - Id for the Rule
     * @param description - description for the Rule
     * @param attributeMap - attributeMap for the Rule
     * @param featureValue - featureValue for the Rule
     */
    public UpdateRuleRequest(String _id, String description, Map<Attribute, Set<String>> attributeMap, String featureValue) throws IOException {
        this._id = _id;
        this.description = description;
        this.attributeMap = attributeMap;
        this.featureValue = featureValue;
    }

    /**
     * Constructor for UpdateRuleRequest
     * @param in - A {@link StreamInput} object
     */
    UpdateRuleRequest(StreamInput in) throws IOException {
        super(in);
        _id = in.readString();
        description = in.readOptionalString();
        attributeMap = in.readMap(i -> Attribute.from(i, QueryGroupFeatureType.INSTANCE), i -> new HashSet<>(i.readStringList()));
        featureValue = in.readOptionalString();
    }

    /**
     * Generate a UpdateRuleRequest from XContent
     * @param parser - A {@link XContentParser} object
     */
    public static UpdateRuleRequest fromXContent(XContentParser parser, String _id) throws IOException {
        Builder builder = Builder.fromXContent(parser, QueryGroupFeatureType.INSTANCE);
        return new UpdateRuleRequest(_id, builder.getDescription(), builder.getAttributeMap(), builder.getFeatureValue());
    }

    @Override
    public ActionRequestValidationException validate() {
        RuleValidator validator = new RuleValidator(description, attributeMap,featureValue, null, QueryGroupFeatureType.INSTANCE);
        validator.validateUpdatingRuleParams();
        return null;
     }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeString(_id);
        out.writeOptionalString(description);
        out.writeMap(attributeMap, (o, a) -> a.writeTo(o), StreamOutput::writeStringCollection);
        out.writeOptionalString(featureValue);
    }

    public String get_id() {
        return _id;
    }

    @Override
    public String getDescription() {
        return description;
    }

    public Map<Attribute, Set<String>> getAttributeMap() {
        return attributeMap;
    }

    public String getFeatureValue() {
        return featureValue;
    }
}
