/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.rule.action;

import org.joda.time.Instant;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.autotagging.Attribute;
import org.opensearch.autotagging.FeatureType;
import org.opensearch.autotagging.Rule.Builder;
import org.opensearch.autotagging.RuleValidator;
import org.opensearch.common.annotation.ExperimentalApi;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.XContentParser;

import java.io.IOException;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.BiFunction;
import java.util.function.Function;

/**
 * A request for update Rule
 * @opensearch.experimental
 */
@ExperimentalApi
public class UpdateRuleRequest extends ActionRequest {
    private final String _id;
    private final String description;
    private final Map<Attribute, Set<String>> attributeMap;
    private final String featureValue;
    private final FeatureType featureType;

    public UpdateRuleRequest(String _id, String description, Map<Attribute, Set<String>> attributeMap, String featureValue, FeatureType featureType) {
        this._id = _id;
        this.description = description;
        this.attributeMap = attributeMap;
        this.featureValue = featureValue;
        this.featureType = featureType;
    }

    public UpdateRuleRequest(StreamInput in) throws IOException {
        super(in);
        _id = in.readString();
        description = in.readOptionalString();
        featureType = FeatureType.from(in);
        attributeMap = in.readMap(i -> Attribute.from(i, featureType), i -> new HashSet<>(i.readStringList()));
        featureValue = in.readOptionalString();
    }

    @Override
    public ActionRequestValidationException validate() {
        RuleValidator validator = new RuleValidator(description, attributeMap, featureValue, null, featureType);
        validator.validateUpdatingRuleParams();
        return null;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeString(_id);
        out.writeOptionalString(description);
        featureType.writeTo(out);
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
