/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.plugin.wlm.rule.action;

import org.opensearch.common.io.stream.BytesStreamOutput;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.test.OpenSearchTestCase;

import java.io.IOException;

import static org.opensearch.plugin.wlm.rule.WlmRuleTestUtils.ATTRIBUTE_MAP;
import static org.opensearch.plugin.wlm.rule.WlmRuleTestUtils.DESCRIPTION_ONE;
import static org.opensearch.plugin.wlm.rule.WlmRuleTestUtils.FEATURE_VALUE_ONE;
import static org.opensearch.plugin.wlm.rule.WlmRuleTestUtils._ID_ONE;

public class UpdateWlmRuleRequestTests extends OpenSearchTestCase {

    /**
     * Test case to verify the serialization and deserialization of UpdateRuleRequest.
     */
    public void testSerialization() throws IOException {
        UpdateWlmRuleRequest request = new UpdateWlmRuleRequest(_ID_ONE, DESCRIPTION_ONE, ATTRIBUTE_MAP, FEATURE_VALUE_ONE);
        BytesStreamOutput out = new BytesStreamOutput();
        request.writeTo(out);
        StreamInput streamInput = out.bytes().streamInput();
        UpdateWlmRuleRequest otherRequest = new UpdateWlmRuleRequest(streamInput);
        assertEquals(request.get_id(), otherRequest.get_id());
        assertEquals(request.getFeatureValue(), otherRequest.getFeatureValue());
        assertEquals(request.getAttributeMap(), otherRequest.getAttributeMap());
        assertEquals(request.getDescription(), otherRequest.getDescription());
    }

    /**
     * Test case to verify the serialization and deserialization of UpdateRuleRequest when there's null values.
     */
    public void testSerializationWithNull() throws IOException {
        UpdateWlmRuleRequest request = new UpdateWlmRuleRequest(_ID_ONE, null, ATTRIBUTE_MAP, null);
        BytesStreamOutput out = new BytesStreamOutput();
        request.writeTo(out);
        StreamInput streamInput = out.bytes().streamInput();
        UpdateWlmRuleRequest otherRequest = new UpdateWlmRuleRequest(streamInput);
        assertEquals(request.get_id(), otherRequest.get_id());
        assertEquals(request.getFeatureValue(), otherRequest.getFeatureValue());
        assertEquals(request.getAttributeMap(), otherRequest.getAttributeMap());
        assertEquals(request.getDescription(), otherRequest.getDescription());
    }
}
