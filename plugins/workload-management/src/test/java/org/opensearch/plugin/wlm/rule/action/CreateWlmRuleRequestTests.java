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

import static org.opensearch.plugin.wlm.rule.WlmRuleTestUtils.assertEqualRule;
import static org.opensearch.plugin.wlm.rule.WlmRuleTestUtils.ruleOne;

public class CreateWlmRuleRequestTests extends OpenSearchTestCase {

    /**
     * Test case to verify the serialization and deserialization of CreateRuleRequest.
     */
    public void testSerialization() throws IOException {
        CreateWlmRuleRequest request = new CreateWlmRuleRequest(ruleOne);
        BytesStreamOutput out = new BytesStreamOutput();
        request.writeTo(out);
        StreamInput streamInput = out.bytes().streamInput();
        CreateWlmRuleRequest otherRequest = new CreateWlmRuleRequest(streamInput);
        assertEqualRule(ruleOne, otherRequest.getRule(), false);
    }
}
