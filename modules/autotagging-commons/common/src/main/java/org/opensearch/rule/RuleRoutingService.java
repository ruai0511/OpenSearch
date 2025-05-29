/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.rule;

import org.opensearch.action.support.clustermanager.AcknowledgedResponse;
import org.opensearch.core.action.ActionListener;
import org.opensearch.transport.TransportService;

/**
 * Interface that handles rule routing logic
 * @opensearch.experimental
 */
public interface RuleRoutingService {

    void handleCreateRuleRequest(CreateRuleRequest request, ActionListener<CreateRuleResponse> listener);
}
