/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.rule;

import org.opensearch.core.action.ActionListener;
import org.opensearch.transport.TransportService;

/**
 * Interface that handles rule routing logic
 * @opensearch.experimental
 */
public interface RuleRoutingService {

    /**
     * Sets the {@link TransportService} for routing rule-related requests.
     * We need to set transport service after initializing RuleRoutingService because {@link TransportService} is only available
     * after AutoTaggingPlugin is fully loaded.
     * @param transportService the transport service used for node communication
     */
    void setTransportService(TransportService transportService);

    /**
     * Handles a create rule request by routing it to the appropriate node.
     * @param request the create rule request
     * @param executePersistLocally callback to execute local persistence in the transport layer
     * @param listener listener to handle the final response
     */
    void handleCreateRuleRequest(
        CreateRuleRequest request,
        ActionListener<Void> executePersistLocally,
        ActionListener<CreateRuleResponse> listener
    );
}
