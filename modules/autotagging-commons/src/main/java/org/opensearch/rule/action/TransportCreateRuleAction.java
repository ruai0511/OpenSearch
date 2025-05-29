/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.rule.action;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.ExceptionsHelper;
import org.opensearch.ResourceAlreadyExistsException;
import org.opensearch.action.ActionListenerResponseHandler;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.TransportAction;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.cluster.routing.IndexRoutingTable;
import org.opensearch.cluster.routing.ShardRouting;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.rule.*;
import org.opensearch.rule.service.IndexStoredRulePersistenceService;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportChannel;
import org.opensearch.transport.TransportException;
import org.opensearch.transport.TransportRequestHandler;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

import java.io.IOException;
import java.util.Map;

import static org.opensearch.rule.RuleFrameworkPlugin.RULE_THREAD_POOL_NAME;

/**
 * Transport action to create Rules
 * @opensearch.experimental
 */
public class TransportCreateRuleAction extends TransportAction<CreateRuleRequest, CreateRuleResponse> {
    private final TransportService transportService;
    private final RuleRoutingServiceRegistry ruleRoutingServiceRegistry;
    /**
     * Constructor for TransportCreateRuleAction
     * @param transportService - a {@link TransportService} object
     * @param actionFilters - a {@link ActionFilters} object
     * @param ruleRoutingServiceRegistry - a {@link RuleRoutingServiceRegistry} object
     */
    @Inject
    public TransportCreateRuleAction(
        TransportService transportService,
        ActionFilters actionFilters,
        RuleRoutingServiceRegistry ruleRoutingServiceRegistry
    ) {
        super(CreateRuleAction.NAME, actionFilters, transportService.getTaskManager());
        this.transportService = transportService;
        this.ruleRoutingServiceRegistry = ruleRoutingServiceRegistry;
    }

    @Override
    protected void doExecute(Task task, CreateRuleRequest request, ActionListener<CreateRuleResponse> listener) {
        ruleRoutingServiceRegistry.getRuleRoutingService(request.getRule().getFeatureType())
            .handleCreateRuleRequest(request, listener);
    }
}
