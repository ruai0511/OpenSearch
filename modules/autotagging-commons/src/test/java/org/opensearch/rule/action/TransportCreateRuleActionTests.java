/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.rule.action;

import org.opensearch.action.support.ActionFilters;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.core.action.ActionListener;
import org.opensearch.rule.*;
import org.opensearch.rule.autotagging.FeatureType;
import org.opensearch.rule.autotagging.Rule;
import org.opensearch.rule.service.IndexStoredRulePersistenceService;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

import java.util.concurrent.ExecutorService;

import static org.opensearch.rule.RuleFrameworkPlugin.RULE_THREAD_POOL_NAME;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("unchecked")
public class TransportCreateRuleActionTests extends OpenSearchTestCase {
    private TransportService transportService;
    private ThreadPool threadPool;
    private RulePersistenceServiceRegistry registry;
    private ActionFilters actionFilters;
    private TransportCreateRuleAction action;
    private FeatureType mockFeatureType;

    private final String testIndexName = "test-index";

    public void setUp() throws Exception {
        super.setUp();
        transportService = mock(TransportService.class);
        threadPool = mock(ThreadPool.class);
        registry = mock(RulePersistenceServiceRegistry.class);
        actionFilters = mock(ActionFilters.class);
        mockFeatureType = mock(FeatureType.class);
        RuleRoutingServiceRegistry registry = new RuleRoutingServiceRegistry();
        when(mockFeatureType.getName()).thenReturn("test_feature");
        RuleRoutingService mockService = mock(RuleRoutingService.class);
        registry.register(mockFeatureType, mockService);

        ExecutorService executorService = mock(ExecutorService.class);
        doAnswer(invocation -> {
            Runnable runnable = invocation.getArgument(0);
            runnable.run();
            return null;
        }).when(executorService).execute(any());
        when(threadPool.executor(any())).thenReturn(executorService);
        action = new TransportCreateRuleAction(transportService, actionFilters, registry);
    }

    public void testExecution() {
        IndexStoredRulePersistenceService persistenceService = mock(IndexStoredRulePersistenceService.class);
        when(registry.getRulePersistenceService(mockFeatureType)).thenReturn(persistenceService);
        Rule rule = mock(Rule.class);
        when(rule.getFeatureType()).thenReturn(mockFeatureType);
        CreateRuleRequest request = new CreateRuleRequest(rule);
        ActionListener<CreateRuleResponse> listener = mock(ActionListener.class);
        action.doExecute(null, request, listener);
        verify(threadPool).executor(RULE_THREAD_POOL_NAME);
    }
}
