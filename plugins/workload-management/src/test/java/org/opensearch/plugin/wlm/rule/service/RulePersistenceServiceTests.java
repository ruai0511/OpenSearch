/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.plugin.wlm.rule.service;

import org.mockito.ArgumentCaptor;
import org.opensearch.ResourceNotFoundException;
import org.opensearch.action.get.GetRequestBuilder;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.update.UpdateRequest;
import org.opensearch.action.update.UpdateResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.cluster.metadata.QueryGroup;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.index.shard.ShardId;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.index.engine.DocumentMissingException;
import org.opensearch.plugin.wlm.QueryGroupTestUtils;
import org.opensearch.plugin.wlm.rule.QueryGroupFeatureType;
import org.opensearch.plugin.wlm.rule.action.CreateRuleResponse;
import org.opensearch.plugin.wlm.rule.action.GetRuleResponse;
import org.opensearch.plugin.wlm.rule.action.UpdateRuleRequest;
import org.opensearch.plugin.wlm.rule.action.UpdateRuleResponse;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.autotagging.Rule;

import java.io.IOException;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import org.mockito.ArgumentCaptor;
import org.opensearch.threadpool.ThreadPool;

import static org.opensearch.plugin.wlm.RuleTestUtils._ID_ONE;
import static org.opensearch.plugin.wlm.RuleTestUtils.assertEqualRules;
import static org.opensearch.plugin.wlm.RuleTestUtils.ruleOne;
import static org.opensearch.plugin.wlm.RuleTestUtils.setUpRulePersistenceService;
import static org.opensearch.plugin.wlm.RuleTestUtils.*;
import static org.opensearch.plugin.wlm.rule.service.RulePersistenceService.RULES_INDEX;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("unchecked")
public class RulePersistenceServiceTests extends OpenSearchTestCase {

    /**
     * Test case to validate the creation logic of a Rule
     */
    public void testCreateRule() throws IOException {
        ActionListener<CreateRuleResponse> listener = mock(ActionListener.class);
        RulePersistenceService rulePersistenceService = setUpRulePersistenceService(new HashMap<>());
        Client client = rulePersistenceService.getClient();
        IndexResponse indexResponse = new IndexResponse(new ShardId(RULES_INDEX, "uuid", 0), "id", 1, 1, 1, true);
        doAnswer(invocation -> {
            ActionListener<IndexResponse> actionListener = invocation.getArgument(1);
            actionListener.onResponse(indexResponse);
            return null;
        }).when(client).index(any(IndexRequest.class), any(ActionListener.class));

        rulePersistenceService.persistRule(ruleOne, listener);
        verify(client).index(any(IndexRequest.class), any(ActionListener.class));
        ArgumentCaptor<CreateRuleResponse> responseCaptor = ArgumentCaptor.forClass(CreateRuleResponse.class);
        verify(listener).onResponse(responseCaptor.capture());

        CreateRuleResponse createRuleResponse = responseCaptor.getValue();
        assertNotNull(createRuleResponse);
        Rule rule = createRuleResponse.getRule();
        assertEqualRule(ruleOne, rule, false);
        clearInvocations(client, listener);
    }

    public void testGetRuleById() throws IOException {
        String ruleSource = ruleOne.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS).toString();
        ActionListener<GetRuleResponse> listener = mock(ActionListener.class);
        RulePersistenceService rulePersistenceService = setUpRulePersistenceService(new HashMap<>());
        Client client = rulePersistenceService.getClient();
        GetRequestBuilder getRequestBuilder = mock(GetRequestBuilder.class);
        GetResponse getResponse = mock(GetResponse.class);

        when(getResponse.isExists()).thenReturn(true);
        when(getResponse.getSourceAsString()).thenReturn(ruleSource);
        when(client.prepareGet(eq(RULES_INDEX), eq(_ID_ONE))).thenReturn(getRequestBuilder);
        doAnswer(invocation -> {
            ActionListener<GetResponse> actionListener = invocation.getArgument(0);
            actionListener.onResponse(getResponse);
            return null;
        }).when(getRequestBuilder).execute(any(ActionListener.class));

        rulePersistenceService.getRule(_ID_ONE, new HashMap<>(), null, listener);

        ArgumentCaptor<GetRuleResponse> captor = ArgumentCaptor.forClass(GetRuleResponse.class);
        verify(listener).onResponse(captor.capture());
        GetRuleResponse response = captor.getValue();
        assertNotNull(response);
        assertEqualRules(Map.of(_ID_ONE, ruleOne), response.getRules(), false);
        clearInvocations(client, getRequestBuilder, getResponse, listener);
    }

    public void testGetRuleByIdNotFound() {
        String nonExistentRuleId = "non-existent-rule";
        RulePersistenceService rulePersistenceService = setUpRulePersistenceService(new HashMap<>());
        Client client = rulePersistenceService.getClient();
        GetRequestBuilder getRequestBuilder = mock(GetRequestBuilder.class);
        GetResponse getResponse = mock(GetResponse.class);
        ActionListener<GetRuleResponse> listener = mock(ActionListener.class);

        when(client.prepareGet(RULES_INDEX, nonExistentRuleId)).thenReturn(getRequestBuilder);
        when(getResponse.isExists()).thenReturn(false);

        doAnswer(invocation -> {
            ActionListener<GetResponse> actionListener = invocation.getArgument(0);
            actionListener.onResponse(getResponse);
            return null;
        }).when(getRequestBuilder).execute(any(ActionListener.class));

        rulePersistenceService.getRule(nonExistentRuleId, new HashMap<>(), null, listener);

        ArgumentCaptor<Exception> captor = ArgumentCaptor.forClass(Exception.class);
        verify(listener).onFailure(captor.capture());
        Exception exception = captor.getValue();
        assertTrue(exception instanceof ResourceNotFoundException);
        clearInvocations(client, getRequestBuilder, getResponse, listener);
    }

    public void testUpdateRule_QueryGroupNotFound() throws IOException {
        ActionListener<UpdateRuleResponse> listener = mock(ActionListener.class);
        RulePersistenceService rulePersistenceService = setUpRulePersistenceService(new HashMap<>());
        UpdateRuleRequest request = new UpdateRuleRequest(_ID_ONE, DESCRIPTION_ONE, ATTRIBUTE_MAP, QueryGroupTestUtils._ID_ONE);
        rulePersistenceService.updateRule(request, listener);
        ArgumentCaptor<ResourceNotFoundException> exceptionCaptor = ArgumentCaptor.forClass(ResourceNotFoundException.class);
        verify(listener).onFailure(exceptionCaptor.capture());
    }

    public void testComposeUpdatedRule() throws IOException {
        Rule originalRule = new Rule(DESCRIPTION_ONE, ATTRIBUTE_MAP, QueryGroupFeatureType.INSTANCE, QueryGroupTestUtils._ID_ONE, Instant.now().toString());
        UpdateRuleRequest request = new UpdateRuleRequest(_ID_ONE, DESCRIPTION_TWO, ATTRIBUTE_MAP, QueryGroupTestUtils._ID_ONE);
        RulePersistenceService rulePersistenceService = setUpRulePersistenceService(new HashMap<>());
        Rule updatedRule = rulePersistenceService.composeUpdatedRule(originalRule, request);

        assertEquals(DESCRIPTION_TWO, updatedRule.getDescription());
        assertEquals(ATTRIBUTE_MAP, updatedRule.getAttributeMap());
        assertEquals(QueryGroupTestUtils._ID_ONE, updatedRule.getFeatureValue());
    }

    public void testPersistUpdatedRule_Success() {
        ActionListener<UpdateRuleResponse> listener = mock(ActionListener.class);
        RulePersistenceService rulePersistenceService = setUpRulePersistenceService(new HashMap<>());
        Client client = rulePersistenceService.getClient();
        Rule updatedRule = new Rule(DESCRIPTION_ONE, ATTRIBUTE_MAP, QueryGroupFeatureType.INSTANCE, QueryGroupTestUtils._ID_ONE, Instant.now().toString());
        doAnswer(invocation -> {
            ActionListener<UpdateResponse> actionListener = invocation.getArgument(1);
            actionListener.onResponse(mock(UpdateResponse.class));
            return null;
        }).when(client).update(any(UpdateRequest.class), any());
        rulePersistenceService.persistUpdatedRule(_ID_ONE, updatedRule, listener);
        verify(listener).onResponse(any(UpdateRuleResponse.class));
    }

    public void testPersistUpdatedRule_Failure() {
        ActionListener<UpdateRuleResponse> listener = mock(ActionListener.class);
        RulePersistenceService rulePersistenceService = setUpRulePersistenceService(new HashMap<>());
        Client client = rulePersistenceService.getClient();
        Rule updatedRule = new Rule(DESCRIPTION_ONE, ATTRIBUTE_MAP, QueryGroupFeatureType.INSTANCE, QueryGroupTestUtils._ID_ONE, Instant.now().toString());
        doAnswer(invocation -> {
            ActionListener<UpdateResponse> actionListener = invocation.getArgument(1);
            actionListener.onFailure(new DocumentMissingException(null, _ID_ONE));
            return null;
        }).when(client).update(any(UpdateRequest.class), any());
        rulePersistenceService.persistUpdatedRule(_ID_ONE, updatedRule, listener);
        verify(listener).onFailure(any(Exception.class));
    }
}
