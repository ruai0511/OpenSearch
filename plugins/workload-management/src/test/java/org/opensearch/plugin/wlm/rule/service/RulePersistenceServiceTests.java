/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.plugin.wlm.rule.service;

import org.opensearch.ResourceNotFoundException;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.search.SearchRequestBuilder;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.update.UpdateRequest;
import org.opensearch.action.update.UpdateResponse;
import org.opensearch.autotagging.Rule;
import org.opensearch.client.Client;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.index.shard.ShardId;
import org.opensearch.index.engine.DocumentMissingException;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.plugin.wlm.QueryGroupTestUtils;
import org.opensearch.plugin.wlm.rule.QueryGroupFeatureType;
import org.opensearch.plugin.wlm.rule.action.CreateRuleResponse;
import org.opensearch.plugin.wlm.rule.action.GetRuleResponse;
import org.opensearch.plugin.wlm.rule.action.UpdateRuleRequest;
import org.opensearch.plugin.wlm.rule.action.UpdateRuleResponse;
import org.opensearch.search.sort.SortOrder;
import org.opensearch.test.OpenSearchTestCase;

import java.io.IOException;
import java.time.Instant;
import java.util.HashMap;

import org.mockito.ArgumentCaptor;

import static org.opensearch.autotagging.Rule._ID_STRING;
import static org.opensearch.plugin.wlm.RuleTestUtils.ATTRIBUTE_MAP;
import static org.opensearch.plugin.wlm.RuleTestUtils.DESCRIPTION_ONE;
import static org.opensearch.plugin.wlm.RuleTestUtils.DESCRIPTION_TWO;
import static org.opensearch.plugin.wlm.RuleTestUtils._ID_ONE;
import static org.opensearch.plugin.wlm.RuleTestUtils._ID_TWO;
import static org.opensearch.plugin.wlm.RuleTestUtils.assertEqualRule;
import static org.opensearch.plugin.wlm.RuleTestUtils.ruleOne;
import static org.opensearch.plugin.wlm.RuleTestUtils.setUpRulePersistenceService;
import static org.opensearch.plugin.wlm.rule.service.RulePersistenceService.RULES_INDEX;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.anyInt;
import static org.mockito.Mockito.anyString;
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

    public void testBuildGetRuleQuery_WithId() {
        RulePersistenceService rulePersistenceService = setUpRulePersistenceService(new HashMap<>());
        BoolQueryBuilder query = rulePersistenceService.buildGetRuleQuery(_ID_ONE, new HashMap<>());
        assertTrue(query.hasClauses());
        assertEquals(QueryBuilders.termQuery(_ID_STRING, _ID_ONE).toString(), query.must().get(0).toString());
    }

    public void testBuildGetRuleQuery_WithFilters() {
        RulePersistenceService rulePersistenceService = setUpRulePersistenceService(new HashMap<>());
        BoolQueryBuilder query = rulePersistenceService.buildGetRuleQuery(null, ATTRIBUTE_MAP);
        assertTrue(query.hasClauses());
        assertEquals(1, query.must().size());
        assertTrue(query.filter().contains(QueryBuilders.existsQuery(QueryGroupFeatureType.NAME)));
    }

    public void testGetRule_WithId() {
        RulePersistenceService rulePersistenceService = setUpRulePersistenceService(new HashMap<>());
        Client client = rulePersistenceService.getClient();
        ActionListener<GetRuleResponse> listener = mock(ActionListener.class);
        SearchRequestBuilder searchRequestBuilder = mock(SearchRequestBuilder.class);
        SetupMocksForGetRule(client, searchRequestBuilder);

        rulePersistenceService.getRule(_ID_ONE, new HashMap<>(), null, listener);
        verify(client).prepareSearch(RulePersistenceService.RULES_INDEX);
        verify(searchRequestBuilder).setQuery(any());
        verify(searchRequestBuilder).execute(any());
    }

    public void testGetRule_WithSearchAfter() {
        RulePersistenceService rulePersistenceService = setUpRulePersistenceService(new HashMap<>());
        Client client = rulePersistenceService.getClient();
        ActionListener<GetRuleResponse> listener = mock(ActionListener.class);
        SearchRequestBuilder searchRequestBuilder = mock(SearchRequestBuilder.class);
        SetupMocksForGetRule(client, searchRequestBuilder);
        when(searchRequestBuilder.addSort(anyString(), any(SortOrder.class))).thenReturn(searchRequestBuilder);
        when(searchRequestBuilder.searchAfter(any())).thenReturn(searchRequestBuilder);

        rulePersistenceService.getRule(null, new HashMap<>(), _ID_TWO, listener);
        verify(searchRequestBuilder).addSort(_ID_STRING, SortOrder.ASC);
        verify(searchRequestBuilder).searchAfter(new Object[] { _ID_TWO });
    }

    public void SetupMocksForGetRule(Client client, SearchRequestBuilder searchRequestBuilder) {
        when(client.prepareSearch(anyString())).thenReturn(searchRequestBuilder);
        when(searchRequestBuilder.setQuery(any())).thenReturn(searchRequestBuilder);
        when(searchRequestBuilder.setSize(anyInt())).thenReturn(searchRequestBuilder);
        doAnswer(invocation -> {
            ActionListener<SearchResponse> searchListener = invocation.getArgument(0);
            searchListener.onResponse(mock(SearchResponse.class));
            return null;
        }).when(searchRequestBuilder).execute(any());
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
        Rule originalRule = new Rule(
            DESCRIPTION_ONE,
            ATTRIBUTE_MAP,
            QueryGroupFeatureType.INSTANCE,
            QueryGroupTestUtils._ID_ONE,
            Instant.now().toString()
        );
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
        Rule updatedRule = new Rule(
            DESCRIPTION_ONE,
            ATTRIBUTE_MAP,
            QueryGroupFeatureType.INSTANCE,
            QueryGroupTestUtils._ID_ONE,
            Instant.now().toString()
        );
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
        Rule updatedRule = new Rule(
            DESCRIPTION_ONE,
            ATTRIBUTE_MAP,
            QueryGroupFeatureType.INSTANCE,
            QueryGroupTestUtils._ID_ONE,
            Instant.now().toString()
        );
        doAnswer(invocation -> {
            ActionListener<UpdateResponse> actionListener = invocation.getArgument(1);
            actionListener.onFailure(new DocumentMissingException(null, _ID_ONE));
            return null;
        }).when(client).update(any(UpdateRequest.class), any());
        rulePersistenceService.persistUpdatedRule(_ID_ONE, updatedRule, listener);
        verify(listener).onFailure(any(Exception.class));
    }
}
