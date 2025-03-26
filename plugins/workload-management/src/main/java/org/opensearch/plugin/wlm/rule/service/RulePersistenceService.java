/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.plugin.wlm.rule.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.ResourceAlreadyExistsException;
import org.opensearch.ResourceNotFoundException;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.SearchRequestBuilder;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.update.UpdateRequest;
import org.opensearch.autotagging.Attribute;
import org.opensearch.autotagging.Rule;
import org.opensearch.autotagging.Rule.Builder;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.DeprecationHandler;
import org.opensearch.core.xcontent.MediaTypeRegistry;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.plugin.wlm.rule.QueryGroupFeatureType;
import org.opensearch.plugin.wlm.rule.action.CreateRuleResponse;
import org.opensearch.plugin.wlm.rule.action.GetRuleResponse;
import org.opensearch.plugin.wlm.rule.action.UpdateRuleRequest;
import org.opensearch.plugin.wlm.rule.action.UpdateRuleResponse;
import org.opensearch.search.SearchHit;
import org.opensearch.search.sort.SortOrder;
import org.joda.time.Instant;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import static org.opensearch.autotagging.Rule._ID_STRING;

/**
 * This class encapsulates the logic to manage the lifecycle of rules at index level
 * @opensearch.experimental
 */
public class RulePersistenceService {
    /**
     * The system index name used for storing rules
     */
    public static final String RULES_INDEX = ".rules";
    private final Client client;
    private final ClusterService clusterService;
    private static final Logger logger = LogManager.getLogger(RulePersistenceService.class);
    /**
     * The maximum number of results allowed per GET request
     */
    private static final int MAX_RETURN_SIZE_ALLOWED_PER_GET_REQUEST = 50;
    private static final Map<String, Object> indexSettings = Map.of("index.number_of_shards", 1, "index.auto_expand_replicas", "0-all");

    /**
     * Constructor for RulePersistenceService
     * @param clusterService {@link ClusterService} - The cluster service to be used by RulePersistenceService
     * @param client {@link Client} - The client to be used by RulePersistenceService
     */
    @Inject
    public RulePersistenceService(final ClusterService clusterService, final Client client) {
        this.clusterService = clusterService;
        this.client = client;
    }

    /**
     * Entry point for the create rule api logic in persistence service.
     * @param rule - The rule to update.
     * @param listener - ActionListener for CreateRuleResponse
     */
    public void createRule(Rule rule, ActionListener<CreateRuleResponse> listener) {
        String queryGroupId = rule.getFeatureValue();
        if (!isExistingQueryGroup(queryGroupId)) {
            listener.onFailure(new ResourceNotFoundException("Couldn't find an existing query group with id: " + queryGroupId));
            return;
        }
        try (ThreadContext.StoredContext ctx = getContext()) {
            createIfAbsent(new ActionListener<>() {
                @Override
                public void onResponse(Boolean indexCreated) {
                    if (!indexCreated) {
                        listener.onFailure(new IllegalStateException(RULES_INDEX + " index creation failed and rule cannot be persisted"));
                        return;
                    }
                    checkDuplicateRule(rule, listener);
                }

                @Override
                public void onFailure(Exception e) {
                    listener.onFailure(e);
                }
            });
        }
    }

    /**
     * Check if there's an existing Rule with the same attributes.
     * For example, if there's an existing Rule with the attribute index_pattern: ["a", "b", "c"],
     * then we cannot create another Rule with only one attribute index_pattern: ["b"], because the value "b"
     * already exists under another Rule. Note that the conflict exists only when we have the exact same attribute
     * names in the two rules (That is, a Rule with attribute "index_pattern" won't create a conflict with another
     * Rule that has "index_pattern" and some other attributes).
     * @param rule - The rule to update.
     * @param listener - ActionListener for CreateRuleResponse
     */
    public void checkDuplicateRule(Rule rule, ActionListener<CreateRuleResponse> listener) {
        try (ThreadContext.StoredContext ctx = getContext()) {
            getRule(null, rule.getAttributeMap(), null, new ActionListener<>() {
                @Override
                public void onResponse(GetRuleResponse getRuleResponse) {
                    Map<String, Rule> responseRules = getRuleResponse.getRules();
                    for (Map.Entry<String, Rule> entry : responseRules.entrySet()) {
                        String ruleId = entry.getKey();
                        Rule rule = entry.getValue();
                        if (rule.getAttributeMap().size() == rule.getAttributeMap().size()) {
                            listener.onFailure(
                                new IllegalArgumentException(
                                    "A rule that has the same attribute values already exists under rule id " + ruleId
                                )
                            );
                            return;
                        }
                    }
                    persistRule(rule, listener);
                }

                @Override
                public void onFailure(Exception e) {
                    listener.onFailure(e);
                }
            });
        }
    }

    /**
     * Persist the rule in the index
     * @param rule - The rule to update.
     * @param listener - ActionListener for CreateRuleResponse
     */
    public void persistRule(Rule rule, ActionListener<CreateRuleResponse> listener) {
        try (ThreadContext.StoredContext ctx = getContext()) {
            IndexRequest indexRequest = new IndexRequest(RULES_INDEX).source(
                rule.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS)
            );
            client.index(indexRequest, ActionListener.wrap(indexResponse -> {
                listener.onResponse(new CreateRuleResponse(indexResponse.getId(), rule, RestStatus.OK));
            }, e -> {
                logger.warn("Failed to save Rule object due to error: {}", e.getMessage());
                listener.onFailure(e);
            }));
        } catch (IOException e) {
            logger.error("Error saving rule to index: {}", RULES_INDEX, e);
            listener.onFailure(new RuntimeException("Failed to save rule to index."));
        }
    }

    /**
     * Creates the system index .rules if it doesn't exist
     * @param listener - ActionListener for CreateRuleResponse
     */
    private void createIfAbsent(ActionListener<Boolean> listener) {
        try (ThreadContext.StoredContext ctx = getContext()) {
            if (clusterService.state().metadata().hasIndex(RulePersistenceService.RULES_INDEX)) {
                listener.onResponse(true);
                return;
            }
            final CreateIndexRequest createIndexRequest = new CreateIndexRequest(RulePersistenceService.RULES_INDEX).settings(
                indexSettings
            );
            client.admin().indices().create(createIndexRequest, new ActionListener<>() {
                @Override
                public void onResponse(CreateIndexResponse response) {
                    logger.info("Index {} created?: {}", RulePersistenceService.RULES_INDEX, response.isAcknowledged());
                    listener.onResponse(response.isAcknowledged());
                }

                @Override
                public void onFailure(Exception e) {
                    if (e instanceof ResourceAlreadyExistsException) {
                        logger.info("Index {} already exists", RulePersistenceService.RULES_INDEX);
                        listener.onResponse(true);
                    } else {
                        logger.error("Failed to create index {}: {}", RulePersistenceService.RULES_INDEX, e.getMessage());
                        listener.onFailure(e);
                    }
                }
            });
        }
    }

    /**
     * Entry point for the get rule api logic in persistence service. If id is provided, we only get a single rule.
     * Otherwise, we get all rules that satisfy the attributeFilters.
     * @param id - The id of the rule to get.
     * @param attributeFilters - A map containing the attributes that user want to filter on
     * @param searchAfter - The sort values from the last document of the previous page, used for pagination
     * @param listener - ActionListener for GetRuleResponse
     */
    public void getRule(
        String id,
        Map<Attribute, Set<String>> attributeFilters,
        String searchAfter,
        ActionListener<GetRuleResponse> listener
    ) {
        try (ThreadContext.StoredContext context = getContext()) {
            BoolQueryBuilder boolQuery = buildGetRuleQuery(id, attributeFilters);
            SearchRequestBuilder searchRequest = client.prepareSearch(RULES_INDEX)
                .setQuery(boolQuery)
                .setSize(MAX_RETURN_SIZE_ALLOWED_PER_GET_REQUEST);
            if (searchAfter != null) {
                searchRequest.addSort(_ID_STRING, SortOrder.ASC).searchAfter(new Object[] { searchAfter });
            }
            searchRequest.execute(ActionListener.wrap(searchResponse -> handleGetRuleResponse(id, searchResponse, listener), e -> {
                logger.error("Failed to fetch all rules: {}", e.getMessage());
                listener.onFailure(e);
            }));
        }
    }

    /**
     * Builds a bool query to retrieve rules from the rules index, applying attribute-based filters
     * when needed and ensuring that the rules are associated with the query group feature type.
     * @param id              The ID of the rule to fetch. If not null, the search will return only this specific rule.
     * @param attributeFilters A map of attributes to their associated set of values used to filter the rules.
     */
    BoolQueryBuilder buildGetRuleQuery(String id, Map<Attribute, Set<String>> attributeFilters) {
        BoolQueryBuilder boolQuery = QueryBuilders.boolQuery();
        if (id != null) {
            return boolQuery.must(QueryBuilders.termQuery(_ID_STRING, id));
        }
        for (Map.Entry<Attribute, Set<String>> entry : attributeFilters.entrySet()) {
            Attribute attribute = entry.getKey();
            Set<String> values = entry.getValue();
            if (values != null && !values.isEmpty()) {
                BoolQueryBuilder attributeQuery = QueryBuilders.boolQuery();
                for (String value : values) {
                    attributeQuery.should(QueryBuilders.matchQuery(attribute.getName(), value));
                }
                boolQuery.must(attributeQuery);
            }
        }
        boolQuery.filter(QueryBuilders.existsQuery(QueryGroupFeatureType.NAME));
        return boolQuery;
    }

    /**
     * Process searchResponse from index and send a GetRuleResponse
     * @param searchResponse - Response received from index
     * @param listener - ActionListener for GetRuleResponse
     */
    void handleGetRuleResponse(String id, SearchResponse searchResponse, ActionListener<GetRuleResponse> listener) {
        List<SearchHit> hits = Arrays.asList(searchResponse.getHits().getHits());
        if (id != null && hits.isEmpty()) {
            logger.error("Rule with ID " + id + " not found.");
            listener.onFailure(new ResourceNotFoundException("Rule with ID " + id + " doesn't exist in the .rules index."));
            return;
        }
        Map<String, Rule> ruleMap = hits.stream()
            .map(hit -> parseRule(hit.getId(), hit.getSourceAsString()))
            .filter(Objects::nonNull)
            .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
        String nextSearchAfter = hits.isEmpty() ? null : hits.get(hits.size() - 1).getId();
        listener.onResponse(new GetRuleResponse(ruleMap, nextSearchAfter, RestStatus.OK));
    }

    /**
     * Parses a source string into a Rule object
     * @param id - document id for the Rule object
     * @param source - The raw source string representing the rule to be parsed
     */
    private Map.Entry<String, Rule> parseRule(String id, String source) {
        try (
            XContentParser parser = MediaTypeRegistry.JSON.xContent()
                .createParser(NamedXContentRegistry.EMPTY, DeprecationHandler.THROW_UNSUPPORTED_OPERATION, source)
        ) {
            return Map.entry(id, Builder.fromXContent(parser, QueryGroupFeatureType.INSTANCE).build());
        } catch (IOException e) {
            logger.info("Issue met when parsing rule for ID {}: {}", id, e.getMessage());
            return null;
        }
    }

    /**
     * Entry point for the update rule api logic in persistence service.
     * @param request - The UpdateRuleRequest
     * @param listener - ActionListener for UpdateRuleResponse
     */
    public void updateRule(UpdateRuleRequest request, ActionListener<UpdateRuleResponse> listener) {
        String ruleId = request.get_id();
        String queryGroupId = request.getFeatureValue();
        if (!isExistingQueryGroup(queryGroupId)) {
            listener.onFailure(new ResourceNotFoundException("Couldn't find an existing query group with id: " + queryGroupId));
            return;
        }
        try (ThreadContext.StoredContext context = getContext()) {
            getRule(ruleId, new HashMap<>(), null, new ActionListener<>() {
                @Override
                public void onResponse(GetRuleResponse getRuleResponse) {
                    if (getRuleResponse == null || getRuleResponse.getRules().isEmpty()) {
                        listener.onFailure(new ResourceNotFoundException("Rule with ID " + ruleId + " not found."));
                        return;
                    }
                    Rule updatedRule = composeUpdatedRule(getRuleResponse.getRules().get(ruleId), request);
                    persistUpdatedRule(ruleId, updatedRule, listener);
                }

                @Override
                public void onFailure(Exception e) {
                    listener.onFailure(e);
                }
            });
        }
    }

    /**
     * Compose the updated rule from the original rule and the UpdateRuleRequest
     * @param originalRule - the existing rule
     * @param request - the UpdateRuleRequest
     */
    Rule composeUpdatedRule(Rule originalRule, UpdateRuleRequest request) {
        String requestDescription = request.getDescription();
        Map<Attribute, Set<String>> requestMap = request.getAttributeMap();
        String requestLabel = request.getFeatureValue();
        return new Rule(
            requestDescription == null ? originalRule.getDescription() : requestDescription,
            requestMap == null || requestMap.isEmpty() ? originalRule.getAttributeMap() : requestMap,
            QueryGroupFeatureType.INSTANCE,
            requestLabel == null ? originalRule.getFeatureValue() : requestLabel,
            Instant.now().toString()
        );
    }

    /**
     * Persist the updated rule in index
     * @param ruleId - the rule id to update
     * @param updatedRule - the rule we update to
     * @param listener - ActionListener for UpdateRuleResponse
     */
    public void persistUpdatedRule(String ruleId, Rule updatedRule, ActionListener<UpdateRuleResponse> listener) {
        try (ThreadContext.StoredContext context = getContext()) {
            UpdateRequest updateRequest = new UpdateRequest(RULES_INDEX, ruleId).doc(
                updatedRule.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS)
            );
            client.update(updateRequest, ActionListener.wrap(updateResponse -> {
                listener.onResponse(new UpdateRuleResponse(ruleId, updatedRule, RestStatus.OK));
            }, e -> {
                logger.warn("Failed to update Rule object due to error: {}", e.getMessage());
                listener.onFailure(e);
            }));
        } catch (IOException e) {
            logger.error("Error updating rule in index: {}", RULES_INDEX, e);
            listener.onFailure(new RuntimeException("Failed to update rule to index."));
        }
    }

    private ThreadContext.StoredContext getContext() {
        return client.threadPool().getThreadContext().stashContext();
    }

    private boolean isExistingQueryGroup(String queryGroupId) {
        return clusterService.state().metadata().queryGroups().containsKey(queryGroupId);
    }

    public Client getClient() {
        return client;
    }

    public ClusterService getClusterService() {
        return clusterService;
    }
}
