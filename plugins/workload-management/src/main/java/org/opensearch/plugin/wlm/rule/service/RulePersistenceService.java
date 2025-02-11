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
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.SearchResponse;
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
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.plugin.wlm.rule.action.CreateRuleResponse;
import org.opensearch.plugin.wlm.rule.action.GetRuleResponse;
import org.opensearch.wlm.Rule;
import org.opensearch.wlm.Rule.Builder;
import org.opensearch.wlm.Rule.RuleAttribute;

import java.io.IOException;
import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * This class defines the functions for Rule persistence
 * @opensearch.experimental
 */
public class RulePersistenceService {
    public static final String RULE_INDEX = ".rule";
    private final Client client;
    private final ClusterService clusterService;
    private static final Logger logger = LogManager.getLogger(RulePersistenceService.class);

    /**
     * Constructor for RulePersistenceService
     * @param client {@link Client} - The client to be used by RulePersistenceService
     */
    @Inject
    public RulePersistenceService(final ClusterService clusterService, final Client client) {
        this.clusterService = clusterService;
        this.client = client;
    }

    public void createRule(Rule rule, ActionListener<CreateRuleResponse> listener) {
        final Map<String, Object> indexSettings = Map.of("index.number_of_shards", 1, "index.auto_expand_replicas", "0-all");
        createIfAbsent(indexSettings, new ActionListener<>() {
            @Override
            public void onResponse(Boolean indexCreated) {
                persistRule(rule, listener);
            }

            @Override
            public void onFailure(Exception e) {
                listener.onFailure(e);
            }
        });
    }

    public void persistRule(Rule rule, ActionListener<CreateRuleResponse> listener) {
        try (ThreadContext.StoredContext context = client.threadPool().getThreadContext().stashContext()) {
            IndexRequest indexRequest = new IndexRequest(RULE_INDEX).source(
                rule.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS)
            );

            client.index(indexRequest, ActionListener.wrap(indexResponse -> {
                CreateRuleResponse createRuleResponse = new CreateRuleResponse(indexResponse.getId(), rule, RestStatus.OK);
                listener.onResponse(createRuleResponse);
            }, e -> {
                logger.warn("Failed to save Rule object due to error: {}", e.getMessage());
                listener.onFailure(e);
            }));
        } catch (IOException e) {
            logger.error("Error saving rule to index: {}", RULE_INDEX, e);
            listener.onFailure(new RuntimeException("Failed to save rule to index."));
        }
    }

    private void createIfAbsent(Map<String, Object> indexSettings, ActionListener<Boolean> listener) {
        if (clusterService.state().metadata().hasIndex(RulePersistenceService.RULE_INDEX)) {
            listener.onResponse(true);
            return;
        }
        try (ThreadContext.StoredContext context = client.threadPool().getThreadContext().stashContext()) {
            final CreateIndexRequest createIndexRequest = new CreateIndexRequest(RulePersistenceService.RULE_INDEX).settings(indexSettings);
            client.admin().indices().create(createIndexRequest, new ActionListener<>() {
                @Override
                public void onResponse(CreateIndexResponse response) {
                    logger.info("Index {} created?: {}", RulePersistenceService.RULE_INDEX, response.isAcknowledged());
                    listener.onResponse(response.isAcknowledged());
                }

                @Override
                public void onFailure(Exception e) {
                    if (e instanceof ResourceAlreadyExistsException) {
                        logger.info("Index {} already exists", RulePersistenceService.RULE_INDEX);
                        listener.onResponse(true);
                    } else {
                        logger.error("Failed to create index {}: {}", RulePersistenceService.RULE_INDEX, e.getMessage());
                        listener.onFailure(e);
                    }
                }
            });
        }
    }

    public void getRule(String id, Map<RuleAttribute, Set<String>> attributeFilters, ActionListener<GetRuleResponse> listener) {
        if (id != null) {
            fetchRuleById(id, listener);
        } else {
            fetchAllRules(attributeFilters, listener);
        }
    }

    private void fetchRuleById(String id, ActionListener<GetRuleResponse> listener) {
        client.prepareGet(RULE_INDEX, id)
            .execute(ActionListener.wrap(getResponse -> handleGetOneRuleResponse(id, getResponse, listener), e -> {
                logger.error("Failed to fetch rule with ID {}: {}", id, e.getMessage());
                listener.onFailure(e);
            }));
    }

    private void handleGetOneRuleResponse(String id, GetResponse getResponse, ActionListener<GetRuleResponse> listener) {
        if (getResponse.isExists()) {
            try (ThreadContext.StoredContext context = client.threadPool().getThreadContext().stashContext()) {
                XContentParser parser = MediaTypeRegistry.JSON.xContent()
                    .createParser(
                        NamedXContentRegistry.EMPTY,
                        DeprecationHandler.THROW_UNSUPPORTED_OPERATION,
                        getResponse.getSourceAsString()
                    );
                listener.onResponse(new GetRuleResponse(Map.of(id, Builder.fromXContent(parser).build()), RestStatus.OK));
            } catch (IOException e) {
                logger.error("Error parsing rule with ID {}: {}", id, e.getMessage());
                listener.onFailure(e);
            }
        } else {
            listener.onFailure(new ResourceNotFoundException("Rule with ID " + id + " not found."));
        }
    }

    private boolean matchesFilters(Rule rule, Map<RuleAttribute, Set<String>> attributeFilters) {
        for (Map.Entry<RuleAttribute, Set<String>> entry : attributeFilters.entrySet()) {
            RuleAttribute attribute = entry.getKey();
            Set<String> expectedValues = entry.getValue();
            Set<String> ruleValues = rule.getAttributeMap().get(attribute);
            if (ruleValues == null || ruleValues.stream().noneMatch(expectedValues::contains)) {
                return false;
            }
        }
        return true;
    }

    private void fetchAllRules(Map<RuleAttribute, Set<String>> attributeFilters, ActionListener<GetRuleResponse> listener) {
        client.prepareSearch(RULE_INDEX)
            .setQuery(QueryBuilders.matchAllQuery())
            .setSize(20)
            .execute(ActionListener.wrap(searchResponse -> handleGetAllRuleResponse(searchResponse, attributeFilters, listener), e -> {
                logger.error("Failed to fetch all rules: {}", e.getMessage());
                listener.onFailure(e);
            }));
    }

    private void handleGetAllRuleResponse(
        SearchResponse searchResponse,
        Map<RuleAttribute, Set<String>> attributeFilters,
        ActionListener<GetRuleResponse> listener
    ) {
        Map<String, Rule> ruleMap = Arrays.stream(searchResponse.getHits().getHits()).map(hit -> {
            try (ThreadContext.StoredContext context = client.threadPool().getThreadContext().stashContext()) {
                XContentParser parser = MediaTypeRegistry.JSON.xContent()
                    .createParser(NamedXContentRegistry.EMPTY, DeprecationHandler.THROW_UNSUPPORTED_OPERATION, hit.getSourceAsString());
                Rule currRule = Rule.Builder.fromXContent(parser).build();
                if (matchesFilters(currRule, attributeFilters)) {
                    return Map.entry(hit.getId(), currRule);
                }
                return null;
            } catch (IOException e) {
                logger.error("Failed to parse rule from hit: {}", e.getMessage());
                listener.onFailure(e);
                return null;
            }
        }).filter(Objects::nonNull).collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
        listener.onResponse(new GetRuleResponse(ruleMap, RestStatus.OK));
    }

    public Client getClient() {
        return client;
    }
}
