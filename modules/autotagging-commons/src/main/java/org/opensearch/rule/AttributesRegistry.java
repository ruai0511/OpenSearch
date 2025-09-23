/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.rule;

import org.opensearch.rule.autotagging.Attribute;
import org.opensearch.rule.autotagging.FeatureType;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * test
 */
public class AttributesRegistry {
    private final Map<String, Attribute> attributesRegistry = new ConcurrentHashMap<>();

    /**
     * default constructor
     */
    public AttributesRegistry() {}

    /**
     * This method is used to register the concrete implementations of RuleRoutingService
     * @param attribute
     */
    public void register(Attribute attribute) {
        if (attributesRegistry.put(attribute.getName(), attribute) != null) {
            throw new IllegalArgumentException("Duplicate attributes: " + attribute.getName());
        }
    }

    /**
     * It is used to get feature type specific {@link RuleRoutingService} implementation
     * @param name
     */
    public Attribute getRuleRoutingService(String name) {
        if (!attributesRegistry.containsKey(name)) {
            throw new IllegalArgumentException("Unknown attribute: " + name);
        }
        return attributesRegistry.get(name);
    }
}
