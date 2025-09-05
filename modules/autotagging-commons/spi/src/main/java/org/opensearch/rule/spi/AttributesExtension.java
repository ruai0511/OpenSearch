/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.rule.spi;

import org.opensearch.rule.RulePersistenceService;
import org.opensearch.rule.RuleRoutingService;
import org.opensearch.rule.autotagging.Attribute;
import org.opensearch.rule.autotagging.FeatureType;

import java.util.function.Supplier;

/**
 * test
 */
public interface AttributesExtension {
    /**
     * test
     * @return
     */
    Attribute getAttribute();
}
