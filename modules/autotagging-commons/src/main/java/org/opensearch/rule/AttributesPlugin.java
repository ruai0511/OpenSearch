/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.rule;

import org.opensearch.plugins.ExtensiblePlugin;
import org.opensearch.plugins.Plugin;
import org.opensearch.rule.autotagging.Attribute;
import org.opensearch.rule.spi.AttributesExtension;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Collection;

/**
 * test
 */
public class AttributesPlugin extends Plugin implements ExtensiblePlugin {
    /**
     * constructor for RuleFrameworkPlugin
     */
    public AttributesPlugin() {}

    /**
     * test
     */
    public static final Map<String, AttributesExtension> attributesExtensions = new HashMap<>();

    @Override
    public void loadExtensions(ExtensionLoader loader) {
        Collection<AttributesExtension> loaded = loader.loadExtensions(AttributesExtension.class);
        for (AttributesExtension ext : loaded) {
            attributesExtensions.put(ext.getAttribute().getName(), ext);
            System.out.println("Security plugin loaded: " + ext.getAttribute().getName());
        }
    }
}
