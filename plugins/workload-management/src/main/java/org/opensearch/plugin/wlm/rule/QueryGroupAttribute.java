/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.plugin.wlm.rule;


import org.opensearch.autotagging.Attribute;
import org.opensearch.autotagging.AutoTaggingRegistry;
import org.opensearch.core.common.io.stream.StreamOutput;

import java.io.IOException;

/**
 * Attributes specific to the query group feature.
 */
public enum QueryGroupAttribute implements Attribute {
    INDEX_PATTERN("index_pattern");

    private final String name;

    QueryGroupAttribute(String name) {
        this.name = name;
    }

    static {
        for (QueryGroupAttribute attr: QueryGroupAttribute.values()) {
            attr.registerAttribute();
        }
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public void registerAttribute() {
        AutoTaggingRegistry.registerAttribute(this);
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(name);
    }

    public static QueryGroupAttribute fromName(String name) {
        for (QueryGroupAttribute attr : QueryGroupAttribute.values()) {
            if (attr.getName().equals(name)) {
                return attr;
            }
        }
        throw new IllegalArgumentException("Unknown QueryGroupAttribute: " + name);
    }
}
