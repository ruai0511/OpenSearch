/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.autotagging;

import org.opensearch.core.common.io.stream.Writeable;

/**
 * Represents an attribute within the auto-tagging feature. Attributes define characteristics that can
 * be used for tagging and classification. Implementations of this interface are responsible for registering
 * attributes in {@link AutoTaggingRegistry}.
 * @opensearch.experimental
 */
public interface Attribute extends Writeable {
    String getName();
    void registerAttribute();
}
