/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.indices.pollingingest;

import org.opensearch.index.IngestionShardPointer;
import org.opensearch.index.Message;

import java.util.Map;

/**
 * Holds the original message consumed from the streaming source, corresponding pointer and parsed payload map. This
 * will be used by the pull-based ingestion processor/writer threads to update the index.
 */
public record ShardUpdateMessage<T extends IngestionShardPointer, M extends Message>(T pointer, M originalMessage, Map<
    String,
    Object> parsedPayloadMap, long autoGeneratedIdTimestamp) {
}
