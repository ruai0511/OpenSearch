/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.plugin.wlm.rule.action;

import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.support.clustermanager.ClusterManagerNodeRequest;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;

import java.io.IOException;

/**
 * A request for deleting a Rule
 * @opensearch.experimental
 */
public class DeleteRuleRequest extends ClusterManagerNodeRequest<DeleteRuleRequest> {
    private final String id;

    /**
     * Constructor for DeleteRuleRequest
     * @param id - Rule id that we want to delete
     */
    public DeleteRuleRequest(String id) {
        this.id = id;
    }

    /**
     * Constructor for DeleteRuleRequest
     * @param in - A {@link StreamInput} object
     */
    public DeleteRuleRequest(StreamInput in) throws IOException {
        super(in);
        id = in.readOptionalString();
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeOptionalString(id);
    }

    /**
     * id getter
     */
    public String get_id() {
        return id;
    }
}
