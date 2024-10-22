/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.plugin.wlm.action;

import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.clustermanager.TransportClusterManagerNodeAction;
import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.block.ClusterBlockException;
import org.opensearch.cluster.block.ClusterBlockLevel;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.plugin.wlm.service.QueryGroupPersistenceService;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

import java.io.IOException;

/**
 * Transport action to create QueryGroup
 *
 * @opensearch.experimental
 */
public class TransportCreateQueryGroupAction extends TransportClusterManagerNodeAction<CreateQueryGroupRequest, AcknowledgedResponse> {

    private final QueryGroupPersistenceService queryGroupPersistenceService;

    /**
     * Constructor for TransportCreateQueryGroupAction
     *
     * @param clusterService - a {@link ClusterService} object
     * @param transportService - a {@link TransportService} object
     * @param actionFilters - a {@link ActionFilters} object
     * @param threadPool - a {@link ThreadPool} object
     * @param indexNameExpressionResolver - a {@link IndexNameExpressionResolver} object
     * @param queryGroupPersistenceService - a {@link QueryGroupPersistenceService} object
     */
    @Inject
    public TransportCreateQueryGroupAction(
        ClusterService clusterService,
        TransportService transportService,
        ActionFilters actionFilters,
        ThreadPool threadPool,
        IndexNameExpressionResolver indexNameExpressionResolver,
        QueryGroupPersistenceService queryGroupPersistenceService
    ) {
        super(
            CreateQueryGroupAction.NAME,
            transportService,
            clusterService,
            threadPool,
            actionFilters,
            CreateQueryGroupRequest::new,
            indexNameExpressionResolver
        );
        this.queryGroupPersistenceService = queryGroupPersistenceService;
    }

    @Override
    protected void clusterManagerOperation(
        CreateQueryGroupRequest request,
        ClusterState state,
        ActionListener<AcknowledgedResponse> listener
    ) throws Exception {
        queryGroupPersistenceService.persistInClusterStateMetadata(request, listener);
    }

    @Override
    protected String executor() {
        return ThreadPool.Names.SAME;
    }

    @Override
    protected AcknowledgedResponse read(StreamInput in) throws IOException {
        return new AcknowledgedResponse(in);
    }

    @Override
    protected ClusterBlockException checkBlock(CreateQueryGroupRequest request, ClusterState state) {
        return state.blocks().globalBlockedException(ClusterBlockLevel.METADATA_WRITE);
    }
}
