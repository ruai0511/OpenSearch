/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.autotagging;

import org.opensearch.common.collect.Tuple;
import org.opensearch.test.OpenSearchTestCase;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.opensearch.autotagging.RuleTests.TEST_ATTR1_NAME;
import static org.opensearch.autotagging.RuleTests.TEST_FEATURE_TYPE;

public class AutoTaggingRegistryTests extends OpenSearchTestCase {
    private static final String NON_EXISTENT_CLASS = "non_existent_class";
    private static final String NON_EXISTENT_ATTRIBUTE = "non_existent_attribute";
    private static final String NON_EXISTENT_FEATURE = "non_existent_feature";

    public void testRegisterFeatureType_Success() {
        FeatureType featureType = mock(FeatureType.class);
        when(featureType.getName()).thenReturn(TEST_FEATURE_TYPE);

        AutoTaggingRegistry.registerFeatureType(featureType);

        Tuple<String, String> key = new Tuple<>(featureType.getClass().getName(), TEST_FEATURE_TYPE);
        assertTrue(AutoTaggingRegistry.featureTypesRegistryMap.containsKey(key));
        assertEquals(featureType, AutoTaggingRegistry.featureTypesRegistryMap.get(key));
    }

    public void testRegisterFeatureType_Null_ThrowsException() {
        Exception exception = assertThrows(IllegalStateException.class, () ->
            AutoTaggingRegistry.registerFeatureType(null)
        );
        assertEquals("Feature type is not initialized and can't be registered", exception.getMessage());
    }

    public void testRegisterAttribute_Success() {
        Attribute attribute = mock(Attribute.class);
        when(attribute.getName()).thenReturn(TEST_ATTR1_NAME);

        AutoTaggingRegistry.registerAttribute(attribute);

        Tuple<String, String> key = new Tuple<>(attribute.getClass().getName(), TEST_ATTR1_NAME);
        assertTrue(AutoTaggingRegistry.attributeRegistryMap.containsKey(key));
        assertEquals(attribute, AutoTaggingRegistry.attributeRegistryMap.get(key));
    }

    public void testRegisterAttribute_Null_ThrowsException() {
        Exception exception = assertThrows(IllegalStateException.class, () ->
            AutoTaggingRegistry.registerAttribute(null)
        );
        assertEquals("Attribute is not initialized and can't be registered", exception.getMessage());
    }

    public void testGetFeatureType_Success() {
        FeatureType featureType = mock(FeatureType.class);
        when(featureType.getName()).thenReturn(TEST_FEATURE_TYPE);

        AutoTaggingRegistry.registerFeatureType(featureType);

        FeatureType retrievedFeatureType = AutoTaggingRegistry.getFeatureType(featureType.getClass().getName(), TEST_FEATURE_TYPE);
        assertEquals(featureType, retrievedFeatureType);
    }

    public void testGetFeatureType_NotFound_ThrowsException() {
        Exception exception = assertThrows(RuntimeException.class, () ->
            AutoTaggingRegistry.getFeatureType(NON_EXISTENT_CLASS, NON_EXISTENT_FEATURE)
        );
        assertTrue(exception.getMessage().contains("Couldn't find a feature type with name: " + NON_EXISTENT_FEATURE));
    }

    public void testGetAttribute_Success() {
        Attribute attribute = mock(Attribute.class);
        when(attribute.getName()).thenReturn(TEST_ATTR1_NAME);

        AutoTaggingRegistry.registerAttribute(attribute);

        Attribute retrievedAttribute = AutoTaggingRegistry.getAttribute(attribute.getClass().getName(), TEST_ATTR1_NAME);
        assertEquals(attribute, retrievedAttribute);
    }

    public void testGetAttribute_NotFound_ThrowsException() {
        Exception exception = assertThrows(RuntimeException.class, () ->
            AutoTaggingRegistry.getAttribute(NON_EXISTENT_CLASS, NON_EXISTENT_ATTRIBUTE)
        );
        assertTrue(exception.getMessage().contains("Couldn't find a attribute with name: " + NON_EXISTENT_ATTRIBUTE));
    }
}
