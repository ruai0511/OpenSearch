package org.opensearch.autotagging;

import org.opensearch.common.ValidationException;
import org.opensearch.common.xcontent.json.JsonXContent;
import org.opensearch.core.common.io.stream.NamedWriteableRegistry;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.test.AbstractSerializingTestCase;
import org.opensearch.test.OpenSearchTestCase;

import java.io.IOException;
import java.time.Instant;
import java.util.*;

import static org.mockito.Mockito.*;
import static org.opensearch.autotagging.Rule._ID_STRING;
import static org.opensearch.autotagging.RuleTests.*;
import static org.opensearch.autotagging.RuleTests.TestAttribute.TEST_ATTRIBUTE_1;

public class FeatureTypeTests extends OpenSearchTestCase {
    public void testIsValidAttribute() {
        assertTrue(FEATURE_TYPE.isValidAttribute(TEST_ATTRIBUTE_1));
        assertFalse(FEATURE_TYPE.isValidAttribute(mock(Attribute.class)));
    }

    public void testGetAttributeFromName() {
        assertEquals(TEST_ATTRIBUTE_1, FEATURE_TYPE.getAttributeFromName(TEST_ATTR1_NAME));
        assertNull(FEATURE_TYPE.getAttributeFromName("invalid_attribute"));
    }

    public void testValidateAttributeMap() {
        ValidationException validationException = new ValidationException();
        Map<Attribute, Set<String>> validMap = Map.of(TEST_ATTRIBUTE_1, Set.of("value1", "value2"));
        FEATURE_TYPE.validateAttributeMap(validMap, validationException);
        assertTrue(validationException.validationErrors().isEmpty());

        Map<Attribute, Set<String>> invalidMap = Map.of(mock(Attribute.class), Set.of("invalid_value"));
        FEATURE_TYPE.validateAttributeMap(invalidMap, validationException);
        assertFalse(validationException.validationErrors().isEmpty());
    }

    public void testWriteTo() throws IOException {
        StreamOutput mockOutput = mock(StreamOutput.class);
        FEATURE_TYPE.writeTo(mockOutput);
        verify(mockOutput).writeString(anyString());
    }
}
