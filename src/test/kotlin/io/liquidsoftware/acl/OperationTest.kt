package io.liquidsoftware.acl

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class OperationTest {
    @Test
    fun manage_covers_read_and_write() {
        assertTrue(Operation.Manage.covers(Operation.Read))
        assertTrue(Operation.Manage.covers(Operation.Write))
        assertTrue(Operation.Manage.covers(Operation.Manage))
    }

    @Test
    fun read_and_write_do_not_cover_each_other() {
        assertFalse(Operation.Read.covers(Operation.Write))
        assertFalse(Operation.Write.covers(Operation.Read))
    }

    @Test
    fun read_and_write_cover_themselves() {
        assertTrue(Operation.Read.covers(Operation.Read))
        assertTrue(Operation.Write.covers(Operation.Write))
    }
}
