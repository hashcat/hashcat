# Test Suite for SSE2NEON

:warning: **Warning: The test suite is based on the little-endian architecture.**

## Add More Test Items
Once the conversion is implemented, the test can be added with the following steps:

* File `tests/impl.h`

  Add the intrinsic under `INTRIN_LIST` macro. The naming convention
  should be `mm_xxx`.
  Place it in the correct classification with the alphabetical order.
  The classification can be referenced from [Intel Intrinsics Guide](https://www.intel.com/content/www/us/en/docs/intrinsics-guide/index.html).

* File `tests/impl.cpp`
    ```c
    result_t test_mm_xxx()
    {
        // The C implementation
        ...

        // The Neon implementation
        ret = _mm_xxx();

        // Compare the result of two implementations and return either
        // TEST_SUCCESS, TEST_FAIL, or TEST_UNIMPL
        ...
    }
    ```
