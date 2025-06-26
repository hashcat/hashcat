#include "common.h"
#include <cmath>
#include <cstdint>

namespace SSE2NEON
{
int32_t NaN = ~0;
int64_t NaN64 = ~0;

result_t validateInt64(__m128i a, int64_t i0, int64_t i1)
{
    const int64_t *t = (const int64_t *) &a;
    ASSERT_RETURN(t[0] == i0);
    ASSERT_RETURN(t[1] == i1);
    return TEST_SUCCESS;
}

result_t validateInt64(__m64 a, int64_t i0)
{
    const int64_t *t = (const int64_t *) &a;
    ASSERT_RETURN(t[0] == i0);
    return TEST_SUCCESS;
}

result_t validateUInt64(__m128i a, uint64_t u0, uint64_t u1)
{
    const uint64_t *t = (const uint64_t *) &a;
    ASSERT_RETURN(t[0] == u0);
    ASSERT_RETURN(t[1] == u1);
    return TEST_SUCCESS;
}

result_t validateUInt64(__m64 a, uint64_t u0)
{
    const uint64_t *t = (const uint64_t *) &a;
    ASSERT_RETURN(t[0] == u0);
    return TEST_SUCCESS;
}

result_t validateInt32(__m128i a,
                       int32_t i0,
                       int32_t i1,
                       int32_t i2,
                       int32_t i3)
{
    const int32_t *t = (const int32_t *) &a;
    ASSERT_RETURN(t[0] == i0);
    ASSERT_RETURN(t[1] == i1);
    ASSERT_RETURN(t[2] == i2);
    ASSERT_RETURN(t[3] == i3);
    return TEST_SUCCESS;
}

result_t validateUInt32(__m128i a,
                        uint32_t u0,
                        uint32_t u1,
                        uint32_t u2,
                        uint32_t u3)
{
    const uint32_t *t = (const uint32_t *) &a;
    ASSERT_RETURN(t[0] == u0);
    ASSERT_RETURN(t[1] == u1);
    ASSERT_RETURN(t[2] == u2);
    ASSERT_RETURN(t[3] == u3);
    return TEST_SUCCESS;
}

result_t validateUInt32(__m64 a, uint32_t u0, uint32_t u1)
{
    const uint32_t *t = (const uint32_t *) &a;
    ASSERT_RETURN(t[0] == u0);
    ASSERT_RETURN(t[1] == u1);
    return TEST_SUCCESS;
}

result_t validateInt16(__m128i a,
                       int16_t i0,
                       int16_t i1,
                       int16_t i2,
                       int16_t i3,
                       int16_t i4,
                       int16_t i5,
                       int16_t i6,
                       int16_t i7)
{
    const int16_t *t = (const int16_t *) &a;
    ASSERT_RETURN(t[0] == i0);
    ASSERT_RETURN(t[1] == i1);
    ASSERT_RETURN(t[2] == i2);
    ASSERT_RETURN(t[3] == i3);
    ASSERT_RETURN(t[4] == i4);
    ASSERT_RETURN(t[5] == i5);
    ASSERT_RETURN(t[6] == i6);
    ASSERT_RETURN(t[7] == i7);
    return TEST_SUCCESS;
}

result_t validateInt16(__m64 a, int16_t i0, int16_t i1, int16_t i2, int16_t i3)
{
    const int16_t *t = (const int16_t *) &a;
    ASSERT_RETURN(t[0] == i0);
    ASSERT_RETURN(t[1] == i1);
    ASSERT_RETURN(t[2] == i2);
    ASSERT_RETURN(t[3] == i3);
    return TEST_SUCCESS;
}

result_t validateUInt16(__m128i a,
                        uint16_t u0,
                        uint16_t u1,
                        uint16_t u2,
                        uint16_t u3,
                        uint16_t u4,
                        uint16_t u5,
                        uint16_t u6,
                        uint16_t u7)
{
    const uint16_t *t = (const uint16_t *) &a;
    ASSERT_RETURN(t[0] == u0);
    ASSERT_RETURN(t[1] == u1);
    ASSERT_RETURN(t[2] == u2);
    ASSERT_RETURN(t[3] == u3);
    ASSERT_RETURN(t[4] == u4);
    ASSERT_RETURN(t[5] == u5);
    ASSERT_RETURN(t[6] == u6);
    ASSERT_RETURN(t[7] == u7);
    return TEST_SUCCESS;
}

result_t validateInt32(__m64 a, int32_t u0, int32_t u1)
{
    const int32_t *t = (const int32_t *) &a;
    ASSERT_RETURN(t[0] == u0);
    ASSERT_RETURN(t[1] == u1);
    return TEST_SUCCESS;
}

result_t validateUInt16(__m64 a,
                        uint16_t u0,
                        uint16_t u1,
                        uint16_t u2,
                        uint16_t u3)
{
    const uint16_t *t = (const uint16_t *) &a;
    ASSERT_RETURN(t[0] == u0);
    ASSERT_RETURN(t[1] == u1);
    ASSERT_RETURN(t[2] == u2);
    ASSERT_RETURN(t[3] == u3);
    return TEST_SUCCESS;
}

result_t validateInt8(__m128i a,
                      int8_t i0,
                      int8_t i1,
                      int8_t i2,
                      int8_t i3,
                      int8_t i4,
                      int8_t i5,
                      int8_t i6,
                      int8_t i7,
                      int8_t i8,
                      int8_t i9,
                      int8_t i10,
                      int8_t i11,
                      int8_t i12,
                      int8_t i13,
                      int8_t i14,
                      int8_t i15)
{
    const int8_t *t = (const int8_t *) &a;
    ASSERT_RETURN(t[0] == i0);
    ASSERT_RETURN(t[1] == i1);
    ASSERT_RETURN(t[2] == i2);
    ASSERT_RETURN(t[3] == i3);
    ASSERT_RETURN(t[4] == i4);
    ASSERT_RETURN(t[5] == i5);
    ASSERT_RETURN(t[6] == i6);
    ASSERT_RETURN(t[7] == i7);
    ASSERT_RETURN(t[8] == i8);
    ASSERT_RETURN(t[9] == i9);
    ASSERT_RETURN(t[10] == i10);
    ASSERT_RETURN(t[11] == i11);
    ASSERT_RETURN(t[12] == i12);
    ASSERT_RETURN(t[13] == i13);
    ASSERT_RETURN(t[14] == i14);
    ASSERT_RETURN(t[15] == i15);
    return TEST_SUCCESS;
}

result_t validateInt8(__m64 a,
                      int8_t i0,
                      int8_t i1,
                      int8_t i2,
                      int8_t i3,
                      int8_t i4,
                      int8_t i5,
                      int8_t i6,
                      int8_t i7)
{
    const int8_t *t = (const int8_t *) &a;
    ASSERT_RETURN(t[0] == i0);
    ASSERT_RETURN(t[1] == i1);
    ASSERT_RETURN(t[2] == i2);
    ASSERT_RETURN(t[3] == i3);
    ASSERT_RETURN(t[4] == i4);
    ASSERT_RETURN(t[5] == i5);
    ASSERT_RETURN(t[6] == i6);
    ASSERT_RETURN(t[7] == i7);
    return TEST_SUCCESS;
}

result_t validateUInt8(__m128i a,
                       uint8_t u0,
                       uint8_t u1,
                       uint8_t u2,
                       uint8_t u3,
                       uint8_t u4,
                       uint8_t u5,
                       uint8_t u6,
                       uint8_t u7,
                       uint8_t u8,
                       uint8_t u9,
                       uint8_t u10,
                       uint8_t u11,
                       uint8_t u12,
                       uint8_t u13,
                       uint8_t u14,
                       uint8_t u15)
{
    const uint8_t *t = (const uint8_t *) &a;
    ASSERT_RETURN(t[0] == u0);
    ASSERT_RETURN(t[1] == u1);
    ASSERT_RETURN(t[2] == u2);
    ASSERT_RETURN(t[3] == u3);
    ASSERT_RETURN(t[4] == u4);
    ASSERT_RETURN(t[5] == u5);
    ASSERT_RETURN(t[6] == u6);
    ASSERT_RETURN(t[7] == u7);
    ASSERT_RETURN(t[8] == u8);
    ASSERT_RETURN(t[9] == u9);
    ASSERT_RETURN(t[10] == u10);
    ASSERT_RETURN(t[11] == u11);
    ASSERT_RETURN(t[12] == u12);
    ASSERT_RETURN(t[13] == u13);
    ASSERT_RETURN(t[14] == u14);
    ASSERT_RETURN(t[15] == u15);
    return TEST_SUCCESS;
}

result_t validateUInt8(__m64 a,
                       uint8_t u0,
                       uint8_t u1,
                       uint8_t u2,
                       uint8_t u3,
                       uint8_t u4,
                       uint8_t u5,
                       uint8_t u6,
                       uint8_t u7)
{
    const uint8_t *t = (const uint8_t *) &a;
    ASSERT_RETURN(t[0] == u0);
    ASSERT_RETURN(t[1] == u1);
    ASSERT_RETURN(t[2] == u2);
    ASSERT_RETURN(t[3] == u3);
    ASSERT_RETURN(t[4] == u4);
    ASSERT_RETURN(t[5] == u5);
    ASSERT_RETURN(t[6] == u6);
    ASSERT_RETURN(t[7] == u7);
    return TEST_SUCCESS;
}

result_t validateSingleFloatPair(float a, float b)
{
    const uint32_t *ua = (const uint32_t *) &a;
    const uint32_t *ub = (const uint32_t *) &b;
    // We do an integer (binary) compare rather than a
    // floating point compare to take NaNs and infinities
    // into account as well.
    return (*ua) == (*ub) ? TEST_SUCCESS : TEST_FAIL;
}

result_t validateSingleDoublePair(double a, double b)
{
    const uint64_t *ua = (const uint64_t *) &a;
    const uint64_t *ub = (const uint64_t *) &b;
    // We do an integer (binary) compare rather than a
    // floating point compare to take NaNs and infinities
    // into account as well.

    if (std::isnan(a) && std::isnan(b)) {
        return TEST_SUCCESS;
    }

    return (*ua) == (*ub) ? TEST_SUCCESS : TEST_FAIL;
}

result_t validateFloat(__m128 a, float f0, float f1, float f2, float f3)
{
    const float *t = (const float *) &a;
    ASSERT_RETURN(validateSingleFloatPair(t[0], f0));
    ASSERT_RETURN(validateSingleFloatPair(t[1], f1));
    ASSERT_RETURN(validateSingleFloatPair(t[2], f2));
    ASSERT_RETURN(validateSingleFloatPair(t[3], f3));
    return TEST_SUCCESS;
}

result_t validateFloatEpsilon(__m128 a,
                              float f0,
                              float f1,
                              float f2,
                              float f3,
                              float epsilon)
{
    const float *t = (const float *) &a;
    float df0 = fabsf(t[0] - f0);
    float df1 = fabsf(t[1] - f1);
    float df2 = fabsf(t[2] - f2);
    float df3 = fabsf(t[3] - f3);

    // Due to floating-point error, subtracting floating-point number with NaN
    // and zero value usually produces erroneous result. Therefore, we directly
    // define the difference of two floating-point numbers to zero if both
    // numbers are NaN or zero.
    if ((std::isnan(t[0]) && std::isnan(f0)) || (t[0] == 0 && f0 == 0)) {
        df0 = 0;
    }

    if ((std::isnan(t[1]) && std::isnan(f1)) || (t[1] == 0 && f1 == 0)) {
        df1 = 0;
    }

    if ((std::isnan(t[2]) && std::isnan(f2)) || (t[2] == 0 && f2 == 0)) {
        df2 = 0;
    }

    if ((std::isnan(t[3]) && std::isnan(f3)) || (t[3] == 0 && f3 == 0)) {
        df3 = 0;
    }

    ASSERT_RETURN(df0 < epsilon);
    ASSERT_RETURN(df1 < epsilon);
    ASSERT_RETURN(df2 < epsilon);
    ASSERT_RETURN(df3 < epsilon);
    return TEST_SUCCESS;
}

result_t validateFloatError(__m128 a,
                            float f0,
                            float f1,
                            float f2,
                            float f3,
                            float err)
{
    const float *t = (const float *) &a;
    float df0 = fabsf((t[0] - f0) / f0);
    float df1 = fabsf((t[1] - f1) / f1);
    float df2 = fabsf((t[2] - f2) / f2);
    float df3 = fabsf((t[3] - f3) / f3);

    if ((std::isnan(t[0]) && std::isnan(f0)) || (t[0] == 0 && f0 == 0) ||
        (std::isinf(t[0]) && std::isinf(f0))) {
        df0 = 0;
    }

    if ((std::isnan(t[1]) && std::isnan(f1)) || (t[1] == 0 && f1 == 0) ||
        (std::isinf(t[1]) && std::isinf(f1))) {
        df1 = 0;
    }

    if ((std::isnan(t[2]) && std::isnan(f2)) || (t[2] == 0 && f2 == 0) ||
        (std::isinf(t[2]) && std::isinf(f2))) {
        df2 = 0;
    }

    if ((std::isnan(t[3]) && std::isnan(f3)) || (t[3] == 0 && f3 == 0) ||
        (std::isinf(t[3]) && std::isinf(f3))) {
        df3 = 0;
    }

    ASSERT_RETURN(df0 < err);
    ASSERT_RETURN(df1 < err);
    ASSERT_RETURN(df2 < err);
    ASSERT_RETURN(df3 < err);
    return TEST_SUCCESS;
}

result_t validateDouble(__m128d a, double d0, double d1)
{
    const double *t = (const double *) &a;
    ASSERT_RETURN(validateSingleDoublePair(t[0], d0));
    ASSERT_RETURN(validateSingleDoublePair(t[1], d1));
    return TEST_SUCCESS;
}

result_t validateFloatError(__m128d a, double d0, double d1, double err)
{
    const double *t = (const double *) &a;
    double td0 = fabs((t[0] - d0) / d0);
    double td1 = fabs((t[1] - d1) / d1);

    if (std::isnan(t[0]) && std::isnan(d0)) {
        td0 = 0;
    }

    if (std::isnan(t[1]) && std::isnan(d1)) {
        td1 = 0;
    }

    ASSERT_RETURN(td0 < err);
    ASSERT_RETURN(td1 < err);
    return TEST_SUCCESS;
}

}  // namespace SSE2NEON
