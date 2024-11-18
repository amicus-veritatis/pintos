#ifndef THREADS_FIXED_POINT_H
#define THREADS_FIXED_POINT_H

#define Q 14
#define F (1<<Q)
#define P 17

typedef int float32_t;

static float32_t itof(int n)
{
	return n * F;
}

static float32_t mul(float32_t x, float32_t y)
{
	return ((int64_t) x) * y / F;
}

static float32_t imul(float32_t x, int n)
{
	return x * n;
}

static float32_t div(float32_t x, float32_t y)
{
	return ((int64_t) x) * F / y;
}

static float32_t idiv(float32_t x, int n)
{
	return x / n;
}

static float32_t add(float32_t x, float32_t y)
{
	return x + y;
}

static float32_t sub(float32_t x, float32_t y)
{
	return x - y;
}

static int ffloor(float32_t x)
{
	return x / F;
}

static int fround(float32_t x)
{
	if (x >= 0) {
		return (x + F / 2) / F;
	}
	return (x - F / 2) / F;
}

#endif
