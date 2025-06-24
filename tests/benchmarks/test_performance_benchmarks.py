import asyncio
import gc
import time
from statistics import mean, median, stdev

import pytest
from fastapi.testclient import TestClient
from httpx import AsyncClient

from src.main import app


class TestPerformanceBenchmarks:
    """Detailed performance benchmarks for the API."""

    def benchmark_sync_endpoint(self, benchmark, client: TestClient):
        """Benchmark synchronous endpoint performance."""
        def make_request():
            response = client.get("/")
            assert response.status_code == 200
            return response

        # Run benchmark
        result = benchmark(make_request)

        # Additional assertions
        assert result.status_code == 200
        assert result.json()["status"] == "running"

    @pytest.mark.asyncio
    async def test_async_endpoint_benchmark(self):
        """Benchmark async endpoint performance with detailed metrics."""
        async with AsyncClient(app=app, base_url="http://test") as client:
            # Warmup
            for _ in range(10):
                await client.get("/health")

            # Benchmark parameters
            iterations = 1000
            response_times = []

            # Force garbage collection before benchmark
            gc.collect()

            # Run benchmark
            print("\nAsync Endpoint Benchmark:")
            print(f"Running {iterations} iterations...")

            start_total = time.time()
            for i in range(iterations):
                start = time.time()
                response = await client.get("/health")
                end = time.time()

                assert response.status_code == 200
                response_times.append(end - start)

                if (i + 1) % 100 == 0:
                    print(f"  Completed {i + 1}/{iterations} requests")

            total_time = time.time() - start_total

            # Calculate metrics
            avg_time = mean(response_times)
            med_time = median(response_times)
            std_time = stdev(response_times)
            min_time = min(response_times)
            max_time = max(response_times)
            p95_time = sorted(response_times)[int(0.95 * iterations)]
            p99_time = sorted(response_times)[int(0.99 * iterations)]

            # Print results
            print("\nBenchmark Results:")
            print(f"Total time: {total_time:.2f}s")
            print(f"Requests/second: {iterations/total_time:.2f}")
            print(f"Average response: {avg_time*1000:.2f}ms")
            print(f"Median response: {med_time*1000:.2f}ms")
            print(f"Std deviation: {std_time*1000:.2f}ms")
            print(f"Min response: {min_time*1000:.2f}ms")
            print(f"Max response: {max_time*1000:.2f}ms")
            print(f"95th percentile: {p95_time*1000:.2f}ms")
            print(f"99th percentile: {p99_time*1000:.2f}ms")

            # Performance assertions
            assert avg_time < 0.01, f"Average response time {avg_time*1000:.2f}ms exceeds 10ms"
            assert p95_time < 0.02, f"95th percentile {p95_time*1000:.2f}ms exceeds 20ms"
            assert p99_time < 0.05, f"99th percentile {p99_time*1000:.2f}ms exceeds 50ms"

    @pytest.mark.asyncio
    async def test_memory_efficiency_benchmark(self):
        """Benchmark memory usage during sustained operations."""
        import os

        import psutil

        process = psutil.Process(os.getpid())

        async with AsyncClient(app=app, base_url="http://test") as client:
            # Initial memory
            gc.collect()
            initial_memory = process.memory_info().rss / 1024 / 1024  # MB

            # Run requests
            num_requests = 1000
            for _ in range(num_requests):
                await client.get("/")

            # Final memory
            gc.collect()
            final_memory = process.memory_info().rss / 1024 / 1024  # MB

            memory_increase = final_memory - initial_memory

            print("\nMemory Benchmark:")
            print(f"Initial memory: {initial_memory:.2f} MB")
            print(f"Final memory: {final_memory:.2f} MB")
            print(f"Memory increase: {memory_increase:.2f} MB")
            print(f"Memory per request: {memory_increase/num_requests*1000:.2f} KB")

            # Memory should not increase significantly
            assert memory_increase < 50, f"Memory increased by {memory_increase:.2f} MB"

    @pytest.mark.asyncio
    async def test_connection_pooling_benchmark(self):
        """Benchmark connection pooling efficiency."""
        # Test with connection reuse
        async with AsyncClient(app=app, base_url="http://test") as client:
            reuse_times = []

            for _ in range(100):
                start = time.time()
                await client.get("/health")
                reuse_times.append(time.time() - start)

        # Test without connection reuse (new client each time)
        no_reuse_times = []

        for _ in range(100):
            async with AsyncClient(app=app, base_url="http://test") as client:
                start = time.time()
                await client.get("/health")
                no_reuse_times.append(time.time() - start)

        # Compare results
        avg_reuse = mean(reuse_times)
        avg_no_reuse = mean(no_reuse_times)
        improvement = (avg_no_reuse - avg_reuse) / avg_no_reuse * 100

        print("\nConnection Pooling Benchmark:")
        print(f"With reuse: {avg_reuse*1000:.2f}ms avg")
        print(f"Without reuse: {avg_no_reuse*1000:.2f}ms avg")
        print(f"Improvement: {improvement:.1f}%")

        # Connection reuse should be faster or at least not significantly slower
        # In test environments, the difference might be minimal
        assert avg_reuse < avg_no_reuse * 1.5, "Connection reuse should not be significantly slower"

    @pytest.mark.asyncio
    async def test_json_serialization_benchmark(self):
        """Benchmark JSON response serialization performance."""
        async with AsyncClient(app=app, base_url="http://test") as client:
            # Test different response sizes
            endpoints = [
                ("/", "small"),  # Small JSON response
                ("/health", "minimal"),  # Minimal JSON response
            ]

            results = {}

            for endpoint, size in endpoints:
                times = []

                # Warmup
                for _ in range(10):
                    await client.get(endpoint)

                # Benchmark
                for _ in range(500):
                    start = time.time()
                    response = await client.get(endpoint)
                    end = time.time()

                    assert response.status_code == 200
                    times.append(end - start)

                avg_time = mean(times)
                results[size] = avg_time

                print(f"\n{size.capitalize()} response ({endpoint}):")
                print(f"  Average time: {avg_time*1000:.2f}ms")

            # All responses should be fast
            for size, avg_time in results.items():
                assert avg_time < 0.01, f"{size} response too slow: {avg_time*1000:.2f}ms"

    @pytest.mark.asyncio
    async def test_concurrent_performance_scaling(self):
        """Benchmark how performance scales with concurrent users."""
        async with AsyncClient(app=app, base_url="http://test") as client:
            concurrent_levels = [1, 5, 10, 20, 50]
            results = {}

            for level in concurrent_levels:
                async def make_request():
                    start = time.time()
                    response = await client.get("/")
                    return time.time() - start, response.status_code

                # Run concurrent requests
                start_total = time.time()
                tasks = [make_request() for _ in range(level * 10)]
                responses = await asyncio.gather(*tasks)
                total_time = time.time() - start_total

                # Analyze results
                times = [r[0] for r in responses]
                success_count = sum(1 for r in responses if r[1] == 200)

                results[level] = {
                    "avg_time": mean(times),
                    "total_time": total_time,
                    "success_rate": success_count / len(responses) * 100,
                    "throughput": len(responses) / total_time
                }

            # Print scaling results
            print("\nConcurrency Scaling Benchmark:")
            for level, metrics in results.items():
                print(f"\n{level} concurrent users:")
                print(f"  Average response: {metrics['avg_time']*1000:.2f}ms")
                print(f"  Throughput: {metrics['throughput']:.2f} req/s")
                print(f"  Success rate: {metrics['success_rate']:.1f}%")

            # Performance should remain acceptable even with high concurrency
            for level, metrics in results.items():
                assert metrics['success_rate'] == 100, f"Failed requests at {level} concurrent users"
                assert metrics['avg_time'] < 0.1, f"Response time too high at {level} concurrent users"
