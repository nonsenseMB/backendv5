import asyncio
import time
from statistics import mean, median, stdev

import pytest
from httpx import AsyncClient

from src.main import app


class TestAPILoadPerformance:
    """Load tests to verify API performance under stress."""

    @pytest.mark.asyncio
    async def test_concurrent_requests_load(self):
        """Test API performance with many concurrent requests."""
        async with AsyncClient(app=app, base_url="http://test") as client:
            num_requests = 100
            
            async def make_request():
                start_time = time.time()
                response = await client.get("/")
                end_time = time.time()
                return {
                    "status_code": response.status_code,
                    "response_time": end_time - start_time
                }
            
            # Run concurrent requests
            start = time.time()
            tasks = [make_request() for _ in range(num_requests)]
            results = await asyncio.gather(*tasks)
            total_time = time.time() - start
            
            # Analyze results
            response_times = [r["response_time"] for r in results]
            success_count = sum(1 for r in results if r["status_code"] == 200)
            
            # Performance assertions
            assert success_count == num_requests, f"Only {success_count}/{num_requests} requests succeeded"
            assert mean(response_times) < 0.1, f"Average response time {mean(response_times):.3f}s is too high"
            assert max(response_times) < 0.5, f"Max response time {max(response_times):.3f}s is too high"
            
            print(f"\nLoad Test Results:")
            print(f"Total requests: {num_requests}")
            print(f"Total time: {total_time:.2f}s")
            print(f"Requests per second: {num_requests/total_time:.2f}")
            print(f"Average response time: {mean(response_times):.3f}s")
            print(f"Median response time: {median(response_times):.3f}s")
            print(f"Std deviation: {stdev(response_times):.3f}s")

    @pytest.mark.asyncio
    async def test_sustained_load(self):
        """Test API performance under sustained load."""
        async with AsyncClient(app=app, base_url="http://test") as client:
            duration = 5  # seconds
            requests_per_second = 20
            
            results = []
            start_time = time.time()
            
            while time.time() - start_time < duration:
                batch_start = time.time()
                
                # Send batch of requests
                tasks = []
                for _ in range(requests_per_second):
                    tasks.append(client.get("/health"))
                
                responses = await asyncio.gather(*tasks)
                
                # Record results
                for response in responses:
                    results.append({
                        "status_code": response.status_code,
                        "timestamp": time.time() - start_time
                    })
                
                # Wait to maintain rate
                batch_duration = time.time() - batch_start
                if batch_duration < 1.0:
                    await asyncio.sleep(1.0 - batch_duration)
            
            # Analyze results
            total_requests = len(results)
            success_count = sum(1 for r in results if r["status_code"] == 200)
            success_rate = success_count / total_requests * 100
            
            assert success_rate >= 99.0, f"Success rate {success_rate:.1f}% is below 99%"
            
            print(f"\nSustained Load Test Results:")
            print(f"Duration: {duration}s")
            print(f"Target rate: {requests_per_second} req/s")
            print(f"Total requests: {total_requests}")
            print(f"Success rate: {success_rate:.1f}%")

    @pytest.mark.asyncio
    async def test_spike_load(self):
        """Test API behavior during traffic spikes."""
        async with AsyncClient(app=app, base_url="http://test") as client:
            # Normal load
            normal_load = 10
            spike_load = 200
            
            # Phase 1: Normal load
            print("\nPhase 1: Normal load")
            normal_tasks = [client.get("/") for _ in range(normal_load)]
            normal_start = time.time()
            normal_results = await asyncio.gather(*normal_tasks)
            normal_time = time.time() - normal_start
            
            # Phase 2: Spike
            print("Phase 2: Traffic spike")
            spike_tasks = [client.get("/") for _ in range(spike_load)]
            spike_start = time.time()
            spike_results = await asyncio.gather(*spike_tasks)
            spike_time = time.time() - spike_start
            
            # Phase 3: Return to normal
            print("Phase 3: Return to normal")
            recovery_tasks = [client.get("/") for _ in range(normal_load)]
            recovery_start = time.time()
            recovery_results = await asyncio.gather(*recovery_tasks)
            recovery_time = time.time() - recovery_start
            
            # Verify all requests succeeded
            assert all(r.status_code == 200 for r in normal_results)
            assert all(r.status_code == 200 for r in spike_results)
            assert all(r.status_code == 200 for r in recovery_results)
            
            print(f"\nSpike Test Results:")
            print(f"Normal load time: {normal_time:.2f}s for {normal_load} requests")
            print(f"Spike load time: {spike_time:.2f}s for {spike_load} requests")
            print(f"Recovery time: {recovery_time:.2f}s for {normal_load} requests")

    @pytest.mark.asyncio
    async def test_mixed_endpoints_load(self):
        """Test load distribution across multiple endpoints."""
        async with AsyncClient(app=app, base_url="http://test") as client:
            num_iterations = 50
            
            endpoint_stats = {
                "/": {"count": 0, "times": []},
                "/health": {"count": 0, "times": []},
            }
            
            async def make_mixed_requests():
                # Mix of different endpoints
                endpoints = ["/", "/health", "/", "/health", "/"]
                tasks = []
                
                for endpoint in endpoints:
                    start = time.time()
                    response = await client.get(endpoint)
                    duration = time.time() - start
                    
                    if response.status_code == 200:
                        endpoint_stats[endpoint]["count"] += 1
                        endpoint_stats[endpoint]["times"].append(duration)
            
            # Run mixed load
            start_time = time.time()
            tasks = [make_mixed_requests() for _ in range(num_iterations)]
            await asyncio.gather(*tasks)
            total_time = time.time() - start_time
            
            # Analyze per-endpoint performance
            print(f"\nMixed Endpoints Load Test:")
            print(f"Total time: {total_time:.2f}s")
            
            for endpoint, stats in endpoint_stats.items():
                if stats["times"]:
                    avg_time = mean(stats["times"])
                    print(f"\n{endpoint}:")
                    print(f"  Requests: {stats['count']}")
                    print(f"  Avg response time: {avg_time:.3f}s")
                    
                    # Assert performance requirements
                    assert avg_time < 0.1, f"{endpoint} avg response time too high"