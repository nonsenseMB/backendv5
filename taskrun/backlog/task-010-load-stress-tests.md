# Task 010: Load and Stress Tests

## Priority: MEDIUM
**Estimated Time**: 5-6 hours  
**Dependencies**: Tasks 001-009 (Complete test infrastructure)  
**Blocking**: Production capacity planning

## Why This Task is Critical

Load and stress tests reveal:
1. **Breaking points** - When does the system fail?
2. **Bottlenecks** - What limits performance?
3. **Resource requirements** - How much CPU/RAM/DB needed?
4. **Scaling characteristics** - Linear or exponential resource needs?
5. **Recovery behavior** - How well does system recover?

## What Needs to Be Done

### 1. Load Test Configuration

Create `tests/load/conftest.py`:
```python
"""Load test configuration and utilities."""
import os
from dataclasses import dataclass
from typing import List, Dict
import aiohttp
from locust import HttpUser, task, between

@dataclass
class LoadTestConfig:
    """Load test configuration."""
    # Target metrics
    target_rps: int = 100  # Requests per second
    target_concurrent_users: int = 1000
    test_duration_seconds: int = 300  # 5 minutes
    ramp_up_seconds: int = 60
    
    # Performance thresholds
    max_response_time_ms: int = 1000  # 1 second
    max_error_rate: float = 0.01  # 1%
    min_success_rate: float = 0.99  # 99%
    
    # Resource limits
    max_cpu_percent: int = 80
    max_memory_percent: int = 85
    max_db_connections: int = 100
    
    @classmethod
    def from_env(cls):
        """Load config from environment."""
        return cls(
            target_rps=int(os.getenv("LOAD_TEST_RPS", "100")),
            target_concurrent_users=int(os.getenv("LOAD_TEST_USERS", "1000")),
            test_duration_seconds=int(os.getenv("LOAD_TEST_DURATION", "300"))
        )

class BaseLoadTest:
    """Base class for load tests."""
    
    def __init__(self, config: LoadTestConfig):
        self.config = config
        self.metrics = {
            "requests": 0,
            "errors": 0,
            "response_times": [],
            "throughput": []
        }
    
    async def setup_test_data(self):
        """Create test data before load test."""
        # Create test users
        self.test_users = await create_load_test_users(self.config.target_concurrent_users)
        
        # Create test documents
        self.test_documents = await create_load_test_documents(10000)
        
        # Create test knowledge bases
        self.test_kbs = await create_load_test_knowledge_bases(100)
    
    def record_request(self, response_time_ms: float, success: bool):
        """Record request metrics."""
        self.metrics["requests"] += 1
        if not success:
            self.metrics["errors"] += 1
        self.metrics["response_times"].append(response_time_ms)
    
    def calculate_percentiles(self):
        """Calculate response time percentiles."""
        times = sorted(self.metrics["response_times"])
        if not times:
            return {}
        
        return {
            "p50": times[int(len(times) * 0.50)],
            "p90": times[int(len(times) * 0.90)],
            "p95": times[int(len(times) * 0.95)],
            "p99": times[int(len(times) * 0.99)],
            "max": times[-1]
        }
```

### 2. API Load Tests

Create `tests/load/test_api_load.py`:
```python
"""API endpoint load tests."""
from locust import HttpUser, task, between, TaskSet
import random
import time

class DocumentBehavior(TaskSet):
    """User behavior for document operations."""
    
    def on_start(self):
        """Login and setup."""
        # Login
        response = self.client.post(
            "/api/v1/auth/login",
            json={
                "email": f"loadtest{random.randint(1, 1000)}@example.com",
                "password": "testpass123"
            }
        )
        if response.status_code == 200:
            self.token = response.json()["access_token"]
            self.headers = {"Authorization": f"Bearer {self.token}"}
        else:
            self.headers = {}
    
    @task(4)  # Weight: 40% of requests
    def list_documents(self):
        """List user documents."""
        with self.client.get(
            "/api/v1/documents",
            headers=self.headers,
            catch_response=True
        ) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Got {response.status_code}")
    
    @task(3)  # Weight: 30% of requests
    def read_document(self):
        """Read specific document."""
        doc_id = random.choice(self.parent.test_document_ids)
        with self.client.get(
            f"/api/v1/documents/{doc_id}",
            headers=self.headers,
            catch_response=True
        ) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Got {response.status_code}")
    
    @task(2)  # Weight: 20% of requests
    def create_document(self):
        """Create new document."""
        with self.client.post(
            "/api/v1/documents",
            headers=self.headers,
            json={
                "title": f"Load Test Doc {time.time()}",
                "content": {"text": "Load test content" * 100}
            },
            catch_response=True
        ) as response:
            if response.status_code == 201:
                response.success()
                # Store ID for later use
                doc_id = response.json()["id"]
                self.parent.created_docs.append(doc_id)
            else:
                response.failure(f"Got {response.status_code}")
    
    @task(1)  # Weight: 10% of requests
    def search_documents(self):
        """Search documents."""
        query = random.choice(["test", "document", "load", "content"])
        with self.client.get(
            f"/api/v1/documents/search?q={query}",
            headers=self.headers,
            catch_response=True
        ) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Got {response.status_code}")

class APILoadTest(HttpUser):
    """API load test user."""
    tasks = [DocumentBehavior]
    wait_time = between(1, 3)  # Wait 1-3 seconds between requests
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.test_document_ids = []  # Populated during setup
        self.created_docs = []

# Run with: locust -f test_api_load.py --host=http://localhost:8000
```

### 3. Database Load Tests

Create `tests/load/test_database_load.py`:
```python
"""Database-specific load tests."""
import asyncio
import asyncpg
from datetime import datetime
import random

class DatabaseLoadTest:
    """Test database under load."""
    
    async def test_connection_pool_saturation(self):
        """Test behavior when connection pool is saturated."""
        # Create pool with limited connections
        pool = await asyncpg.create_pool(
            DATABASE_URL,
            min_size=10,
            max_size=20  # Limited pool
        )
        
        async def query_task(task_id):
            """Execute queries."""
            try:
                async with pool.acquire() as conn:
                    # Simulate slow query
                    await conn.fetchval(
                        "SELECT pg_sleep(0.5), COUNT(*) FROM documents"
                    )
                return True
            except asyncpg.PoolTimeout:
                return False
        
        # Launch more tasks than pool size
        tasks = [query_task(i) for i in range(50)]
        results = await asyncio.gather(*tasks)
        
        # Some should timeout
        successes = sum(1 for r in results if r)
        timeouts = sum(1 for r in results if not r)
        
        assert timeouts > 0  # Some should timeout
        assert successes > 20  # But many should succeed
        
        await pool.close()
    
    async def test_write_heavy_load(self):
        """Test database under write-heavy load."""
        start_time = datetime.utcnow()
        write_times = []
        
        async def write_batch(batch_id):
            """Write batch of records."""
            batch_start = time.perf_counter()
            
            async with get_db_connection() as conn:
                # Insert 100 documents
                await conn.executemany(
                    """
                    INSERT INTO documents (id, title, content, tenant_id, owner_id)
                    VALUES ($1, $2, $3, $4, $5)
                    """,
                    [
                        (
                            uuid4(),
                            f"Load test doc {batch_id}-{i}",
                            {"text": "content"},
                            TEST_TENANT_ID,
                            TEST_USER_ID
                        )
                        for i in range(100)
                    ]
                )
            
            write_times.append(time.perf_counter() - batch_start)
        
        # Run 100 batches concurrently (10,000 total inserts)
        tasks = [write_batch(i) for i in range(100)]
        await asyncio.gather(*tasks)
        
        # Calculate metrics
        total_time = (datetime.utcnow() - start_time).total_seconds()
        avg_batch_time = sum(write_times) / len(write_times)
        writes_per_second = 10000 / total_time
        
        print(f"Write performance: {writes_per_second:.0f} writes/sec")
        print(f"Average batch time: {avg_batch_time:.3f}s")
        
        # Should handle at least 1000 writes/sec
        assert writes_per_second > 1000
    
    async def test_complex_query_load(self):
        """Test complex queries under load."""
        
        async def complex_query():
            """Execute complex join query."""
            start = time.perf_counter()
            
            result = await execute_query("""
                SELECT 
                    d.id,
                    d.title,
                    COUNT(DISTINCT dc.id) as version_count,
                    COUNT(DISTINCT dp.user_id) as collaborator_count,
                    MAX(dc.created_at) as last_modified
                FROM documents d
                LEFT JOIN document_contents dc ON d.id = dc.document_id
                LEFT JOIN document_permissions dp ON d.id = dp.document_id
                WHERE d.tenant_id = $1
                  AND d.created_at > NOW() - INTERVAL '7 days'
                GROUP BY d.id, d.title
                ORDER BY last_modified DESC
                LIMIT 100
            """, TEST_TENANT_ID)
            
            return time.perf_counter() - start
        
        # Run 50 concurrent complex queries
        query_times = await asyncio.gather(*[complex_query() for _ in range(50)])
        
        # Check performance
        avg_time = sum(query_times) / len(query_times)
        max_time = max(query_times)
        
        print(f"Complex query avg: {avg_time:.3f}s, max: {max_time:.3f}s")
        
        # Complex queries should complete reasonably fast
        assert avg_time < 0.5  # Average under 500ms
        assert max_time < 2.0  # Max under 2 seconds
```

### 4. Vector Store Load Tests

Create `tests/load/test_vector_load.py`:
```python
"""Vector store load tests."""
import numpy as np
from concurrent.futures import ThreadPoolExecutor
import asyncio

class VectorStoreLoadTest:
    """Test vector store under load."""
    
    async def test_vector_insertion_rate(self):
        """Test vector insertion performance."""
        embedding_dim = 1536
        batch_size = 100
        num_batches = 100  # 10,000 vectors total
        
        async def insert_batch(batch_id):
            """Insert batch of vectors."""
            vectors = np.random.rand(batch_size, embedding_dim).tolist()
            metadata = [
                {
                    "doc_id": f"doc_{batch_id}_{i}",
                    "chunk_index": i,
                    "text": f"Test chunk {i}"
                }
                for i in range(batch_size)
            ]
            
            start = time.perf_counter()
            vector_ids = await vector_store.add_vectors(
                vectors=vectors,
                metadata=metadata,
                collection="load_test"
            )
            duration = time.perf_counter() - start
            
            return duration, len(vector_ids)
        
        # Insert vectors concurrently
        insert_times = []
        tasks = [insert_batch(i) for i in range(num_batches)]
        results = await asyncio.gather(*tasks)
        
        # Calculate metrics
        total_vectors = sum(count for _, count in results)
        total_time = sum(duration for duration, _ in results)
        avg_insert_time = total_time / num_batches
        vectors_per_second = total_vectors / total_time
        
        print(f"Vector insertion rate: {vectors_per_second:.0f} vectors/sec")
        print(f"Average batch insert: {avg_insert_time:.3f}s")
        
        # Should handle reasonable insertion rate
        assert vectors_per_second > 500
    
    async def test_concurrent_similarity_search(self):
        """Test similarity search under load."""
        # Pre-populate with test vectors
        await populate_test_vectors(count=100000)
        
        search_times = []
        
        async def search_task():
            """Perform similarity search."""
            query_vector = np.random.rand(1536).tolist()
            
            start = time.perf_counter()
            results = await vector_store.search(
                query_vector=query_vector,
                top_k=20,
                collection="load_test"
            )
            duration = time.perf_counter() - start
            
            search_times.append(duration)
            return len(results)
        
        # Run 1000 concurrent searches
        tasks = [search_task() for _ in range(1000)]
        results = await asyncio.gather(*tasks)
        
        # Calculate percentiles
        search_times.sort()
        p50 = search_times[int(len(search_times) * 0.50)]
        p90 = search_times[int(len(search_times) * 0.90)]
        p99 = search_times[int(len(search_times) * 0.99)]
        
        print(f"Search latency - p50: {p50*1000:.0f}ms, p90: {p90*1000:.0f}ms, p99: {p99*1000:.0f}ms")
        
        # Performance requirements
        assert p50 < 0.05  # 50th percentile < 50ms
        assert p90 < 0.1   # 90th percentile < 100ms
        assert p99 < 0.5   # 99th percentile < 500ms
```

### 5. Stress Tests

Create `tests/load/test_stress.py`:
```python
"""Stress tests to find breaking points."""
import psutil
import resource

class StressTest:
    """Push system to breaking point."""
    
    async def test_memory_exhaustion(self):
        """Test behavior when memory is exhausted."""
        documents = []
        memory_usage = []
        
        try:
            # Keep creating large documents
            while True:
                # Create 10MB document
                large_content = "x" * (10 * 1024 * 1024)
                doc = await create_document(
                    title="Memory test",
                    content={"text": large_content}
                )
                documents.append(doc)
                
                # Check memory
                process = psutil.Process()
                mem_mb = process.memory_info().rss / 1024 / 1024
                memory_usage.append(mem_mb)
                
                # Stop before OOM
                if mem_mb > 4096:  # 4GB limit
                    break
                    
        except MemoryError:
            print("Hit memory limit")
        
        # Verify graceful degradation
        assert len(documents) > 0
        assert max(memory_usage) < 5120  # Should stop before 5GB
        
        # Cleanup
        for doc in documents:
            await delete_document(doc.id)
    
    async def test_connection_exhaustion(self):
        """Test when all connections are exhausted."""
        connections = []
        
        try:
            # Open connections until failure
            while len(connections) < 1000:
                conn = await asyncpg.connect(DATABASE_URL)
                connections.append(conn)
                
        except (asyncpg.TooManyConnectionsError, OSError):
            print(f"Connection limit reached at {len(connections)}")
        
        # Should handle gracefully
        assert len(connections) > 50  # Should support reasonable number
        
        # Close all
        for conn in connections:
            await conn.close()
    
    async def test_disk_space_exhaustion(self):
        """Test behavior when disk space runs low."""
        # Monitor disk usage
        initial_usage = psutil.disk_usage('/').percent
        
        large_docs = []
        try:
            # Create documents until disk is nearly full
            while psutil.disk_usage('/').percent < 90:
                doc = await create_large_document(size_mb=100)
                large_docs.append(doc)
                
                if len(large_docs) > 100:  # Safety limit
                    break
                    
        except IOError as e:
            if "No space left" in str(e):
                print("Disk space exhausted as expected")
        
        # Should fail gracefully
        final_usage = psutil.disk_usage('/').percent
        assert final_usage > initial_usage
        
        # Cleanup
        for doc in large_docs:
            await delete_document(doc.id)
    
    async def test_cpu_saturation(self):
        """Test under CPU saturation."""
        import multiprocessing
        
        async def cpu_intensive_task():
            """CPU-bound operation."""
            # Calculate prime numbers
            def is_prime(n):
                for i in range(2, int(n**0.5) + 1):
                    if n % i == 0:
                        return False
                return n > 1
            
            # Find primes up to 100000
            primes = [n for n in range(100000) if is_prime(n)]
            return len(primes)
        
        # Launch CPU-intensive tasks on all cores
        num_cores = multiprocessing.cpu_count()
        tasks = [cpu_intensive_task() for _ in range(num_cores * 2)]
        
        start_time = time.time()
        results = await asyncio.gather(*tasks)
        duration = time.time() - start_time
        
        # Should complete even under CPU pressure
        assert all(r > 0 for r in results)
        assert duration < 60  # Should complete within 1 minute
```

### 6. Recovery Tests

Create `tests/load/test_recovery.py`:
```python
"""Test system recovery after stress."""

class RecoveryTest:
    """Test system recovery capabilities."""
    
    async def test_recovery_after_spike(self):
        """Test recovery after traffic spike."""
        baseline_metrics = await collect_baseline_metrics()
        
        # Generate traffic spike
        await generate_traffic_spike(
            duration_seconds=60,
            requests_per_second=1000  # 10x normal
        )
        
        # Wait for recovery
        recovery_start = time.time()
        recovered = False
        
        while time.time() - recovery_start < 300:  # 5 min timeout
            current_metrics = await collect_system_metrics()
            
            if all([
                current_metrics["response_time_p95"] < baseline_metrics["response_time_p95"] * 1.2,
                current_metrics["error_rate"] < 0.01,
                current_metrics["cpu_usage"] < baseline_metrics["cpu_usage"] * 1.2
            ]):
                recovered = True
                break
                
            await asyncio.sleep(10)
        
        assert recovered, "System did not recover within 5 minutes"
        recovery_time = time.time() - recovery_start
        print(f"Recovery time: {recovery_time:.0f} seconds")
        
        # Should recover reasonably fast
        assert recovery_time < 180  # Under 3 minutes
    
    async def test_cascading_failure_prevention(self):
        """Test prevention of cascading failures."""
        # Simulate one service degradation
        await degrade_service("vector_store", latency_ms=5000)
        
        # Monitor other services
        monitoring_duration = 60  # 1 minute
        service_health = {
            "api": [],
            "database": [],
            "cache": []
        }
        
        start_time = time.time()
        while time.time() - start_time < monitoring_duration:
            for service in service_health:
                health = await check_service_health(service)
                service_health[service].append(health)
            await asyncio.sleep(1)
        
        # Other services should remain healthy
        for service, health_checks in service_health.items():
            healthy_percentage = sum(1 for h in health_checks if h["healthy"]) / len(health_checks)
            assert healthy_percentage > 0.95, f"{service} degraded due to cascade"
```

## Success Criteria

1. ✅ System handles target load (1000 users, 100 RPS)
2. ✅ Response times meet SLA (p95 < 1 second)
3. ✅ Error rate stays below 1%
4. ✅ Resource usage stays within limits
5. ✅ No memory leaks under sustained load
6. ✅ Graceful degradation under stress
7. ✅ Quick recovery after load spike
8. ✅ No cascading failures

## Load Test Metrics

| Metric | Target | Actual | Status |
|--------|--------|--------|--------|
| Requests/sec | 100 | - | - |
| Concurrent Users | 1000 | - | - |
| Response Time p50 | < 200ms | - | - |
| Response Time p95 | < 1000ms | - | - |
| Response Time p99 | < 2000ms | - | - |
| Error Rate | < 1% | - | - |
| CPU Usage | < 80% | - | - |
| Memory Usage | < 85% | - | - |
| DB Connections | < 100 | - | - |

## Running Load Tests

```bash
# Run Locust for API load test
locust -f tests/load/test_api_load.py --host=http://localhost:8000 --users=1000 --spawn-rate=10

# Run database load tests
pytest tests/load/test_database_load.py -v

# Run full stress test suite
pytest tests/load/test_stress.py -v --stress

# Generate load test report
python tests/load/generate_report.py
```

## Next Steps

After this task:
- Analyze load test results
- Identify and fix bottlenecks
- Create capacity planning document
- Set up continuous load testing
- Configure auto-scaling based on metrics

## Notes

- Run load tests in isolated environment
- Monitor all system components during tests
- Save metrics for baseline comparison
- Test both gradual and spike loads
- Document breaking points and limits