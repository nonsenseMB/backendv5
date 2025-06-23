# Task 008: Concurrency and Performance Tests

## Priority: HIGH
**Estimated Time**: 5-6 hours  
**Dependencies**: Tasks 001-002 (Pytest setup, fixtures)  
**Blocking**: Production scalability

## Why This Task is Critical

Without concurrency and performance tests:
1. **Race conditions** - Data corruption under concurrent access
2. **Deadlocks** - System freezes with multiple users
3. **Memory leaks** - Server crashes after extended use
4. **Slow queries** - Poor user experience at scale
5. **Resource exhaustion** - System fails under load

## What Needs to Be Done

### 1. Concurrent Access Tests

Create `tests/performance/test_concurrent_access.py`:
```python
"""Test concurrent access scenarios."""
import pytest
import asyncio
from datetime import datetime
from uuid import uuid4
from tests.factories import DocumentFactory, UserFactory

class TestConcurrentAccess:
    """Test system behavior under concurrent access."""
    
    @pytest.mark.asyncio
    @pytest.mark.performance
    async def test_concurrent_document_creation(self, db_session, test_tenant):
        """Test multiple users creating documents simultaneously."""
        # Create multiple users
        users = await UserFactory.create_batch(10, tenant_id=test_tenant.id)
        
        async def create_user_document(user):
            """Create document for a user."""
            doc = await DocumentFactory.create(
                title=f"Document by {user.name}",
                owner_id=user.id,
                tenant_id=test_tenant.id
            )
            return doc
        
        # Create documents concurrently
        start_time = datetime.utcnow()
        tasks = [create_user_document(user) for user in users]
        documents = await asyncio.gather(*tasks)
        duration = (datetime.utcnow() - start_time).total_seconds()
        
        # Verify all succeeded
        assert len(documents) == 10
        assert all(doc.id is not None for doc in documents)
        
        # Should complete reasonably fast
        assert duration < 2.0  # 10 documents in < 2 seconds
        
        # Verify no duplicate slugs
        slugs = [doc.slug for doc in documents]
        assert len(set(slugs)) == len(slugs)
    
    @pytest.mark.asyncio
    @pytest.mark.performance
    async def test_concurrent_document_updates(self, db_session):
        """Test concurrent updates to same document."""
        doc = await DocumentFactory.create()
        users = await UserFactory.create_batch(5)
        
        async def update_document(user, index):
            """Update document title."""
            repo = DocumentRepository(db_session)
            try:
                await repo.update(
                    doc.id,
                    title=f"Updated by User {index}",
                    updated_by_id=user.id
                )
                return True
            except OptimisticLockError:
                return False
        
        # Multiple users try to update simultaneously
        tasks = [update_document(user, i) for i, user in enumerate(users)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Only one should succeed due to optimistic locking
        successes = [r for r in results if r is True]
        assert len(successes) == 1
        
        # Others should get lock errors
        failures = [r for r in results if isinstance(r, OptimisticLockError)]
        assert len(failures) == 4
    
    @pytest.mark.asyncio
    @pytest.mark.performance
    async def test_reader_writer_concurrency(self, db_session):
        """Test readers don't block writers and vice versa."""
        doc = await DocumentFactory.create(
            title="Shared Document",
            content={"text": "Initial content"}
        )
        
        read_times = []
        write_times = []
        
        async def reader(index):
            """Read document multiple times."""
            repo = DocumentRepository(db_session)
            for _ in range(10):
                start = datetime.utcnow()
                result = await repo.get(doc.id)
                duration = (datetime.utcnow() - start).total_seconds()
                read_times.append(duration)
                await asyncio.sleep(0.01)  # Small delay
        
        async def writer(index):
            """Update document periodically."""
            repo = DocumentRepository(db_session)
            for i in range(5):
                start = datetime.utcnow()
                await repo.update(
                    doc.id,
                    content={"text": f"Update {index}-{i}"}
                )
                duration = (datetime.utcnow() - start).total_seconds()
                write_times.append(duration)
                await asyncio.sleep(0.02)
        
        # Run readers and writers concurrently
        tasks = []
        tasks.extend([reader(i) for i in range(5)])  # 5 readers
        tasks.extend([writer(i) for i in range(2)])  # 2 writers
        
        await asyncio.gather(*tasks)
        
        # Reads should be fast even with concurrent writes
        avg_read_time = sum(read_times) / len(read_times)
        assert avg_read_time < 0.01  # < 10ms average
        
        # Writes should complete reasonably fast
        avg_write_time = sum(write_times) / len(write_times)
        assert avg_write_time < 0.05  # < 50ms average
```

### 2. Race Condition Tests

Create `tests/performance/test_race_conditions.py`:
```python
"""Test for race conditions."""
import pytest
import asyncio
from uuid import uuid4

class TestRaceConditions:
    """Test system handles race conditions correctly."""
    
    @pytest.mark.asyncio
    @pytest.mark.performance
    async def test_double_spending_prevention(self, db_session):
        """Test preventing double-spending of resources."""
        # User with limited credits
        user = await UserFactory.create(credits=100)
        
        async def spend_credits(amount):
            """Try to spend credits."""
            return await deduct_user_credits(
                user_id=user.id,
                amount=amount
            )
        
        # Try to spend 60 credits twice simultaneously
        tasks = [spend_credits(60) for _ in range(2)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Only one should succeed
        successes = [r for r in results if r is True]
        failures = [r for r in results if isinstance(r, InsufficientCreditsError)]
        
        assert len(successes) == 1
        assert len(failures) == 1
        
        # User should have 40 credits left
        updated_user = await get_user(user.id)
        assert updated_user.credits == 40
    
    @pytest.mark.asyncio
    @pytest.mark.performance
    async def test_unique_constraint_race(self, db_session):
        """Test unique constraints under concurrent inserts."""
        tenant_id = uuid4()
        slug = "unique-document-slug"
        
        async def create_with_slug(index):
            """Try to create document with same slug."""
            try:
                doc = await DocumentFactory.create(
                    title=f"Document {index}",
                    slug=slug,
                    tenant_id=tenant_id
                )
                return doc
            except DuplicateResourceError:
                return None
        
        # Multiple attempts to create with same slug
        tasks = [create_with_slug(i) for i in range(10)]
        results = await asyncio.gather(*tasks)
        
        # Only one should succeed
        successful = [r for r in results if r is not None]
        assert len(successful) == 1
        assert successful[0].slug == slug
    
    @pytest.mark.asyncio
    @pytest.mark.performance
    async def test_counter_increment_race(self, db_session):
        """Test atomic counter increments."""
        doc = await DocumentFactory.create(view_count=0)
        
        async def increment_views():
            """Increment view counter."""
            repo = DocumentRepository(db_session)
            await repo.increment_view_count(doc.id)
        
        # 100 concurrent view increments
        tasks = [increment_views() for _ in range(100)]
        await asyncio.gather(*tasks)
        
        # Should have exactly 100 views
        updated_doc = await get_document(doc.id)
        assert updated_doc.view_count == 100
    
    @pytest.mark.asyncio
    @pytest.mark.performance
    async def test_inventory_depletion_race(self, db_session):
        """Test inventory management under concurrent access."""
        # Tool with limited executions
        tool = await ToolFactory.create(
            max_daily_executions=50,
            current_executions=0
        )
        
        async def try_execute_tool():
            """Try to execute tool."""
            return await execute_tool_with_limit_check(tool.id)
        
        # 60 concurrent execution attempts
        tasks = [try_execute_tool() for _ in range(60)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Exactly 50 should succeed
        successes = [r for r in results if r is True]
        failures = [r for r in results if isinstance(r, QuotaExceededError)]
        
        assert len(successes) == 50
        assert len(failures) == 10
```

### 3. Performance Benchmark Tests

Create `tests/performance/test_benchmarks.py`:
```python
"""Performance benchmark tests."""
import pytest
import time
from statistics import mean, stdev
from tests.utils import measure_time

class TestPerformanceBenchmarks:
    """Test system performance characteristics."""
    
    @pytest.mark.asyncio
    @pytest.mark.benchmark
    async def test_document_search_performance(self, db_session, benchmark_data):
        """Benchmark document search performance."""
        # Create test dataset
        await create_benchmark_documents(1000)  # 1000 documents
        
        search_times = []
        queries = ["test", "document", "example", "data", "content"]
        
        for query in queries:
            for _ in range(10):  # 10 runs per query
                start = time.perf_counter()
                results = await search_documents(
                    query=query,
                    limit=50
                )
                duration = time.perf_counter() - start
                search_times.append(duration)
        
        # Calculate statistics
        avg_time = mean(search_times)
        std_dev = stdev(search_times)
        max_time = max(search_times)
        
        # Performance assertions
        assert avg_time < 0.1  # Average < 100ms
        assert max_time < 0.5  # Max < 500ms
        assert std_dev < 0.05  # Consistent performance
        
        # Log for tracking
        print(f"Search Performance: avg={avg_time:.3f}s, max={max_time:.3f}s, std={std_dev:.3f}s")
    
    @pytest.mark.asyncio
    @pytest.mark.benchmark
    async def test_vector_search_performance(self, db_session):
        """Benchmark vector similarity search."""
        # Add test vectors
        kb = await create_knowledge_base()
        await add_benchmark_vectors(kb.id, count=10000)  # 10k vectors
        
        search_times = []
        
        for _ in range(50):  # 50 searches
            query_vector = generate_random_vector(1536)
            
            start = time.perf_counter()
            results = await vector_similarity_search(
                knowledge_base_id=kb.id,
                query_vector=query_vector,
                top_k=20
            )
            duration = time.perf_counter() - start
            search_times.append(duration)
        
        # Performance requirements
        avg_time = mean(search_times)
        p95_time = sorted(search_times)[int(len(search_times) * 0.95)]
        
        assert avg_time < 0.05  # Average < 50ms
        assert p95_time < 0.1   # 95th percentile < 100ms
    
    @pytest.mark.asyncio
    @pytest.mark.benchmark
    async def test_bulk_operations_performance(self, db_session):
        """Test performance of bulk operations."""
        # Bulk create
        start = time.perf_counter()
        documents = await bulk_create_documents(count=1000)
        create_time = time.perf_counter() - start
        
        # Should handle 1000 inserts efficiently
        assert create_time < 5.0  # < 5 seconds for 1000 docs
        assert len(documents) == 1000
        
        # Bulk update
        start = time.perf_counter()
        await bulk_update_documents(
            document_ids=[d.id for d in documents],
            updates={"status": "published"}
        )
        update_time = time.perf_counter() - start
        
        assert update_time < 3.0  # < 3 seconds for 1000 updates
        
        # Bulk delete
        start = time.perf_counter()
        await bulk_delete_documents([d.id for d in documents[:500]])
        delete_time = time.perf_counter() - start
        
        assert delete_time < 2.0  # < 2 seconds for 500 deletes
```

### 4. Memory and Resource Tests

Create `tests/performance/test_resource_usage.py`:
```python
"""Test resource usage and memory leaks."""
import pytest
import psutil
import gc
from memory_profiler import profile

class TestResourceUsage:
    """Test system resource usage."""
    
    @pytest.mark.asyncio
    @pytest.mark.performance
    async def test_memory_leak_prevention(self, db_session):
        """Test for memory leaks in long-running operations."""
        process = psutil.Process()
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Perform many operations
        for i in range(100):
            # Create and delete documents
            docs = await DocumentFactory.create_batch(10)
            for doc in docs:
                await delete_document(doc.id)
            
            # Force garbage collection every 10 iterations
            if i % 10 == 0:
                gc.collect()
        
        # Check memory after operations
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = final_memory - initial_memory
        
        # Should not leak significant memory
        assert memory_increase < 50  # Less than 50MB increase
    
    @pytest.mark.asyncio
    @pytest.mark.performance
    async def test_connection_pool_limits(self, db_session):
        """Test database connection pool behavior."""
        pool_stats_before = get_pool_statistics()
        
        # Create many concurrent database operations
        async def db_operation(index):
            repo = DocumentRepository(db_session)
            return await repo.count()
        
        # Launch more tasks than pool size
        tasks = [db_operation(i) for i in range(100)]
        await asyncio.gather(*tasks)
        
        pool_stats_after = get_pool_statistics()
        
        # Verify pool limits were respected
        assert pool_stats_after["max_connections"] <= 20  # Pool limit
        assert pool_stats_after["connection_errors"] == 0
        assert pool_stats_after["pool_exhausted_count"] < 10
    
    @pytest.mark.asyncio
    @pytest.mark.performance
    @profile  # Memory profiler decorator
    async def test_large_result_set_handling(self, db_session):
        """Test handling large result sets efficiently."""
        # Create large dataset
        await create_benchmark_documents(10000)
        
        # Test streaming/pagination
        all_docs = []
        async for batch in stream_documents(batch_size=100):
            all_docs.extend(batch)
            # Process batch without holding all in memory
            assert len(batch) <= 100
        
        assert len(all_docs) == 10000
        
        # Memory should not spike significantly
        # (checked by @profile decorator)
```

### 5. Deadlock Prevention Tests

Create `tests/performance/test_deadlock_prevention.py`:
```python
"""Test deadlock prevention mechanisms."""
import pytest
import asyncio
from datetime import datetime

class TestDeadlockPrevention:
    """Test system prevents deadlocks."""
    
    @pytest.mark.asyncio
    @pytest.mark.performance
    async def test_ordered_lock_acquisition(self, db_session):
        """Test locks are acquired in consistent order."""
        # Create related entities
        doc1 = await DocumentFactory.create()
        doc2 = await DocumentFactory.create()
        
        async def update_both_forward(name):
            """Update doc1 then doc2."""
            async with acquire_locks([doc1.id, doc2.id]):
                await update_document(doc1.id, title=f"{name}-1")
                await asyncio.sleep(0.01)  # Simulate work
                await update_document(doc2.id, title=f"{name}-2")
        
        async def update_both_reverse(name):
            """Update doc2 then doc1 (but locks in same order)."""
            async with acquire_locks([doc2.id, doc1.id]):
                await update_document(doc2.id, title=f"{name}-2")
                await asyncio.sleep(0.01)  # Simulate work
                await update_document(doc1.id, title=f"{name}-1")
        
        # Run both concurrently - should not deadlock
        tasks = [
            update_both_forward("Task1"),
            update_both_reverse("Task2")
        ]
        
        # Should complete without deadlock
        start = datetime.utcnow()
        await asyncio.gather(*tasks)
        duration = (datetime.utcnow() - start).total_seconds()
        
        assert duration < 1.0  # Should not hang
    
    @pytest.mark.asyncio
    @pytest.mark.performance
    async def test_lock_timeout_prevention(self, db_session):
        """Test lock timeouts prevent indefinite waiting."""
        doc = await DocumentFactory.create()
        
        async def long_operation():
            """Hold lock for extended time."""
            async with acquire_lock(doc.id, timeout=None):
                await asyncio.sleep(2.0)  # Hold for 2 seconds
        
        async def waiting_operation():
            """Try to acquire same lock with timeout."""
            try:
                async with acquire_lock(doc.id, timeout=0.5):
                    return "acquired"
            except LockTimeoutError:
                return "timeout"
        
        # Start long operation
        long_task = asyncio.create_task(long_operation())
        await asyncio.sleep(0.1)  # Let it acquire lock
        
        # Try to acquire with timeout
        result = await waiting_operation()
        
        assert result == "timeout"
        
        # Cleanup
        await long_task
```

### 6. Scalability Tests

Create `tests/performance/test_scalability.py`:
```python
"""Test system scalability."""
import pytest
from concurrent.futures import ThreadPoolExecutor

class TestScalability:
    """Test system scales appropriately."""
    
    @pytest.mark.asyncio
    @pytest.mark.performance
    @pytest.mark.slow
    async def test_tenant_isolation_at_scale(self, db_session):
        """Test tenant isolation with many tenants."""
        # Create multiple tenants
        tenants = await TenantFactory.create_batch(10)
        
        # Create data for each tenant
        for tenant in tenants:
            users = await UserFactory.create_batch(10, tenant_id=tenant.id)
            for user in users:
                await DocumentFactory.create_batch(
                    5,
                    owner_id=user.id,
                    tenant_id=tenant.id
                )
        
        # Verify complete isolation
        for tenant in tenants:
            docs = await get_tenant_documents(tenant.id)
            assert len(docs) == 50  # 10 users * 5 docs
            
            # Verify no cross-tenant data
            for doc in docs:
                assert doc.tenant_id == tenant.id
    
    @pytest.mark.asyncio
    @pytest.mark.performance
    async def test_horizontal_scaling_simulation(self):
        """Simulate multiple app instances."""
        async def simulate_instance(instance_id):
            """Simulate single app instance workload."""
            results = []
            for i in range(100):
                result = await process_request(
                    instance_id=instance_id,
                    request_id=f"{instance_id}-{i}"
                )
                results.append(result)
            return results
        
        # Simulate 5 instances
        tasks = [simulate_instance(i) for i in range(5)]
        all_results = await asyncio.gather(*tasks)
        
        # Verify all requests processed
        total_processed = sum(len(r) for r in all_results)
        assert total_processed == 500
        
        # Check for even distribution
        instance_loads = [len(r) for r in all_results]
        assert all(95 <= load <= 105 for load in instance_loads)
```

## Success Criteria

1. ✅ No race conditions in concurrent operations
2. ✅ Deadlocks are prevented or detected
3. ✅ Performance meets requirements (< 100ms for most operations)
4. ✅ Memory usage is stable (no leaks)
5. ✅ System scales linearly with load
6. ✅ Resource pools are properly managed
7. ✅ Lock contention is minimized
8. ✅ Tenant isolation is maintained at scale

## Performance Targets

| Operation | Average | 95th Percentile | Maximum |
|-----------|---------|-----------------|---------|
| Document Create | < 50ms | < 100ms | < 500ms |
| Document Search | < 100ms | < 200ms | < 1s |
| Vector Search | < 50ms | < 100ms | < 500ms |
| Bulk Create (1000) | < 5s | < 7s | < 10s |
| Concurrent Updates | < 100ms | < 200ms | < 1s |

## Next Steps

After this task:
- Run performance tests: `pytest tests/performance -v -m performance`
- Generate performance report: `pytest tests/performance --benchmark-only`
- Profile memory usage: `mprof run pytest tests/performance`
- Move on to Integration tests (Task 009)

## Notes

- Use `pytest-benchmark` for consistent measurements
- Test with realistic data volumes
- Monitor resource usage during tests
- Test both average and worst-case scenarios
- Document performance characteristics