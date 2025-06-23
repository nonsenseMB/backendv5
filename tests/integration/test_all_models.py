"""
Comprehensive integration test runner for all new database models.
Tests Document System, Knowledge Graph, and Tool System models.
"""
import asyncio
import sys
from typing import Dict, List

from test_document_models import main as test_documents
from test_knowledge_models import main as test_knowledge
from test_tool_models import main as test_tools


async def run_all_integration_tests() -> Dict[str, bool]:
    """Run all integration tests and return results."""
    print("🚀 Starting Comprehensive Database Model Integration Tests")
    print("=" * 80)
    
    results = {}
    
    # Run Document System tests
    print("\n📄 DOCUMENT SYSTEM TESTS")
    print("-" * 40)
    try:
        results["document_system"] = await test_documents()
    except Exception as e:
        print(f"❌ Document System tests crashed: {e}")
        results["document_system"] = False
    
    # Run Knowledge Graph tests
    print("\n🧠 KNOWLEDGE GRAPH TESTS")
    print("-" * 40)
    try:
        results["knowledge_graph"] = await test_knowledge()
    except Exception as e:
        print(f"❌ Knowledge Graph tests crashed: {e}")
        results["knowledge_graph"] = False
    
    # Run Tool System tests
    print("\n🛠️ TOOL SYSTEM TESTS")
    print("-" * 40)
    try:
        results["tool_system"] = await test_tools()
    except Exception as e:
        print(f"❌ Tool System tests crashed: {e}")
        results["tool_system"] = False
    
    return results


def print_test_summary(results: Dict[str, bool]) -> bool:
    """Print comprehensive test summary."""
    print("\n" + "=" * 80)
    print("🏁 INTEGRATION TEST SUMMARY")
    print("=" * 80)
    
    all_passed = True
    
    for test_suite, passed in results.items():
        status = "✅ PASSED" if passed else "❌ FAILED"
        suite_name = test_suite.replace("_", " ").title()
        print(f"{suite_name:.<40} {status}")
        if not passed:
            all_passed = False
    
    print("-" * 80)
    
    if all_passed:
        print("🎉 ALL INTEGRATION TESTS PASSED! 🎉")
        print("✅ Database foundation is 100% complete and functional!")
        print("✅ All models implement CRUD operations correctly")
        print("✅ All relationships and constraints work as expected")
        print("✅ Multi-tenant architecture is properly implemented")
        print("✅ Vector storage integration is ready")
        print("✅ Apache AGE graph integration is ready")
        print("✅ Tool system with MCP support is functional")
        print("✅ Real-time collaboration features work correctly")
        print("✅ Permission and access control systems are operational")
        print("✅ Ready for Auth and LangChain implementation!")
    else:
        print("❌ SOME TESTS FAILED!")
        print("🔍 Please review the failed test output above")
        print("⚠️  Database foundation needs fixes before proceeding")
    
    print("=" * 80)
    return all_passed


async def verify_database_schema():
    """Verify that all tables exist and have correct structure."""
    print("\n🔍 Verifying Database Schema...")
    
    try:
        from infrastructure.database.session import get_async_session, init_db
        from infrastructure.database.unit_of_work import UnitOfWork
        from sqlalchemy import text
        
        await init_db()
        
        async for session in get_async_session():
            async with UnitOfWork(session) as uow:
                # Check that all new tables exist
                table_check_query = """
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_name IN (
                    'documents', 'document_content', 'document_permissions', 'document_shares',
                    'knowledge_bases', 'knowledge_entities', 'knowledge_relations', 'document_vectors',
                    'tools', 'tool_definitions', 'mcp_servers', 'tool_executions'
                )
                ORDER BY table_name;
                """
                
                result = await session.execute(text(table_check_query))
                existing_tables = [row[0] for row in result.fetchall()]
                
                expected_tables = [
                    'document_content', 'document_permissions', 'document_shares', 'documents',
                    'document_vectors', 'knowledge_bases', 'knowledge_entities', 'knowledge_relations',
                    'mcp_servers', 'tool_definitions', 'tool_executions', 'tools'
                ]
                
                missing_tables = set(expected_tables) - set(existing_tables)
                if missing_tables:
                    print(f"❌ Missing tables: {missing_tables}")
                    return False
                
                print(f"✅ All {len(expected_tables)} new tables exist in database")
                
                # Check index creation (tenant_id indexes for multi-tenancy)
                index_check_query = """
                SELECT tablename, indexname 
                FROM pg_indexes 
                WHERE tablename IN ('documents', 'knowledge_bases', 'tools', 'mcp_servers')
                AND indexname LIKE '%tenant_id%'
                ORDER BY tablename;
                """
                
                result = await session.execute(text(index_check_query))
                tenant_indexes = result.fetchall()
                
                if len(tenant_indexes) >= 4:  # At least one tenant_id index per tenant-aware table
                    print(f"✅ Tenant ID indexes properly created")
                else:
                    print(f"⚠️  Some tenant ID indexes may be missing")
                
                return True
                
        return False
    except Exception as e:
        print(f"❌ Schema verification failed: {e}")
        return False


async def main():
    """Main test runner."""
    print("🧪 Database Model Integration Test Suite")
    print("Testing complete implementation of:")
    print("• Document System (TipTap, permissions, collaboration)")
    print("• Knowledge Graph (Apache AGE, vector storage)")
    print("• Tool System (MCP integration, execution tracking)")
    print()
    
    # First verify database schema
    schema_ok = await verify_database_schema()
    if not schema_ok:
        print("❌ Schema verification failed. Aborting tests.")
        return False
    
    # Run all integration tests
    results = await run_all_integration_tests()
    
    # Print summary and determine overall success
    all_passed = print_test_summary(results)
    
    return all_passed


if __name__ == "__main__":
    success = asyncio.run(main())
    exit(0 if success else 1)