"""Device analytics tracking and processing."""
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from uuid import UUID

from src.core.auth.trust_manager import trust_manager
from src.core.logging import get_logger
from src.infrastructure.cache import get_redis_client

logger = get_logger(__name__)


class DeviceAnalyticsProcessor:
    """Processes and aggregates device analytics data."""
    
    def __init__(self):
        """Initialize analytics processor."""
        self.processing_interval = 300  # 5 minutes
        self.retention_days = 90
        
    async def process_device_analytics(self, device_id: UUID) -> Dict:
        """
        Process analytics for a specific device.
        
        Args:
            device_id: Device identifier
            
        Returns:
            Processed analytics dictionary
        """
        try:
            redis_client = await get_redis_client()
            
            # Get raw events from Redis
            events_key = f"device_events:{device_id}"
            raw_events = await redis_client.lrange(events_key, 0, -1)
            
            if not raw_events:
                return {}
            
            # Parse events
            events = []
            for event_data in raw_events:
                try:
                    import json
                    event = json.loads(event_data)
                    events.append(event)
                except Exception as e:
                    logger.debug(f"Failed to parse event: {e}")
            
            # Calculate metrics
            now = datetime.utcnow()
            metrics = {
                "total_events": len(events),
                "successful_auth_count": 0,
                "failed_auth_count": 0,
                "api_calls_last_hour": 0,
                "unique_endpoints_accessed": set(),
                "location_changes": 0,
                "suspicious_activity_count": 0,
                "last_processed": now.isoformat()
            }
            
            # Process events
            auth_streak = 0
            last_location = None
            hour_ago = now - timedelta(hours=1)
            
            for event in events:
                event_type = event.get("type")
                event_time = datetime.fromisoformat(event.get("timestamp", now.isoformat()))
                
                if event_type == "authentication":
                    if event.get("success"):
                        metrics["successful_auth_count"] += 1
                        auth_streak += 1
                    else:
                        metrics["failed_auth_count"] += 1
                        auth_streak = 0
                
                elif event_type == "api_access":
                    if event_time > hour_ago:
                        metrics["api_calls_last_hour"] += 1
                    endpoint = event.get("metadata", {}).get("endpoint")
                    if endpoint:
                        metrics["unique_endpoints_accessed"].add(endpoint)
                
                elif event_type == "location_change":
                    location = event.get("metadata", {}).get("location")
                    if location and location != last_location:
                        metrics["location_changes"] += 1
                        last_location = location
                
                elif event_type == "suspicious_activity":
                    metrics["suspicious_activity_count"] += 1
            
            # Convert sets to counts
            metrics["unique_endpoints_count"] = len(metrics["unique_endpoints_accessed"])
            metrics["unique_endpoints_accessed"] = list(metrics["unique_endpoints_accessed"])[:10]  # Top 10
            metrics["successful_auth_streak"] = auth_streak
            
            # Calculate derived metrics
            total_auth = metrics["successful_auth_count"] + metrics["failed_auth_count"]
            if total_auth > 0:
                metrics["auth_success_rate"] = metrics["successful_auth_count"] / total_auth
            else:
                metrics["auth_success_rate"] = 0
            
            # Store processed metrics
            metrics_key = f"device_metrics:{device_id}"
            await redis_client.setex(
                metrics_key,
                86400,  # 24 hour TTL
                json.dumps(metrics)
            )
            
            # Clean up old events
            await redis_client.ltrim(events_key, 0, 999)  # Keep last 1000 events
            
            logger.info(
                "Processed device analytics",
                device_id=str(device_id),
                event_count=len(events),
                metrics=metrics
            )
            
            return metrics
            
        except Exception as e:
            logger.error(
                "Failed to process device analytics",
                device_id=str(device_id),
                error=str(e),
                exc_info=True
            )
            return {}
    
    async def calculate_trust_adjustments(
        self,
        device_id: UUID,
        current_trust_score: int
    ) -> tuple[int, List[str]]:
        """
        Calculate trust score adjustments based on analytics.
        
        Args:
            device_id: Device identifier
            current_trust_score: Current trust score
            
        Returns:
            Tuple of (new_score, adjustment_reasons)
        """
        try:
            # Get processed metrics
            redis_client = await get_redis_client()
            metrics_key = f"device_metrics:{device_id}"
            metrics_data = await redis_client.get(metrics_key)
            
            if not metrics_data:
                # No analytics available
                return current_trust_score, ["No analytics data available"]
            
            import json
            metrics = json.loads(metrics_data)
            
            # Use trust manager to calculate adjustments
            new_score, reasons = trust_manager.adjust_trust_for_behavior(
                current_score=current_trust_score,
                device_analytics=metrics
            )
            
            return new_score, reasons
            
        except Exception as e:
            logger.error(
                "Failed to calculate trust adjustments",
                device_id=str(device_id),
                error=str(e),
                exc_info=True
            )
            return current_trust_score, ["Failed to calculate adjustments"]
    
    async def record_device_event(
        self,
        device_id: UUID,
        event_type: str,
        success: bool = True,
        metadata: Optional[Dict] = None
    ):
        """
        Record a device event for analytics.
        
        Args:
            device_id: Device identifier
            event_type: Type of event
            success: Whether event was successful
            metadata: Additional event data
        """
        try:
            redis_client = await get_redis_client()
            
            # Create event record
            event = {
                "device_id": str(device_id),
                "type": event_type,
                "success": success,
                "timestamp": datetime.utcnow().isoformat(),
                "metadata": metadata or {}
            }
            
            # Store in Redis list
            import json
            events_key = f"device_events:{device_id}"
            await redis_client.lpush(events_key, json.dumps(event))
            
            # Set expiry on first event
            await redis_client.expire(events_key, 86400 * self.retention_days)
            
            # Also update trust manager cache
            trust_manager.record_device_event(
                device_id=device_id,
                event_type=event_type,
                success=success,
                metadata=metadata
            )
            
        except Exception as e:
            logger.error(
                "Failed to record device event",
                device_id=str(device_id),
                event_type=event_type,
                error=str(e)
            )
    
    async def run_analytics_processor(self):
        """
        Background task to process device analytics periodically.
        
        This should be run as a background task in the application.
        """
        logger.info("Starting device analytics processor")
        
        while True:
            try:
                # Get all devices that need processing
                redis_client = await get_redis_client()
                
                # Get all device event keys
                pattern = "device_events:*"
                cursor = 0
                device_ids = []
                
                while True:
                    cursor, keys = await redis_client.scan(
                        cursor,
                        match=pattern,
                        count=100
                    )
                    
                    for key in keys:
                        # Extract device ID from key
                        device_id = key.decode().split(":")[-1]
                        device_ids.append(device_id)
                    
                    if cursor == 0:
                        break
                
                # Process each device
                for device_id in device_ids:
                    try:
                        await self.process_device_analytics(UUID(device_id))
                    except Exception as e:
                        logger.error(
                            "Failed to process device",
                            device_id=device_id,
                            error=str(e)
                        )
                
                logger.info(
                    "Analytics processing cycle complete",
                    devices_processed=len(device_ids)
                )
                
            except Exception as e:
                logger.error(
                    "Analytics processor error",
                    error=str(e),
                    exc_info=True
                )
            
            # Wait for next cycle
            await asyncio.sleep(self.processing_interval)


# Global instance
analytics_processor = DeviceAnalyticsProcessor()