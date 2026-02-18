"""
Timestamp picker module for selecting optimal Wayback Machine timestamps
"""

import random
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime

from utils.logger import get_logger, log_module_start, log_module_complete, log_error
from config.config import MAX_TIMESTAMPS

class TimestampPicker:
    """
    Select optimal timestamps from Wayback Machine CDX entries
    """
    
    def __init__(self):
        self.logger = get_logger()
        self.max_timestamps = MAX_TIMESTAMPS
    
    def select_timestamps(self, entries: List[Dict[str, Any]], count: int = None) -> List[str]:
        """
        Select optimal timestamps from CDX entries
        
        Args:
            entries: List of CDX entries
            count: Number of timestamps to select (default from config)
            
        Returns:
            List of selected timestamps
        """
        if count is None:
            count = self.max_timestamps
        
        if not entries:
            return []
        
        try:
            # Extract valid timestamps
            timestamps = []
            
            for entry in entries:
                timestamp = entry.get('timestamp')
                status_code = entry.get('statuscode')
                
                # Only consider successful responses (2xx)
                if timestamp and status_code and status_code.startswith('2'):
                    timestamps.append(timestamp)
            
            if not timestamps:
                self.logger.warning("No valid timestamps found with successful status codes")
                return []
            
            # Sort timestamps chronologically
            timestamps.sort()
            
            # Select timestamps based on available count
            if len(timestamps) <= count:
                selected = timestamps
            else:
                selected = self._select_optimal_timestamps(timestamps, count)
            
            self.logger.debug(f"Selected {len(selected)} timestamps from {len(timestamps)} available")
            return selected
            
        except Exception as e:
            log_error(self.logger, "Timestamp Picker", "selection", str(e))
            return []
    
    def _select_optimal_timestamps(self, timestamps: List[str], count: int) -> List[str]:
        """
        Select optimal timestamps using various strategies
        
        Args:
            timestamps: Sorted list of timestamps
            count: Number to select
            
        Returns:
            List of selected timestamps
        """
        if count == 1:
            # Return the most recent
            return [timestamps[-1]]
        
        if count == 2:
            # Return oldest and newest
            return [timestamps[0], timestamps[-1]]
        
        if count >= 3:
            # Return oldest, newest, and random middle
            selected = [timestamps[0], timestamps[-1]]
            
            # Select random timestamps from the middle
            middle_timestamps = timestamps[1:-1]
            
            if middle_timestamps:
                remaining_count = min(count - 2, len(middle_timestamps))
                
                if remaining_count == 1:
                    # Pick one from the middle third
                    middle_index = len(middle_timestamps) // 2
                    selected.append(middle_timestamps[middle_index])
                else:
                    # Pick multiple random timestamps
                    random_timestamps = random.sample(
                        middle_timestamps,
                        min(remaining_count, len(middle_timestamps))
                    )
                    selected.extend(random_timestamps)
            
            return selected
        
        return timestamps[:count]
    
    def select_timestamps_by_strategy(
        self,
        entries: List[Dict[str, Any]],
        strategy: str = "balanced"
    ) -> List[str]:
        """
        Select timestamps using different strategies
        
        Args:
            entries: List of CDX entries
            strategy: Selection strategy ("oldest", "newest", "random", "balanced")
            
        Returns:
            List of selected timestamps
        """
        if not entries:
            return []
        
        try:
            # Extract and filter timestamps
            valid_entries = [
                entry for entry in entries
                if entry.get('timestamp') and entry.get('statuscode', '').startswith('2')
            ]
            
            if not valid_entries:
                return []
            
            # Sort by timestamp
            valid_entries.sort(key=lambda x: x.get('timestamp', ''))
            
            timestamps = [entry['timestamp'] for entry in valid_entries]
            
            if strategy == "oldest":
                # Return oldest timestamps
                return timestamps[:self.max_timestamps]
            
            elif strategy == "newest":
                # Return newest timestamps
                return timestamps[-self.max_timestamps:]
            
            elif strategy == "random":
                # Return random timestamps
                count = min(self.max_timestamps, len(timestamps))
                return random.sample(timestamps, count)
            
            else:  # balanced (default)
                return self.select_timestamps(entries, self.max_timestamps)
                
        except Exception as e:
            log_error(self.logger, "Timestamp Picker", f"strategy_{strategy}", str(e))
            return []
    
    def get_timestamp_metadata(self, timestamp: str) -> Dict[str, Any]:
        """
        Get metadata about a timestamp
        
        Args:
            timestamp: Wayback Machine timestamp
            
        Returns:
            Dictionary with timestamp metadata
        """
        try:
            # Parse timestamp (YYYYMMDDHHMMSS format)
            if len(timestamp) < 14:
                return {"error": "Invalid timestamp format"}
            
            year = int(timestamp[:4])
            month = int(timestamp[4:6])
            day = int(timestamp[6:8])
            hour = int(timestamp[8:10])
            minute = int(timestamp[10:12])
            second = int(timestamp[12:14])
            
            # Create datetime object
            dt = datetime(year, month, day, hour, minute, second)
            
            return {
                "year": year,
                "month": month,
                "day": day,
                "hour": hour,
                "minute": minute,
                "second": second,
                "datetime": dt,
                "iso_format": dt.isoformat(),
                "readable": dt.strftime("%Y-%m-%d %H:%M:%S"),
                "age_days": (datetime.now() - dt).days
            }
            
        except Exception as e:
            return {"error": f"Failed to parse timestamp: {e}"}
    
    def filter_timestamps_by_age(
        self,
        timestamps: List[str],
        min_age_days: int = None,
        max_age_days: int = None
    ) -> List[str]:
        """
        Filter timestamps by age
        
        Args:
            timestamps: List of timestamps
            min_age_days: Minimum age in days
            max_age_days: Maximum age in days
            
        Returns:
            Filtered list of timestamps
        """
        if not timestamps:
            return []
        
        try:
            filtered = []
            now = datetime.now()
            
            for timestamp in timestamps:
                metadata = self.get_timestamp_metadata(timestamp)
                
                if "error" in metadata:
                    continue
                
                age_days = metadata["age_days"]
                
                # Check age constraints
                if min_age_days is not None and age_days < min_age_days:
                    continue
                
                if max_age_days is not None and age_days > max_age_days:
                    continue
                
                filtered.append(timestamp)
            
            return filtered
            
        except Exception as e:
            log_error(self.logger, "Timestamp Picker", "age_filter", str(e))
            return timestamps
    
    def get_selection_statistics(
        self,
        all_entries: List[Dict[str, Any]],
        selected_timestamps: List[str]
    ) -> Dict[str, Any]:
        """
        Get statistics about timestamp selection
        
        Args:
            all_entries: All CDX entries
            selected_timestamps: Selected timestamps
            
        Returns:
            Statistics dictionary
        """
        try:
            total_entries = len(all_entries)
            selected_count = len(selected_timestamps)
            
            # Get date range of all entries
            all_timestamps = [entry.get('timestamp') for entry in all_entries if entry.get('timestamp')]
            all_timestamps.sort()
            
            date_range = None
            if all_timestamps:
                start_meta = self.get_timestamp_metadata(all_timestamps[0])
                end_meta = self.get_timestamp_metadata(all_timestamps[-1])
                
                if "error" not in start_meta and "error" not in end_meta:
                    date_range = {
                        "start": start_meta["readable"],
                        "end": end_meta["readable"],
                        "span_days": end_meta["age_days"] - start_meta["age_days"]
                    }
            
            # Get metadata for selected timestamps
            selected_metadata = []
            for timestamp in selected_timestamps:
                meta = self.get_timestamp_metadata(timestamp)
                if "error" not in meta:
                    selected_metadata.append(meta)
            
            return {
                "total_entries": total_entries,
                "selected_count": selected_count,
                "selection_percentage": (selected_count / total_entries * 100) if total_entries > 0 else 0,
                "date_range": date_range,
                "selected_timestamps_metadata": selected_metadata
            }
            
        except Exception as e:
            log_error(self.logger, "Timestamp Picker", "statistics", str(e))
            return {"error": str(e)}

# Singleton instance
_timestamp_picker = None

def get_timestamp_picker() -> TimestampPicker:
    """Get the timestamp picker instance"""
    global _timestamp_picker
    if _timestamp_picker is None:
        _timestamp_picker = TimestampPicker()
    return _timestamp_picker
