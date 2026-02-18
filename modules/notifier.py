"""
Discord notification module for sending alerts
"""

import asyncio
import json
from typing import Dict, Any, Optional, List
from datetime import datetime

from utils.logger import get_logger, log_error
from utils.rate_limiter import get_rate_limiter
from config.config import DISCORD_WEBHOOKS

class DiscordNotifier:
    """
    Send Discord notifications for different vulnerability types
    """
    
    def __init__(self):
        self.logger = get_logger()
        self.rate_limiter = get_rate_limiter()
        self.webhooks = DISCORD_WEBHOOKS
        
        # Discord color codes for different severities
        self.severity_colors = {
            "CRITICAL": 0xFF0000,  # Red
            "HIGH": 0xFF6600,      # Orange
            "MEDIUM": 0xFFFF00,    # Yellow
            "LOW": 0x00FF00,       # Green
            "INFO": 0x00FFFF       # Cyan
        }
    
    async def send_js_leak_alert(self, finding: Dict[str, Any]) -> bool:
        """
        Send alert for JavaScript leak findings
        
        Args:
            finding: Finding dictionary
            
        Returns:
            True if successful
        """
        webhook_url = self.webhooks.get("js_leaks")
        if not webhook_url:
            self.logger.warning("No Discord webhook configured for JS leaks")
            return False
        
        return await self._send_discord_alert(webhook_url, finding, "JavaScript Leak")
    
    async def send_env_exposure_alert(self, finding: Dict[str, Any]) -> bool:
        """
        Send alert for environment file exposure
        
        Args:
            finding: Finding dictionary
            
        Returns:
            True if successful
        """
        webhook_url = self.webhooks.get("env_exposure")
        if not webhook_url:
            self.logger.warning("No Discord webhook configured for ENV exposure")
            return False
        
        return await self._send_discord_alert(webhook_url, finding, "Environment File Exposure")
    
    async def send_git_exposure_alert(self, finding: Dict[str, Any]) -> bool:
        """
        Send alert for Git repository exposure
        
        Args:
            finding: Finding dictionary
            
        Returns:
            True if successful
        """
        webhook_url = self.webhooks.get("git_exposure")
        if not webhook_url:
            self.logger.warning("No Discord webhook configured for Git exposure")
            return False
        
        return await self._send_discord_alert(webhook_url, finding, "Git Repository Exposure")
    
    async def send_cors_alert(self, finding: Dict[str, Any]) -> bool:
        """
        Send alert for CORS misconfiguration
        
        Args:
            finding: Finding dictionary
            
        Returns:
            True if successful
        """
        webhook_url = self.webhooks.get("cors")
        if not webhook_url:
            self.logger.warning("No Discord webhook configured for CORS")
            return False
        
        return await self._send_discord_alert(webhook_url, finding, "CORS Misconfiguration")
    
    async def _send_discord_alert(
        self,
        webhook_url: str,
        finding: Dict[str, Any],
        alert_type: str
    ) -> bool:
        """
        Send Discord alert using webhook
        
        Args:
            webhook_url: Discord webhook URL
            finding: Finding dictionary
            alert_type: Type of alert
            
        Returns:
            True if successful
        """
        try:
            # Create Discord embed
            embed = self._create_discord_embed(finding, alert_type)
            
            # Prepare payload
            payload = {
                "embeds": [embed],
                "username": "Security Scanner",
                "avatar_url": "https://i.imgur.com/4M34hi2.png"  # Security icon
            }
            
            # Send request
            response = await self.rate_limiter.post(
                webhook_url,
                json=payload,
                headers={"Content-Type": "application/json"}
            )
            
            if response and response.status == 204:
                self.logger.info(f"Discord alert sent for {alert_type} on {finding.get('target', 'unknown')}")
                return True
            else:
                self.logger.warning(f"Failed to send Discord alert: {response.status if response else 'No response'}")
                return False
                
        except Exception as e:
            log_error(self.logger, "Discord Notifier", f"{alert_type}", str(e))
            return False
    
    def _create_discord_embed(self, finding: Dict[str, Any], alert_type: str) -> Dict[str, Any]:
        """
        Create Discord embed for the finding
        
        Args:
            finding: Finding dictionary
            alert_type: Type of alert
            
        Returns:
            Discord embed dictionary
        """
        severity = finding.get("severity", "UNKNOWN").upper()
        color = self.severity_colors.get(severity, 0x808080)  # Gray default
        
        # Create title
        title = f"🚨 {severity} - {alert_type}"
        
        # Create description
        target = finding.get("target", "Unknown")
        module = finding.get("module", "Unknown")
        vuln_type = finding.get("vulnerability_type", "Unknown")
        
        description = f"**Target:** {target}\n"
        description += f"**Module:** {module}\n"
        description += f"**Type:** {vuln_type}\n"
        description += f"**Severity:** {severity}"
        
        # Create fields
        fields = []
        
        # URL field
        url = finding.get("url", "")
        if url:
            fields.append({
                "name": "🔗 URL",
                "value": url[:1024] if len(url) > 1024 else url,  # Discord field limit
                "inline": False
            })
        
        # Evidence field
        evidence = finding.get("evidence", "")
        if evidence:
            # Truncate evidence if too long
            if len(evidence) > 1024:
                evidence = evidence[:1000] + "..."
            
            fields.append({
                "name": "📋 Evidence",
                "value": f"```{evidence}```",
                "inline": False
            })
        
        # Additional fields based on finding type
        if alert_type == "Environment File Exposure":
            secrets = finding.get("secrets", [])
            if secrets:
                secret_count = len(secrets)
                categories = set(secret.get("category", "unknown") for secret in secrets)
                fields.append({
                    "name": "🔑 Secrets Found",
                    "value": f"**Count:** {secret_count}\n**Categories:** {', '.join(categories)}",
                    "inline": True
                })
        
        elif alert_type == "Git Repository Exposure":
            git_info = finding.get("git_info", {})
            accessible_files = git_info.get("accessible_files", [])
            if accessible_files:
                fields.append({
                    "name": "📁 Accessible Files",
                    "value": f"{len(accessible_files)} files exposed",
                    "inline": True
                })
        
        elif alert_type == "JavaScript Leak":
            # Add specific JS leak info if available
            pass
        
        elif alert_type == "CORS Misconfiguration":
            test_origin = finding.get("test_origin", "")
            misconfig_type = finding.get("misconfiguration_type", "")
            if test_origin:
                fields.append({
                    "name": "🎯 Test Origin",
                    "value": test_origin,
                    "inline": True
                })
            if misconfig_type:
                fields.append({
                    "name": "⚠️ Misconfiguration",
                    "value": misconfig_type.replace("_", " ").title(),
                    "inline": True
                })
        
        # Timestamp
        timestamp = finding.get("timestamp", datetime.now().isoformat())
        fields.append({
            "name": "⏰ Discovered",
            "value": f"<t:{int(datetime.fromisoformat(timestamp.replace('Z', '+00:00')).timestamp())}:R>",
            "inline": True
        })
        
        # Create embed
        embed = {
            "title": title,
            "description": description,
            "color": color,
            "fields": fields,
            "footer": {
                "text": "Security Scanner",
                "icon_url": "https://i.imgur.com/4M34hi2.png"
            },
            "timestamp": datetime.now().isoformat()
        }
        
        return embed
    
    async def send_summary_alert(self, summary: Dict[str, Any]) -> bool:
        """
        Send summary alert with scan statistics
        
        Args:
            summary: Summary statistics dictionary
            
        Returns:
            True if successful
        """
        # Use a general webhook or the first available one
        webhook_url = None
        for webhook_type, url in self.webhooks.items():
            if url:
                webhook_url = url
                break
        
        if not webhook_url:
            self.logger.warning("No Discord webhook configured for summary alerts")
            return False
        
        try:
            # Create summary embed
            embed = self._create_summary_embed(summary)
            
            # Prepare payload
            payload = {
                "embeds": [embed],
                "username": "Security Scanner",
                "avatar_url": "https://i.imgur.com/4M34hi2.png"
            }
            
            # Send request
            response = await self.rate_limiter.post(
                webhook_url,
                json=payload,
                headers={"Content-Type": "application/json"}
            )
            
            if response and response.status == 204:
                self.logger.info("Summary alert sent to Discord")
                return True
            else:
                self.logger.warning(f"Failed to send summary alert: {response.status if response else 'No response'}")
                return False
                
        except Exception as e:
            log_error(self.logger, "Discord Notifier", "summary", str(e))
            return False
    
    def _create_summary_embed(self, summary: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create Discord embed for summary statistics
        
        Args:
            summary: Summary statistics
            
        Returns:
            Discord embed dictionary
        """
        total_findings = summary.get("total_findings", 0)
        targets_count = summary.get("targets_count", 0)
        severity_dist = summary.get("severity_distribution", {})
        
        # Determine color based on critical findings
        critical_count = severity_dist.get("CRITICAL", 0)
        high_count = severity_dist.get("HIGH", 0)
        
        if critical_count > 0:
            color = self.severity_colors["CRITICAL"]
        elif high_count > 0:
            color = self.severity_colors["HIGH"]
        else:
            color = self.severity_colors["MEDIUM"]
        
        # Create title and description
        title = "📊 Security Scan Summary"
        
        description = f"**Total Findings:** {total_findings}\n"
        description += f"**Targets Scanned:** {targets_count}\n\n"
        
        # Severity breakdown
        if severity_dist:
            description += "**Severity Breakdown:**\n"
            for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                count = severity_dist.get(severity, 0)
                if count > 0:
                    description += f"• {severity}: {count}\n"
        
        # Create fields
        fields = []
        
        # Module distribution
        module_dist = summary.get("module_distribution", {})
        if module_dist:
            module_text = ""
            for module, count in sorted(module_dist.items(), key=lambda x: x[1], reverse=True)[:5]:
                module_text += f"• {module}: {count}\n"
            
            fields.append({
                "name": "🔧 Top Modules",
                "value": module_text,
                "inline": True
            })
        
        # Type distribution
        type_dist = summary.get("type_distribution", {})
        if type_dist:
            type_text = ""
            for vuln_type, count in sorted(type_dist.items(), key=lambda x: x[1], reverse=True)[:5]:
                type_text += f"• {vuln_type}: {count}\n"
            
            fields.append({
                "name": "🏷️ Top Vulnerability Types",
                "value": type_text,
                "inline": True
            })
        
        # Create embed
        embed = {
            "title": title,
            "description": description,
            "color": color,
            "fields": fields,
            "footer": {
                "text": "Security Scanner",
                "icon_url": "https://i.imgur.com/4M34hi2.png"
            },
            "timestamp": datetime.now().isoformat()
        }
        
        return embed
    
    def test_webhook_configuration(self) -> Dict[str, bool]:
        """
        Test all configured webhooks
        
        Returns:
            Dictionary mapping webhook types to test results
        """
        results = {}
        
        for webhook_type, webhook_url in self.webhooks.items():
            if webhook_url:
                # Basic URL validation
                if webhook_url.startswith("https://discord.com/api/webhooks/"):
                    results[webhook_type] = True
                else:
                    results[webhook_type] = False
            else:
                results[webhook_type] = False
        
        return results
    
    async def send_test_alert(self, webhook_type: str) -> bool:
        """
        Send a test alert to verify webhook configuration
        
        Args:
            webhook_type: Type of webhook to test
            
        Returns:
            True if successful
        """
        webhook_url = self.webhooks.get(webhook_type)
        if not webhook_url:
            return False
        
        try:
            test_embed = {
                "title": "🧪 Test Alert",
                "description": "This is a test alert to verify Discord webhook configuration.",
                "color": 0x00FF00,  # Green
                "footer": {
                    "text": "Security Scanner - Test",
                    "icon_url": "https://i.imgur.com/4M34hi2.png"
                },
                "timestamp": datetime.now().isoformat()
            }
            
            payload = {
                "embeds": [test_embed],
                "username": "Security Scanner (Test)",
                "avatar_url": "https://i.imgur.com/4M34hi2.png"
            }
            
            response = await self.rate_limiter.post(
                webhook_url,
                json=payload,
                headers={"Content-Type": "application/json"}
            )
            
            return response is not None and response.status == 204
            
        except Exception as e:
            self.logger.error(f"Error sending test alert: {e}")
            return False

# Singleton instance
_discord_notifier = None

def get_discord_notifier() -> DiscordNotifier:
    """Get the Discord notifier instance"""
    global _discord_notifier
    if _discord_notifier is None:
        _discord_notifier = DiscordNotifier()
    return _discord_notifier
