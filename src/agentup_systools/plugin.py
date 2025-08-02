"""
Agentup Systools plugin for AgentUp.

A plugin that provides Agentup Systools functionality
"""

import datetime
from typing import Dict, Any
import structlog

from agent.plugins.base import Plugin
from agent.plugins.decorators import capability
from agent.plugins.models import CapabilityContext


class AgentupSystoolsPlugin(Plugin):
    """Basic plugin class for Agentup Systools."""

    def __init__(self):
        """Initialize the plugin."""
        super().__init__()
        self.name = "agentup_systools"
        self.version = "1.0.0"

    @capability(
        id="read_file",
        name="Agentup Systools",
        description="A plugin that provides Agentup Systools functionality",
        scopes=["agentup-systools:use"],
        ai_function=False    )
    async def read_file(self, context: CapabilityContext) -> Dict[str, Any]:
        """Execute the agentup systools capability."""
        try:
            # Extract input from context using base class method
            input_text = self._extract_task_content(context)
            
            # Log the start of processing (demonstrates structured logging)
            self.logger.info("Starting capability execution", capability_id="read_file", input_length=len(input_text))

            # Basic processing
            processed_result = f"Agentup Systools processed: {input_text}"
            
            # Log successful completion
            self.logger.info("Capability execution completed", 
                           capability_id="read_file", 
                           input_length=len(input_text),
                           result_length=len(processed_result))

            return {
                "success": True,
                "content": processed_result,
                "metadata": {
                    "capability": "read_file",
                    "processed_at": datetime.datetime.now().isoformat(),
                    "input_length": len(input_text)
                }
            }

        except Exception as e:
            # Log the error with structured data
            self.logger.error("Error in capability execution", 
                            capability_id="read_file", 
                            error=str(e), 
                            exc_info=True)
            return {
                "success": False,
                "error": str(e),
                "content": f"Error in Agentup Systools: {str(e)}"
            }

    def get_config_schema(self) -> Dict[str, Any]:
        """Define configuration schema for basic plugin."""
        return {
            "type": "object",
            "properties": {
                "enabled": {
                    "type": "boolean",
                    "default": True,
                    "description": "Enable/disable the plugin"
                },
                "debug": {
                    "type": "boolean",
                    "default": False,
                    "description": "Enable debug logging"
                }
            },
            "additionalProperties": False
        }

    def validate_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Validate basic plugin configuration."""
        return {
            "valid": True,
            "errors": [],
            "warnings": []
        }

    def _extract_user_input(self, context: CapabilityContext) -> str:
        """Extract user input from the task context (A2A message structure)."""
        if hasattr(context.task, "history") and context.task.history:
            # Get the first user message (not the last, as that might be agent response)
            for msg in context.task.history:
                if hasattr(msg, "role") and msg.role.value == "user":
                    if hasattr(msg, "parts") and msg.parts:
                        for part in msg.parts:
                            if hasattr(part, "root") and hasattr(part.root, "text"):
                                return part.root.text
                            elif hasattr(part, "text"):
                                return part.text
        return ""

    async def cleanup(self):
        """Cleanup resources when plugin is destroyed."""
        # Basic cleanup
        pass
