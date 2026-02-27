"""
Lightweight pub/sub event bus for cross-view communication in MAD.
Views publish events (e.g. 'process_selected') and other views subscribe.
"""

from collections import defaultdict


class EventBus:
    """Simple publish/subscribe event system for decoupled view communication."""

    def __init__(self):
        self._handlers = defaultdict(list)

    def on(self, event_name, handler):
        """Subscribe to an event.

        Args:
            event_name: Event identifier string
            handler: Callable that receives **kwargs from emit()
        """
        self._handlers[event_name].append(handler)

    def off(self, event_name, handler=None):
        """Unsubscribe from an event.

        Args:
            event_name: Event identifier string
            handler: Specific handler to remove, or None to remove all
        """
        if handler is None:
            self._handlers[event_name].clear()
        else:
            self._handlers[event_name] = [
                h for h in self._handlers[event_name] if h is not handler
            ]

    def emit(self, event_name, **kwargs):
        """Publish an event to all subscribers.

        Args:
            event_name: Event identifier string
            **kwargs: Event data passed to handlers
        """
        for handler in self._handlers[event_name]:
            try:
                handler(**kwargs)
            except Exception as e:
                print(f"EventBus error in handler for '{event_name}': {e}")
