"""Parsers package for LogTimeline.

Each parser knows how to read one log format and turn its lines into the
shared ``Core.EventModel.Event`` structure. v0.1 ships a single parser,
``AuthLogParser``, for ISO 8601 ``auth.log`` files.
"""
