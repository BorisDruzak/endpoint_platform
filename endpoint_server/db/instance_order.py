"""Canonical latest authenticated instance ordering, including unknown versions."""

from endpoint_server.db.models.devices import DeviceInstance


def latest_instance_order():
    return (DeviceInstance.last_seen_at.desc().nulls_last(), DeviceInstance.id.desc())
