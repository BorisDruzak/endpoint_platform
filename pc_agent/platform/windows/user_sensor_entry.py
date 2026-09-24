"""Fixed executable entrypoint for the interactive User Sensor."""

from pc_agent.platform.windows.user_sensor_runtime import main


if __name__ == "__main__":
    raise SystemExit(main())
