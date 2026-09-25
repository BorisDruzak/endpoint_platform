# Browser Sensor signed release

The Browser Sensor has one pinned extension ID in `browser_sensor/extension-id.txt`. Keep its signing private key outside Git and outside the Endpoint server. Build with `python -m browser_sensor.tools.build_release` as documented in `browser_sensor/README.md`; the output directory for each version contains exactly `sensor.crx`, `update.xml`, and `release.json`. Set `minimum_agent_version` from the verified Agent release state before publication; the local `3.2.68` build value is provisional until that gate passes.

## Publish after the server migration

1. Confirm the deployed server includes Alembic `0031_browser_sensor_release` and the three public routes in the canonical OpenAPI contract. Complete the normal server backup and migration gate first.
2. Transfer only the three release files to a version-named candidate directory on the Endpoint server. Do not transfer the signing key. Keep the candidate directory outside `ARTIFACT_ROOT` until registration.
3. In the deployed application environment, load `DATABASE_URL` and `ARTIFACT_ROOT` from the service EnvironmentFile without printing them, then run:

   ```bash
   python -m tools.register_browser_sensor_release --candidate /path/to/candidate/0.1.0
   ```

   The registrar rejects unknown files, wrong version/ID, a bad CRX3 signature, unexpected package entries, hash mismatch, or an update URL outside the approved Endpoint HTTPS route. It stages immutable artifacts and registers metadata in PostgreSQL. Repeating registration of identical verified bytes is safe; a changed release under the same version or a lower version is rejected. If a database transaction fails after artifact staging, the unregistered files may remain in `ARTIFACT_ROOT` but are not served; inspect the failure and registration state before retrying or removing them.

4. With the workstation's trusted Endpoint CA and normal DNS name, fetch `https://endpoint.sosnadmin.local/api/v1/browser-sensor/update.xml`, then the CRX URL named inside it. Verify both SHA-256 values against `release.json`. Verify `GET /api/v1/browser-sensor/releases/0.1.0/release.json` and the admin Console release projection. Do not disable TLS verification.
5. Only after the browser policy applicator, installed Agent package and managed browser test are ready, run the extension-absent Chrome/Yandex force-install acceptance from the Foundation v1 plan. A successful HTTPS fetch alone is not browser installation proof.

The current update manifest selects the latest unretired registration. Versioned CRX and metadata routes remain available after retirement so a previously issued update document does not point to removed bytes. Public routes never list artifact directories and serve only the three registered filenames after digest verification. The Console projection exposes public release identity, not server paths or signing material.
