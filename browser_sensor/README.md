# Endpoint Browser Sensor source

One Manifest V3 source tree serves Google Chrome and Yandex Browser. The worker sends bounded metadata only to the fixed local Native Messaging host `ru.sosnadmin.endpoint.browser`; it has no Endpoint server credential or network client.

Run `npm test --prefix browser_sensor` from the repository root. The tests require Node.js and no package installation.

Version 0.1 observes active HTTP(S) origin/domain, file-input selection metadata, and paste MIME categories. It does not read file names, clipboard values, page text, titles, cookies or browser history. File-input selection does not cover every upload mechanism, including drag/drop and custom JavaScript transfers.

This tree is unsigned source. A stable extension ID, signed package and managed release metadata are delivered through the separate release phase. Signing material must remain outside the repository.
