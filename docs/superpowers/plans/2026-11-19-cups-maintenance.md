# CUPS Maintenance Implementation Plan

**Goal** Enable Endpoint operators to update an existing CUPS queue and submit
a single test page with independently authorized, auditable actions.

1. Add strict command and result contracts. A request selects an existing local
   destination. The queue action sets enabled and accepting state in place.
   The print action submits a fixed first page with one copy.
2. Wire the Linux agent to the local CUPS socket. Persist each intent before
   making a change. Duplicate delivery returns the stored outcome. If a process
   stops during an action, report an unknown outcome and reconcile before
   retrying the physical operation.
3. Deliver the actions through Endpoint Gateway from separately scoped Endpoint
   routes. Persist the authenticated actor, target, intent and terminal outcome.
   Keep the existing module catalog and diagnostic contracts compatible.
4. Exercise replay and access controls end to end. On an isolated Linux queue
   with pending jobs, verify that configuring the queue preserves the jobs and
   submitting the test page adds exactly one job.

References for the in-place CUPS operations and fixed page options
[CUPS clients](https://openprinting.github.io/cups/doc/man-client.conf.html),
[queue state](https://openprinting.github.io/cups/doc/man-cupsenable.html),
[acceptance state](https://openprinting.github.io/cups/doc/man-cupsaccept.html),
and [print submission](https://openprinting.github.io/cups/doc/man-lp.html).
