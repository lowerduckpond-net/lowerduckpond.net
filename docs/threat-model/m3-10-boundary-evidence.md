# M3.10 archive boundary review evidence

This review slice introduces exact versioned storage, construction and retirement
journals, quarantine, private descriptor transport, and job-bound export and
construction services. Lifecycle dispatch and installed service configuration
follow in separate dependent reviews. Publication remains disabled.

| Invariant | Evidence in this slice |
| --- | --- |
| Explicit regional credential, fixed system trust, no ambient endpoint/authentication, one low-level upload | `test_archive_remote.py`, `test_archive_configuration.py` |
| All versions, markers, and multipart accounting; preserve unknown or bound bytes | `test_archive_journal.py`, packaged `test_archive_remote_minio.py` |
| Construction authority exists before upload; interrupted preparation never repeats a PUT | `test_archive_journal.py`, `test_archive_construction_service.py` |
| Export exclusion survives descriptor transfer and worker exit | `test_locks.py`, `test_archive_transport.py`, `test_archive_service.py` |
| Archived export returns the exact bound bundle through ordinary job authority | `test_export_handler.py`, `test_archive_service.py`, `test_export_snapshot.py` |
| Administrator deletion has distinct strict authority, without ordinary job impersonation | `test_emergency_contract.py`; handler and installed evidence follow in the lifecycle/configuration reviews |

The independently assembled slice passed 1,776 contract and host-agent tests.
Its MinIO test is an explicit separate lane, not live Spaces evidence. The
remaining Python/infrastructure checks and required installed-host CI qualify
this slice independently of the complete development branch. Record review
acceptance and exact CI conclusions on its PR before merging.

This file does not assert that the complete M3.10 convergence gate has passed.
Live checks run on the secure workstation; production credentials never enter
the coder workspace or review artifacts.
