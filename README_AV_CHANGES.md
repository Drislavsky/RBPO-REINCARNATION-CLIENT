# BMTX antivirus scanning changes

Implemented in source files:

- `rpc/bmtx_rpc.idl`
  - Added `BMTX_AV_DB_INFO` and `BMTX_SCAN_RESULT` RPC structs.
  - Added RPC methods `BmtxGetAvDbInfo`, `BmtxScanFile`, `BmtxScanDirectory`.

- `src/service.cpp`
  - Added an in-memory antivirus database based on `std::map<uint64_t, std::vector<AvRecord>>`.
  - Database key: first 8 bytes of the signature.
  - Record fields include prefix, signature length, hashed signature, offset range, object type, and a demo record signature hash.
  - Added two object types: PE files and scripts.
  - Database is loaded after successful activation and can also be queried through RPC.
  - Added byte-stream scanning logic that checks object type, offset interval, signature bytes, and hash.
  - Added selected file and recursive directory scanning.

- `src/main.cpp`
  - Added RPC wrappers for AV database info, file scanning, and directory scanning.
  - Added GUI buttons for scan file, scan folder, and AV database information refresh.
  - Added result output showing scanned count, infected count, threat name, and first infected path.

- `CMakeLists.txt`
  - Added required Windows libraries: `comdlg32`, `ole32`, and `shlwapi`.

Notes:

- The demo AV database is intentionally in RAM only, as allowed by the task.
- Demo signatures included: EICAR test string, a PE demo signature, and a script demo signature.
- Rebuild on Windows so MIDL regenerates `bmtx_rpc.h`, `bmtx_rpc_c.c`, and `bmtx_rpc_s.c` from the updated IDL.
