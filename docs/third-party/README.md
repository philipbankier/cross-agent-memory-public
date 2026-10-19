# Third-Party Sources And Notices

The application's Apache-2.0 license does not replace third-party terms.
`notices.txt` preserves original native-library and Rust notices, including alternative licenses.
The container also retains installed Python/Debian package notices and the pinned Python
producer's aggregate at `/usr/share/doc/cross-agent-memory/python-runtime-licenses.rst`.

`source-index.json` gives HTTPS source locations and complete archive hashes for the pinned
Debian, Python, bundled UI, interpreter and native-library inputs. Download only the sources
needed, check the complete listed hash, and treat archives as data rather than commands.
The Python producer source includes its build scripts and patches. The source distribution
includes this application's build recipe and hash-locked dependencies.

The native inventory is a conservative superset: Rust build/other-target components and both
protobuf versions declared by upstream recipes are retained. Hash origins distinguish upstream
declarations from an observed libffi archive identity. This is not source-to-binary reproducibility,
an exact linker graph, signed upstream attestation or a legal opinion.

These three files are included in the verified source distribution and installed read-only at
`/usr/share/doc/cross-agent-memory/third-party/` in the container. They do not add native binaries
to the Python wheel. The build-provenance manifest binds the companion bytes to its source
revision. Published package/image identities and authenticated provenance are verified separately
at release; a static source index alone is not that proof.
