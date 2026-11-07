# Java dependency graph imports

Toolip reads Java dependency results as inert files. It does not invoke Maven or
Gradle and does not run build plugins while scanning.

For Maven, provide `maven-dependency-tree.json` as a resolved tree object or an
array of module roots. Each root and dependency uses `groupId`, `artifactId`,
`version`, optional `type`, `classifier`, `scope`, and `optional` fields, with a
`children` array. For Gradle, provide `gradle-dependencies.json` using the same
resolved node fields under a `modules` array. The parser also accepts `group`,
`module`, and `dependencies` aliases for Gradle exports. The existing
`gradle.lockfile` remains supported for exact identities, but Toolip marks it
incomplete when no resolved graph export supplies dependency edges. The Maven
`maven-dependency-tree.txt` format remains supported as a compatibility input.

These exports must come from a trusted, reviewed Maven/Gradle execution that
resolved the actual module graph. They represent the result of parent POM
properties, BOM management, Gradle constraints and lock overrides without
asking Toolip to execute the project. Exact group, artifact and version
coordinates become Maven package identities; module boundaries keep equal
coordinates in separate workspaces distinct. Classifiers and non-default types
are preserved in CycloneDX and SPDX Maven PURLs.

Malformed nodes, unresolved property expressions, conflict-omitted entries,
unknown edges, missing resolved exports, and nested workspaces that are not
represented by an imported graph make coverage incomplete. Toolip does not
substitute a declared version range or unresolved property with a guessed
installed version. JSON imports are bounded to 100,000 nodes and 512 levels;
the shared dependency file reader also applies its regular-file and byte limits.

This import support does not establish artifact provenance, run Maven/Gradle
advisory tests, or verify that the exported file was generated from the current
revision. Retain the export with the build that produced it and bind it to the
same immutable project snapshot when using the API.
