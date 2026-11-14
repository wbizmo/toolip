# Java dependency graph imports

Toolip reads Java dependency results as inert files. It does not invoke Maven or
Gradle and does not run build plugins while scanning.

For Maven, provide `maven-dependency-tree.json` as the resolved tree object
emitted by `maven-dependency-plugin` or an array of module roots. The plugin's
`-DoutputType=json` output uses `groupId`, `artifactId`, `version`, `type`,
`classifier`, `scope`, `optional`, and `children`. In that official output,
`classifier` may be an empty string and `optional` is a string boolean; Toolip
normalizes those forms without losing exact coordinates. For a multi-module
build, capture one tree per module and combine the unmodified root objects into
an array. A single root object is also accepted.

For Gradle, provide `gradle-dependencies.json` using resolved nodes under a
`modules` array. Each module root has `group`, `module`, `version`, and
`dependencies`; dependency nodes have exact coordinates, scope and recursively
nested `dependencies`. The parser also accepts `groupId`, `artifactId`,
`children` and `dependencies` aliases where Maven-style exporters use them.
Gradle does not provide a stable built-in JSON dependency-tree format, so this
file is an export contract for a trusted build-side adapter. Gradle's generated
`gradle.lockfile` is read at the root and in nested project modules, but it only
establishes exact locked identities; Toolip marks coverage incomplete until a
resolved graph export supplies edges. The Maven `maven-dependency-tree.txt`
format remains supported as a compatibility input.

For example, a Maven module can be captured with:

```sh
mvn org.apache.maven.plugins:maven-dependency-plugin:3.8.1:tree \
  -DoutputType=json -DoutputFile=target/toolip-dependencies.json -Dverbose
```

For Gradle, generate the JSON from a build-side task that resolves the chosen
configuration and serializes its resolved module graph. Run that task in the
trusted build that produced the scan snapshot, then pass the export as inert
input. Toolip itself never invokes the build task.

These exports must come from a trusted, reviewed Maven/Gradle execution that
resolved the actual module graph. They represent the result of parent POM
properties, BOM management, Gradle constraints and lock overrides without
asking Toolip to execute the project. Exact group, artifact and version
coordinates become Maven package identities; module boundaries keep equal
coordinates in separate workspaces distinct. Classifiers and non-default types
are preserved in CycloneDX and SPDX Maven PURLs. `tests/fixtures/java` contains
captured Maven and Gradle reference outputs for parent-property, BOM and Gradle
lock-selection behavior, with tool versions and checksums recorded beside the
fixtures.

Malformed nodes, unresolved property expressions, conflict-omitted entries,
unknown edges, missing resolved exports, and nested workspaces that are not
represented by an imported graph make coverage incomplete. Toolip does not
substitute a declared version range or unresolved property with a guessed
installed version. JSON imports are bounded to 100,000 nodes and 512 levels;
the shared dependency file reader also applies its regular-file and byte limits.
Maven's verbose JSON exporter can include both sides of a version conflict
without identifying the evicted node. When one module contains multiple
versions of the same group, artifact, type and classifier, Toolip marks those
versions unknown, withholds them from OSV and reports incomplete coverage.
Maven scopes are validated against the supported scope set. Gradle's common
`api`, `implementation`, compile/runtime classpath, and test configurations map
to dependency sections; unknown scopes and malformed `optional` or `omitted`
flags keep the exact coordinate visible but mark graph coverage incomplete.

This import support does not establish artifact provenance, run Maven/Gradle
advisory tests, or verify that the exported file was generated from the current
revision. Retain the export with the build that produced it and bind it to the
same immutable project snapshot when using the API.
