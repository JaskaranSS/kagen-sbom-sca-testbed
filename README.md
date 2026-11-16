# kagen-sbom-sca-testbed

Synthetic monorepo for exercising the Kagen Secure **SBOM** and **SCA** modules (zip upload and GitHub-connector scans).
It contains **only dependency manifests and lockfiles** pinned to publicly known-vulnerable versions — no runnable code.
**Do not deploy anything from here.**

Upload `kagen-sbom-sca-testbed.zip` to SBOM and to SCA, then check the results against this sheet.

## 1. Coverage matrix — what each folder exercises

| Path | Files | Discovery parser | What to check |
|---|---|---|---|
| `services/web-frontend/` | package.json, package-lock.json (lockfileVersion **3**), workspace `packages/shared-ui` | ParseNpmManifest, ParseNpmLock | direct vs transitive, dev group, nested `express/node_modules/debug`, workspace `link: true` resolved, licence mix |
| `services/legacy-ui/` | package-lock.json (lockfileVersion **1**) | ParseNpmV1 | nested `optimist → minimist 0.0.10`, `requires` edges |
| `services/yarn-classic/` | yarn.lock v1 | ParseYarn (classic) | multi-selector `"set-value@^2.0.0", "set-value@^2.0.1"` maps to one node |
| `services/yarn-berry/` | yarn.lock Berry (`__metadata`) | ParseYarn (berry) | `npm:` alias `my-semver@npm:semver@7.3.2`: check it is reported as `semver 7.3.2`, not a package named `my-semver@npm:semver` (that would be a parser bug); workspace entry |
| `services/pnpm-app/` | pnpm-lock.yaml v9 | ParsePnpm | importers = direct, snapshots = edges |
| `services/bun-app/` | bun.lock | — | **warning** `discovery.unsupported_manifest` |
| `services/broken/` | truncated package.json | — | **warning** `discovery.manifest_unreadable`; rest of scan continues |
| `services/huge/` | 2.2 MB package-lock.json | — | **warning** `discovery.file_limit` (manifest cap is 2 MB) |
| `python/api/` | requirements.txt with `-r`, `-c`, `--index-url`, extras, markers, `--hash`, ranges, editable + local wheel | ParseRequirements | includes resolved recursively; ranges stay unpinned |
| `python/pipenv-svc/` | Pipfile + Pipfile.lock | ParsePythonManifest(TOML), ParsePipfile | `default` / `develop` groups, markers |
| `python/poetry-svc/` | pyproject.toml (`tool.poetry` **and** PEP 621 `[project]`) + poetry.lock | ParsePythonManifest, ParseTomlLock | groups main/test/dev/docs; lock edges |
| `python/legacy/` | setup.py, setup.cfg, uv.lock | — | **warnings** `discovery.dynamic_manifest` ×2, `discovery.unsupported_manifest` (uv.lock) |
| `java/maven-parent/` | parent POM + `order-service` child POM | ParsePom | versions from parent `dependencyManagement` + `${properties}`; scopes; `optional`; plugin deps **excluded**; `${undefined.version}` kept as unresolved |
| `java/gradle-svc/` | build.gradle (Groovy, `ext`/`def` variables, map notation), reporting/build.gradle.kts, gradle.lockfile, okhttp.lockfile | ParseGradleManifest, ParseGradleLock | **warnings** `discovery.gradle_lock` (one malformed line), `discovery.gradle_catalog` (`libs.okhttp`) |
| `java/scala-svc/` | build.sbt | — | **warning** `discovery.unsupported_manifest` |
| `go/` | go.mod (block + single `require`, `// indirect`, `replace`) + go.sum | ParseGoMod, ParseGoSum | `github.com/old/logger` reported as `sirupsen/logrus v1.4.2`; go.sum's stale `x/text v0.3.2` **ignored** |
| `rust/` | workspace Cargo.toml, crates/api/Cargo.toml, Cargo.lock v3 | ParseCargoManifest, ParseTomlLock | `workspace = true`, `package =` rename, path dep, target-specific deps, dev/build groups |
| `ruby/` | Gemfile + Gemfile.lock | ParseGems | DEPENDENCIES = direct, specs edges |
| `php/` | composer.json + composer.lock | — | **warning** `discovery.unsupported_manifest` ×2 (PHP not parsed yet) |
| `dotnet/` | Directory.Packages.props (central versions), Api.csproj (`$(Property)` version, `<Version>` element, range), packages.lock.json, packages.config, .fsproj, .vbproj, obj/project.assets.json | ParseNugetXml, ParseNugetLock, ParseNugetAssets | central versions applied; `Worker.Shared` project ref **not** a package |
| `infra/terraform/` | main.tf + .terraform.lock.hcl | ParseTerraform (IaC) | providers (object + short form), registry modules; local `./modules/thing` module |
| `infra/helm/` | Chart.yaml + Chart.lock (v2), requirements.yaml + requirements.lock (v1) | ParseHelm (IaC) | locked vs declared versions |
| `vendor/` | jquery-1.8.3.min.js, app.bundle.js, libcrypto.so (ELF stub), sqlite3.dll (PE stub), empty.dll | Binary identification | stubs stay **Unresolved** unless the reference catalog matches; `empty.dll` → `discovery.artifact_unreadable` |
| `sbom/` | CycloneDX 1.5 + SPDX 2.3 JSON | — | **ignored** inside a zip (not on the source allowlist). Use `extras/` for SBOM-document import |

### Must NOT appear in results
`evil-should-be-ignored` / `event-stream` (under node_modules), `flask 0.1` (under .venv), `git-internal-should-be-ignored` / `left-pad` (under .git),
`plugin.only:must-not-appear`, `golang.org/x/text v0.3.2`, anything from `README.md`.

### Parser quirks this repo surfaces (worth checking)
1. **Only a file named exactly `requirements.txt` is parsed.** `requirements-base.txt`, `requirements-constraints.txt` and `requirements-dev.txt` are kept (the allowlist matches `requirements*.txt`) but come back as `unsupported_manifest` when read on their own. They still count when pulled in with `-r` / `-c`.
2. **Editable and local requirements:** `-e git+…#egg=internal-lib` and `./vendor/local-wheel-…whl` should end up as `requirement_unresolved`. The requirement regex accepts `-` and `.` as name characters, so look for odd components named `-e` or `.`.
3. **Gemfile.lock with platform-specific duplicates** (e.g. `nokogiri (1.10.0-x86_64-linux)`) would throw while building the dictionary. This repo avoids them on purpose.

## 2. Expected vulnerabilities (OSV), by ecosystem

Only well-known advisories are listed. OSV will return more. A **bold** row has a critical/high CVE that should drive the CI gate.

### npm
| Package@version | Where | Expected IDs (not exhaustive) |
|---|---|---|
| **lodash@4.17.15** | web-frontend (+ shared-ui, edge zip) | CVE-2020-8203, CVE-2021-23337 |
| lodash@4.17.11 | legacy-ui | CVE-2019-10744, CVE-2020-8203 |
| axios@0.21.1 | web-frontend | CVE-2021-3749, CVE-2023-45857 |
| **minimist@1.2.5** / 0.0.10 | web-frontend / legacy-ui | CVE-2021-44906 (+ CVE-2020-7598 for 0.0.10) |
| node-fetch@2.6.0 | web-frontend | CVE-2020-15168, CVE-2022-0235 |
| **jsonwebtoken@8.5.1** | web-frontend | CVE-2022-23529, CVE-2022-23539, CVE-2022-23540, CVE-2022-23541 |
| express@4.17.1 / qs@6.7.0 | web-frontend | CVE-2024-29041, CVE-2022-24999 |
| path-to-regexp@0.1.7 | web-frontend | CVE-2024-45296 |
| moment@2.29.1 | web-frontend | CVE-2022-24785, CVE-2022-31129 |
| marked@0.3.6 | web-frontend | several XSS / ReDoS |
| xmldom@0.6.0 | web-frontend | CVE-2022-39353, CVE-2021-32796 |
| ua-parser-js@0.7.28 | web-frontend | CVE-2022-25927 |
| follow-redirects@1.13.1 | web-frontend (transitive) | CVE-2022-0155, CVE-2022-0536 |
| semver@5.7.1, semver@7.3.2 | web-frontend, yarn-berry (alias) | CVE-2022-25883 |
| minimatch@3.0.4 | web-frontend (dev, nested) | CVE-2022-3517 |
| handlebars@4.0.11 | legacy-ui | CVE-2019-19919 + others |
| jquery@2.2.4 | legacy-ui | CVE-2015-9251, CVE-2019-11358, CVE-2020-11022, CVE-2020-11023 |
| angular@1.5.8, bootstrap@3.3.7 | legacy-ui | many XSS (bootstrap: CVE-2019-8331, CVE-2018-14040/41/42) |
| underscore@1.12.0 | legacy-ui | CVE-2021-23358 |
| dot-prop@4.2.0 | legacy-ui | CVE-2020-8116 |
| elliptic@6.5.3 | yarn-classic | CVE-2020-28498 |
| kind-of@6.0.2 | yarn-classic | CVE-2019-20149 |
| serialize-javascript@2.1.0 | yarn-classic | CVE-2020-7660 |
| set-value@2.0.0 | yarn-classic | CVE-2019-10747, CVE-2021-23440 |
| ws@7.4.5 | yarn-berry | CVE-2021-32640, CVE-2024-37890 |
| trim-newlines@3.0.0 | yarn-berry | CVE-2021-33623 |
| tar@4.4.13 | pnpm-app | CVE-2021-32803, CVE-2021-32804, CVE-2021-37701 |
| glob-parent@5.1.1 | pnpm-app | CVE-2020-28469 |
| nth-check@1.0.2 | pnpm-app | CVE-2021-3803 |
| shell-quote@1.7.2 | pnpm-app | CVE-2021-42740 |
| ansi-regex@5.0.0 | pnpm-app (dev) | CVE-2021-3807 |

### PyPI
| Package@version | Where | Expected IDs |
|---|---|---|
| **django@2.2.0** | python/api | many (e.g. CVE-2019-12308, CVE-2019-14234) |
| requests@2.19.1 | python/api | CVE-2018-18074, CVE-2023-32681 |
| **pyyaml@5.3** | python/api | CVE-2020-1747, CVE-2020-14343 |
| jinja2@2.10 | python/api | CVE-2019-10906, CVE-2020-28493 |
| urllib3@1.24.1 | python/api | CVE-2019-11324, CVE-2019-11236 |
| flask@0.12.2 | python/api | CVE-2018-1000656, CVE-2019-1010083 |
| werkzeug@0.15.3 | python/api | CVE-2023-25577 |
| sqlparse@0.4.1 | python/api | CVE-2021-32839 |
| **paramiko@2.4.1** (via -r) | requirements-base.txt | CVE-2018-1000805 |
| lxml@4.6.2, numpy@1.19.0 (via -r) | requirements-base.txt | CVE-2021-28957; CVE-2021-41495 |
| idna@2.7, certifi@2019.11.28 (via -c) | requirements-constraints.txt | CVE-2024-3651; CVE-2022-23491 |
| pillow@8.1.0 | pipenv-svc | many (e.g. CVE-2021-25287) |
| cryptography@3.2 | pipenv-svc | CVE-2020-36242 |
| aiohttp@3.7.3 | pipenv-svc | CVE-2021-21330 |
| pyjwt@1.7.1 | pipenv-svc | CVE-2022-29217 |
| py@1.9.0 | pipenv-svc | CVE-2020-29651 |
| babel@2.8.0, black@19.10b0 | pipenv-svc (develop) | CVE-2021-42771; CVE-2024-21503 |
| fastapi@0.65.1 | poetry-svc | CVE-2021-32677 |
| pydantic@1.6.1 | poetry-svc | CVE-2021-29510 |
| sqlalchemy@1.3.0 | poetry-svc | CVE-2019-7164, CVE-2019-7548 |
| rsa@4.0 | poetry-svc | CVE-2020-13757 |
| httpx@0.22.0 | poetry-svc | CVE-2021-41945 |

### Maven
| Package@version | Where | Expected IDs |
|---|---|---|
| **org.apache.logging.log4j:log4j-core@2.14.1** | maven child (from parent mgmt) | CVE-2021-44228 (Log4Shell), CVE-2021-45046, CVE-2021-45105, CVE-2021-44832 |
| **com.fasterxml.jackson.core:jackson-databind@2.9.8** | maven child | many (e.g. CVE-2019-12384, CVE-2020-36518) |
| org.springframework:spring-core@5.2.0.RELEASE | maven child | CVE-2022-22965-family, CVE-2022-22950 |
| **commons-collections:commons-collections@3.2.1** | maven parent | CVE-2015-7501 |
| **org.apache.struts:struts2-core@2.3.20** | maven child (own property) | CVE-2017-5638 |
| com.thoughtworks.xstream:xstream@1.4.10 | maven child | CVE-2021-21344 + many |
| **org.apache.commons:commons-text@1.9** | maven child (optional) | CVE-2022-42889 (Text4Shell) |
| com.h2database:h2@1.4.197 | maven child (runtime) | CVE-2021-42392, CVE-2022-23221 |
| junit:junit@4.12 | maven child (test) | CVE-2020-15250 |
| org.yaml:snakeyaml@1.26 | gradle | CVE-2022-1471 |
| io.netty:netty-codec-http@4.1.42.Final | gradle | CVE-2019-20444, CVE-2019-20445, CVE-2021-21290 |
| com.google.guava:guava@29.0-jre | gradle | CVE-2020-8908, CVE-2023-2976 |
| org.bouncycastle:bcprov-jdk15on@1.65 | gradle (map notation) | CVE-2020-28052 |
| mysql:mysql-connector-java@8.0.16 | gradle | CVE-2019-2692 |
| com.google.protobuf:protobuf-java@3.6.1 | gradle.lockfile only | CVE-2021-22569 |
| org.apache.poi:poi-ooxml@4.1.0 | gradle kts | CVE-2019-12415 |
| org.jsoup:jsoup@1.13.1 | gradle kts | CVE-2021-37714 |
| com.squareup.okio:okio@1.15.0 | okhttp.lockfile | CVE-2023-3635 |

### Go
| Module@version | Expected IDs |
|---|---|
| github.com/gin-gonic/gin@v1.6.0 | CVE-2020-28483 |
| **github.com/dgrijalva/jwt-go@v3.2.0+incompatible** | CVE-2020-26160 |
| golang.org/x/text@v0.3.6 | CVE-2021-38561, CVE-2022-32149 |
| golang.org/x/crypto@v0.0.0-20200622… | CVE-2020-29652, CVE-2021-43565, CVE-2022-27191 |
| golang.org/x/net@v0.0.0-20200822… (indirect) | CVE-2021-33194 + others |
| gopkg.in/yaml.v2@v2.2.2 | CVE-2019-11254 |
| github.com/gorilla/websocket@v1.4.0 | CVE-2020-27813 |
| github.com/miekg/dns@v1.0.14 | CVE-2019-19794 |

### crates.io
| Crate@version | Expected IDs |
|---|---|
| hyper@0.14.9 | CVE-2021-32714, CVE-2021-32715 |
| regex@1.5.4 | CVE-2022-24713 |
| tokio@1.8.0 | CVE-2021-45710 |
| time@0.1.43 | CVE-2020-26235 |
| smallvec@1.6.0 | CVE-2021-25900 |
| nix@0.19.0 | CVE-2021-45707 |

### RubyGems
| Gem@version | Expected IDs |
|---|---|
| **actionpack@5.2.0 / rails@5.2.0** | CVE-2019-5418, CVE-2019-5419 + many |
| nokogiri@1.10.0 | CVE-2019-5477 + libxml2 advisories |
| rack@2.0.6 | CVE-2019-16782, CVE-2020-8184 |
| devise@4.6.0 | CVE-2019-16109 |
| loofah@2.2.2 | CVE-2018-16468 |
| rails-html-sanitizer@1.0.3 | CVE-2018-3741 |

### NuGet
| Package@version | Where | Expected IDs |
|---|---|---|
| Newtonsoft.Json@12.0.1 / 9.0.1 | Api / Legacy | CVE-2024-21907 |
| System.Text.Encodings.Web@4.5.0 | Api (central version) | CVE-2021-26701 |
| log4net@2.0.8 | Api | CVE-2018-1285 |
| SharpZipLib@1.2.0 | Api | CVE-2021-32840 |
| System.Data.SqlClient@4.8.0 | Analytics (central version) | CVE-2024-0056 |
| Portable.BouncyCastle@1.8.5 | Reports (.vbproj) | CVE-2020-15522 |
| Microsoft.Owin@4.0.0, DotNetZip@1.13.3, jQuery@1.7.1 | Legacy packages.config | CVE-2020-1045; CVE-2024-48510; jQuery XSS |
| MessagePack@2.1.80 | Worker project.assets.json | CVE-2020-5234 |
| System.Drawing.Common@4.7.0 | Worker project.assets.json | CVE-2021-24112 |

### Helm / Terraform
No vulnerability matches are expected. These check IaC component discovery only: providers `hashicorp/aws 3.74.0`, `hashicorp/kubernetes ~> 2.0`, `random 3.1.0`; modules `terraform-aws-modules/vpc/aws 2.78.0`, `…/eks/aws 17.1.0`; charts redis 10.5.7, postgresql 8.6.4 (locked) / ~8.6.0 (declared), nginx-ingress 1.41.3, mongodb 7.8.10.

## 3. Licences to look for (npm, web-frontend lockfile)
| Package | Licence | Policy expectation |
|---|---|---|
| gpl-widget-kit@1.0.0 | GPL-3.0-only | strong copyleft — flag |
| agpl-telemetry@2.1.0 | AGPL-3.0-or-later | network copyleft — flag |
| dual-licensed-util@3.0.0 | (MIT OR Apache-2.0) | SPDX expression — permissive |
| internal-private-sdk@0.0.1 | UNLICENSED | proprietary — flag/review |
| no-license-helper@1.2.3 | *(missing)* | unknown licence — review |

These five packages are fictional, so OSV and the registry won't know them. They should show up as components that registry enrichment can't resolve. Their licence comes only from the lockfile.

## 4. Other uploads (outside the main zip)
* `kagen-sbom-sca-edge-cases.zip`: zip-slip entries (`../`, `../../`, absolute path, `./`, backslash traversal), a directory-only entry and a hidden `node_modules`. **Expected:** only `edge/package.json` and `edge/package-lock.json` (`lodash@4.17.15`) are kept. `edge/./dot/Gemfile.lock` is dropped too, because the reader rejects any path with a `.` or `..` segment. Nothing named `zip-slip-parent`, `evil`, `abs` or `hidden-nm` appears.
* `extras/bom.cdx.json` (CycloneDX 1.5) and `extras/sbom.spdx.json` (SPDX 2.3): SBOM-document import, 8 components each with purls and licences. `bom.cdx.xml`, `sbom.spdx` (tag-value) and `sbom.spdx3.jsonld` should each be rejected with `discovery.sbom_unsupported`.
