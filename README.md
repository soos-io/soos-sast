# [SOOS SAST](https://soos.io/products/sast)

SOOS is an independent software security company, located in Winooski, VT USA, building security software for your team. [SOOS, Software security, simplified](https://soos.io).

Use SOOS to scan your software for [vulnerabilities](https://app.soos.io/research/vulnerabilities) and [open source license](https://app.soos.io/research/licenses) issues with [SOOS Core SCA](https://soos.io/products/sca). [Generate and ingest SBOMs](https://soos.io/products/sbom-manager). [Export reports](https://kb.soos.io/project-exports-and-reports) to industry standards. Govern your open source dependencies. Run the [SOOS DAST vulnerability scanner](https://soos.io/products/dast) against your web apps or APIs. [Scan your Docker containers](https://soos.io/products/containers) for vulnerabilities. Check your source code for issues with [SAST Analysis](https://soos.io/products/sast).

[Demo SOOS](https://app.soos.io/demo) or [Register for a Free Trial](https://app.soos.io/register).

If you maintain an Open Source project, sign up for the Free as in Beer [SOOS Community Edition](https://soos.io/products/community-edition).

## SOOS Badge Status
[![Dependency Vulnerabilities](https://img.shields.io/endpoint?url=https%3A%2F%2Fapi-hooks.soos.io%2Fapi%2Fshieldsio-badges%3FbadgeType%3DDependencyVulnerabilities%26pid%3Dysq9tf5jn%26)](https://app.soos.io)
[![Out Of Date Dependencies](https://img.shields.io/endpoint?url=https%3A%2F%2Fapi-hooks.soos.io%2Fapi%2Fshieldsio-badges%3FbadgeType%3DOutOfDateDependencies%26pid%3Dysq9tf5jn%26)](https://app.soos.io)

## Requirements
  - [npm](https://docs.npmjs.com/downloading-and-installing-node-js-and-npm)
  
## Installation

### Globally
run `npm i -g @soos-io/soos-sast@latest`

Then Run `soos-sast` from any terminal and add the parameters you want.

### Locally
run `npm install --prefix ./soos @soos-io/soos-sast`

Then run from the same terminal `node ./soos/node_modules/@soos-io/soos-sast/bin/index.js`

## Client Parameters


| Argument                 | Default                             | Description                                                                                                                          |
| ------------------------ | ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `--apiKey`               |                                     | SOOS API Key - get yours from [SOOS Integration](https://app.soos.io/integrate/sast). Uses `SOOS_API_KEY` env value if present.      |
| `--branchName`           |                                     | The name of the branch from the SCM System.                                                                                          |
| `--branchURI`            |                                     | The URI to the branch from the SCM System.                                                                                           |
| `--buildURI`             |                                     | URI to CI build info.                                                                                                                |
| `--buildVersion`         |                                     | Version of application build artifacts.                                                                                              |
| `--clientId`             |  | SOOS Client ID - get yours from [SOOS Integration](https://app.soos.io/integrate/sast). Uses `SOOS_API_CLIENT` env value if present.                                        |
| `--commitHash`           |                                     | The commit hash value from the SCM System.                                                                                           |
| `--directoriesToExclude` | `**/node_modules/**, "**/bin/**", "**/obj/**", "**/lib/**` | Listing of directories or patterns to exclude from the search for manifest files. eg: **bin/start/**, **/start/**   |
| `--exportFormat`         |  | Write the scan result to this file format. Options: CsafVex, CycloneDx, Sarif, Spdx, SoosIssues, SoosLicenses, SoosPackages, SoosVulnerabilities |
| `--exportFileType`       |  | Write the scan result to this file type (when used with exportFormat). Options: Csv, Html, Json, Text, Xml                                       |
| `--filesToExclude`       |                                     | Listing of files or patterns to exclude from the search for manifest files. eg: **/req**.txt/, **/requirements.txt                   |
| `--logLevel`             |                                     | Minimum level to show logs: DEBUG, INFO, WARN, FAIL, ERROR. |
| `--onFailure`            | `continue_on_failure`               | Action to perform when the scan fails. Options: fail_the_build, continue_on_failure.                                                 |
| `--operatingEnvironment` |                                     | Set Operating environment for information purposes only.                                                                             |
| `--projectName`          |                                     | Project Name - this is what will be displayed in the SOOS app.                                                                       |
| `--sourceCodePath`       | `process.cwd()`                     | Root path to begin recursive search for Sarif files.                                                                                 |
