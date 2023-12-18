# [SOOS SAST](https://soos.io/products/sast)

SOOS is an independent software security company, located in Winooski, VT USA, building security software for your team. [SOOS, Software security, simplified](https://soos.io).

Use SOOS to scan your software for [vulnerabilities](https://app.soos.io/research/vulnerabilities) and [open source license](https://app.soos.io/research/licenses) issues with [SOOS Core SCA](https://soos.io/products/sca). [Generate SBOMs](https://kb.soos.io/help/generating-a-software-bill-of-materials-sbom). Govern your open source dependencies. Run the [SOOS DAST vulnerability scanner](https://soos.io/products/dast) against your web apps or APIs.

[Demo SOOS](https://app.soos.io/demo) or [Register for a Free Trial](https://app.soos.io/register).

If you maintain an Open Source project, sign up for the Free as in Beer [SOOS Community Edition](https://soos.io/products/community-edition).

## Requirements
  - [npm](https://docs.npmjs.com/downloading-and-installing-node-js-and-npm)
  
## Installation

### Globally
run `npm i -g @soos-io/soos-sast@latest`

Then Run `soos-sast` from any terminal and add the parameters you want.

### Locally
run `npm install --prefix ./soos @soos-io/soos-sast`

Then run from the same terminal `node ./soos/node_modules/@soos-io/soos-sast/bin/index.js`

## Parameters


| Argument                 | Default                                   | Description                                                                                                                          |
| ------------------------ | ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `--apiKey`               | N/A | SOOS API Key - get yours from [SOOS Integration](https://app.soos.io/integrate/sast). Uses `SOOS_API_KEY` env value if present.                                            |
| `--apiURL`               | N/A                                       | SOOS API URL - Intended for internal use only, do not modify.                                                                        |
| `--appVersion`           | N/A                                       | App Version - Intended for internal use only.                                                                                        |
| `--branchName`           | `null`                                    | The name of the branch from the SCM System.                                                                                          |
| `--branchURI`            | `null`                                    | The URI to the branch from the SCM System.                                                                                           |
| `--buildURI`             | `null`                                    | URI to CI build info.                                                                                                                |
| `--buildVersion`         | `null`                                    | Version of application build artifacts.                                                                                              |
| `--clientId`             | N/A | SOOS Client ID - get yours from [SOOS Integration](https://app.soos.io/integrate/sast). Uses `SOOS_API_CLIENT` env vaue if present.                                        |
| `--commitHash`           | `null`                                    | The commit hash value from the SCM System.                                                                                           |
| `--directoriesToExclude` | `**/node_modules/**, "**/bin/**", "**/obj/**", "**/lib/**` | Listing of directories or patterns to exclude from the search for manifest files. eg: **bin/start/**, **/start/**   |
| `--filesToExclude`       | None                                      | Listing of files or patterns to exclude from the search for manifest files. eg: **/req**.txt/, **/requirements.txt                   |
| `--integrationName`      | N/A                                       | Integration Name - Intended for internal use only.                                                                                   |
| `--integrationType`      | N/A                                       | Integration Type - Intended for internal use only.                                                                                   |
| `--logLevel`             | `INFO`                                    | Minimum level to show logs: PASS, IGNORE, INFO, WARN or FAIL.                                                                        |
| `--onFailure`            | `continue_on_failure`                     | Action to perform when the scan fails. Options: fail_the_build, continue_on_failure.                                                 |
| `--operatingEnvironment` | `null`                                    | Set Operating environment for information purposes only.                                                                             |
| `--projectName`          | N/A                                       | Project Name - this is what will be displayed in the SOOS app.                                                                       |
| `--scriptVersion`        | N/A                                       | Script Version - Intended for internal use only.                                                                                     |
| `--sourceCodePath`       | `process.cwd()`                           | Root path to begin recursive search for Sarif files.                                                                                 |
| `--verbose`              | `false`                                   | Enable verbose logging.                                                                                                              |
