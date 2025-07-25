#!/usr/bin/env node
import {
  AttributionFileTypeEnum,
  AttributionFormatEnum,
  IntegrationName,
  IntegrationType,
  ScanStatus,
  ScanType,
  soosLogger,
} from "@soos-io/api-client";
import {
  obfuscateProperties,
  getAnalysisExitCodeWithMessage,
  isScanDone,
  obfuscateCommandLine,
  reassembleCommandLine,
} from "@soos-io/api-client/dist/utilities";
import { exit } from "process";
import { version } from "../package.json";
import AnalysisService from "@soos-io/api-client/dist/services/AnalysisService";
import AnalysisArgumentParser, {
  IBaseScanArguments,
} from "@soos-io/api-client/dist/services/AnalysisArgumentParser";
import { SOOS_SAST_CONSTANTS } from "./constants";

interface ISASTAnalysisArgs extends IBaseScanArguments {
  directoriesToExclude: Array<string>;
  filesToExclude: Array<string>;
  sourceCodePath: string;
  outputDirectory: string;
}

class SOOSSASTAnalysis {
  constructor(private args: ISASTAnalysisArgs) {}

  static parseArgs(): ISASTAnalysisArgs {
    const analysisArgumentParser = AnalysisArgumentParser.create(
      IntegrationName.SoosSast,
      IntegrationType.Script,
      ScanType.SAST,
      version,
    );

    analysisArgumentParser.addArgument(
      "directoriesToExclude",
      "Listing of directories or patterns to exclude from the search for manifest files. eg: **bin/start/**, **/start/**",
      {
        argParser: (value: string) => {
          return value.split(",").map((pattern) => pattern.trim());
        },
        defaultValue: [],
      },
    );

    analysisArgumentParser.addArgument(
      "filesToExclude",
      "Listing of files or patterns patterns to exclude from the search for manifest files. eg: **/sa**.sarif.json/, **/sast.sarif.json",
      {
        argParser: (value: string) => {
          return value.split(",").map((pattern) => pattern.trim());
        },
        defaultValue: [],
      },
    );

    analysisArgumentParser.addArgument(
      "sourceCodePath",
      "The path to start searching for SAST files.",
      {
        defaultValue: process.cwd(),
      },
    );

    analysisArgumentParser.addArgument(
      "outputDirectory",
      "Absolute path where SOOS will write exported reports and SBOMs. eg Correct: /out/sbom/ | Incorrect: ./out/sbom/",
      {
        defaultValue: process.cwd(),
      },
    );

    return analysisArgumentParser.parseArguments();
  }

  async runAnalysis(): Promise<void> {
    const scanType = ScanType.SAST;
    const soosAnalysisService = AnalysisService.create(this.args.apiKey, this.args.apiURL);

    let projectHash: string | undefined;
    let branchHash: string | undefined;
    let analysisId: string | undefined;
    let scanStatusUrl: string | undefined;
    let scanStatus: ScanStatus | undefined;

    try {
      const result = await soosAnalysisService.setupScan({
        clientId: this.args.clientId,
        projectName: this.args.projectName,
        commitHash: this.args.commitHash,
        contributingDeveloperAudit: [
          {
            contributingDeveloperId: this.args.contributingDeveloperId,
            source: this.args.contributingDeveloperSource,
            sourceName: this.args.contributingDeveloperSourceName,
          },
        ],
        branchName: this.args.branchName,
        buildVersion: this.args.buildVersion,
        buildUri: this.args.buildURI,
        branchUri: this.args.branchURI,
        integrationType: this.args.integrationType,
        operatingEnvironment: this.args.operatingEnvironment,
        integrationName: this.args.integrationName,
        appVersion: this.args.appVersion,
        scanType,
        scriptVersion: this.args.scriptVersion,
        commandLine:
          process.argv.length > 2
            ? obfuscateCommandLine(
                reassembleCommandLine(process.argv.slice(2)),
                SOOS_SAST_CONSTANTS.ObfuscatedArguments.map((a) => `--${a}`),
              )
            : null,
      });

      projectHash = result.projectHash;
      branchHash = result.branchHash;
      analysisId = result.analysisId;
      scanStatusUrl = result.scanStatusUrl;

      const { filePaths, hasMoreThanMaximumFiles } = await soosAnalysisService.findAnalysisFiles(
        scanType,
        this.args.sourceCodePath,
        SOOS_SAST_CONSTANTS.FilePattern,
        this.args.filesToExclude,
        this.args.directoriesToExclude,
        SOOS_SAST_CONSTANTS.MaxFiles,
      );
      if (filePaths.length === 0) {
        const noFilesMessage = `No SAST input files found. Please ensure you have generated Sarif JSON files before running soos-sast. They need to match the pattern ${SOOS_SAST_CONSTANTS.FilePattern}. See https://kb.soos.io/getting-started-with-sast-secrets for more information.`;
        await soosAnalysisService.updateScanStatus({
          analysisId,
          clientId: this.args.clientId,
          projectHash,
          branchHash,
          scanType,
          status: ScanStatus.NoFiles,
          message: noFilesMessage,
          scanStatusUrl,
        });
        soosLogger.error(noFilesMessage);
        soosLogger.always(`${noFilesMessage} - exit 1`);
        exit(1);
      }

      soosLogger.info("Uploading SAST File(s)...");
      const formData = await soosAnalysisService.getAnalysisFilesAsFormData(
        filePaths,
        this.args.sourceCodePath,
        true,
      );
      await soosAnalysisService.analysisApiClient.uploadScanToolResult({
        clientId: this.args.clientId,
        projectHash,
        branchHash,
        scanType,
        scanId: analysisId,
        resultFile: formData,
        hasMoreThanMaximumFiles,
      });

      soosLogger.info("Scan results uploaded successfully.");

      scanStatus = await soosAnalysisService.waitForScanToFinish({
        scanStatusUrl,
        scanUrl: result.scanUrl,
        scanType,
      });

      if (
        isScanDone(scanStatus) &&
        this.args.exportFormat !== AttributionFormatEnum.Unknown &&
        this.args.exportFileType !== AttributionFileTypeEnum.Unknown
      ) {
        await soosAnalysisService.generateFormattedOutput({
          clientId: this.args.clientId,
          projectHash: result.projectHash,
          projectName: this.args.projectName,
          branchHash: result.branchHash,
          analysisId: result.analysisId,
          format: this.args.exportFormat,
          fileType: this.args.exportFileType,
          includeDependentProjects: false,
          includeOriginalSbom: false,
          includeVulnerabilities: false,
          workingDirectory: this.args.outputDirectory,
        });
      }

      const exitCodeWithMessage = getAnalysisExitCodeWithMessage(
        scanStatus,
        this.args.integrationName,
        this.args.onFailure,
      );
      soosLogger.always(`${exitCodeWithMessage.message} - exit ${exitCodeWithMessage.exitCode}`);
      exit(exitCodeWithMessage.exitCode);
    } catch (error) {
      if (projectHash && branchHash && analysisId && (!scanStatus || !isScanDone(scanStatus)))
        await soosAnalysisService.updateScanStatus({
          analysisId,
          clientId: this.args.clientId,
          projectHash,
          branchHash,
          scanType,
          status: ScanStatus.Error,
          message: `Error while performing scan.`,
          scanStatusUrl,
        });
      soosLogger.error(error);
      soosLogger.always(`${error} - exit 1`);
      exit(1);
    }
  }

  static async createAndRun(): Promise<void> {
    try {
      const args = this.parseArgs();
      soosLogger.setMinLogLevel(args.logLevel);
      soosLogger.always("Starting SOOS SAST Analysis");
      soosLogger.debug(
        JSON.stringify(
          obfuscateProperties(args as unknown as Record<string, unknown>, ["apiKey"]),
          null,
          2,
        ),
      );

      const soosSASTAnalysis = new SOOSSASTAnalysis(args);
      await soosSASTAnalysis.runAnalysis();
    } catch (error) {
      soosLogger.error(`Error on createAndRun: ${error}`);
      soosLogger.always(`Error on createAndRun: ${error} - exit 1`);
      exit(1);
    }
  }
}

SOOSSASTAnalysis.createAndRun();
