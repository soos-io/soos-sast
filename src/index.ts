#!/usr/bin/env node
import {
  IntegrationName,
  IntegrationType,
  LogLevel,
  OnFailure,
  ScanStatus,
  ScanType,
  soosLogger,
} from "@soos-io/api-client";
import {
  obfuscateProperties,
  ensureNonEmptyValue,
  ensureEnumValue,
  getAnalysisExitCode,
} from "@soos-io/api-client/dist/utilities";
import { exit } from "process";
import { version } from "../package.json";
import AnalysisService from "@soos-io/api-client/dist/services/AnalysisService";
import AnalysisArgumentParser, {
  IBaseScanArguments,
} from "@soos-io/api-client/dist/services/AnalysisArgumentParser";
import { SOOS_SAST_CONSTANTS } from "./constants";

interface SOOSSASTAnalysisArgs extends IBaseScanArguments {
  directoriesToExclude: Array<string>;
  filesToExclude: Array<string>;
  sourceCodePath: string;
}

class SOOSSASTAnalysis {
  constructor(private args: SOOSSASTAnalysisArgs) {}

  static parseArgs(): SOOSSASTAnalysisArgs {
    const analysisArgumentParser = AnalysisArgumentParser.create(ScanType.SAST);

    analysisArgumentParser.addBaseScanArguments(
      IntegrationName.SoosSast,
      IntegrationType.Script,
      version,
    );

    analysisArgumentParser.argumentParser.add_argument("--directoriesToExclude", {
      help: "Listing of directories or patterns to exclude from the search for manifest files. eg: **bin/start/**, **/start/**",
      type: (value: string) => {
        return value.split(",").map((pattern) => pattern.trim());
      },
      required: false,
    });

    analysisArgumentParser.argumentParser.add_argument("--filesToExclude", {
      help: "Listing of files or patterns patterns to exclude from the search for manifest files. eg: **/sa**.sarif.json/, **/sast.sarif.json",
      type: (value: string) => {
        return value.split(",").map((pattern) => pattern.trim());
      },
      required: false,
    });

    analysisArgumentParser.argumentParser.add_argument("--sourceCodePath", {
      help: "The path to start searching for SAST files.",
      required: false,
      default: process.cwd(),
    });

    soosLogger.info("Parsing arguments");
    return analysisArgumentParser.parseArguments();
  }

  async runAnalysis(): Promise<void> {
    const scanType = ScanType.SAST;
    const soosAnalysisService = AnalysisService.create(this.args.apiKey, this.args.apiURL);

    let projectHash: string | undefined;
    let branchHash: string | undefined;
    let analysisId: string | undefined;
    let scanStatusUrl: string | undefined;

    try {
      const { filePaths, hasMoreThanMaximumFiles } = await soosAnalysisService.findAnalysisFiles(
        scanType,
        this.args.sourceCodePath,
        SOOS_SAST_CONSTANTS.FilePattern,
        this.args.filesToExclude,
        this.args.directoriesToExclude,
        SOOS_SAST_CONSTANTS.MaxFiles,
      );

      if (filePaths.length === 0) {
        throw new Error("No SAST files found.");
      }

      soosLogger.info("Starting SOOS SAST Analysis");
      soosLogger.info(`Creating scan for project '${this.args.projectName}'...`);
      soosLogger.info(`Branch Name: ${this.args.branchName}`);

      const result = await soosAnalysisService.setupScan({
        clientId: this.args.clientId,
        projectName: this.args.projectName,
        commitHash: this.args.commitHash,
        contributingDeveloperAudit:
          !this.args.contributingDeveloperId ||
          !this.args.contributingDeveloperSource ||
          !this.args.contributingDeveloperSourceName
            ? []
            : [
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
        toolName: undefined,
        toolVersion: undefined,
      });

      projectHash = result.projectHash;
      branchHash = result.branchHash;
      analysisId = result.analysisId;
      scanStatusUrl = result.scanStatusUrl;

      soosLogger.info(`Project Hash: ${projectHash}`);
      soosLogger.info(`Branch Hash: ${branchHash}`);
      soosLogger.info(`Scan Id: ${analysisId}`);
      soosLogger.info("Scan created successfully.");
      soosLogger.logLineSeparator();

      soosLogger.info("Uploading SAST Files");

      const formData = await soosAnalysisService.getAnalysisFilesAsFormData(
        filePaths,
        this.args.sourceCodePath,
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

      soosLogger.logLineSeparator();
      soosLogger.info("Scan results uploaded successfully.");

      const scanStatus = await soosAnalysisService.waitForScanToFinish({
        scanStatusUrl,
        scanUrl: result.scanUrl,
        scanType,
      });

      const exitCode = getAnalysisExitCode(
        scanStatus,
        this.args.integrationName,
        this.args.onFailure,
      );
      soosLogger.debug(`Exiting with code ${exitCode}`);
      exit(exitCode);
    } catch (error) {
      if (projectHash && branchHash && analysisId)
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
      exit(1);
    }
  }

  static async createAndRun(): Promise<void> {
    soosLogger.info("Starting SOOS SAST Analysis");
    soosLogger.logLineSeparator();
    try {
      const args = this.parseArgs();
      soosLogger.setMinLogLevel(args.logLevel);
      soosLogger.setVerbose(args.verbose);
      soosLogger.info("Configuration read");
      soosLogger.verboseDebug(
        JSON.stringify(
          obfuscateProperties(args as unknown as Record<string, unknown>, ["apiKey"]),
          null,
          2,
        ),
      );
      soosLogger.logLineSeparator();
      const soosSASTAnalysis = new SOOSSASTAnalysis(args);
      await soosSASTAnalysis.runAnalysis();
    } catch (error) {
      soosLogger.error(`Error on createAndRun: ${error}`);
      exit(1);
    }
  }
}

SOOSSASTAnalysis.createAndRun();
