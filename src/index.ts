#!/usr/bin/env node
import {
  IntegrationName,
  IntegrationType,
  LogLevel,
  SOOS_CONSTANTS,
  ScanStatus,
  ScanType,
  soosLogger,
} from "@soos-io/api-client";
import { obfuscateProperties, ensureValue } from "@soos-io/api-client/dist/utilities";
import * as FileSystem from "fs";
import * as Path from "path";
import FormData from "form-data";
import * as Glob from "glob";
import { exit } from "process";
import { version } from "../package.json";
import AnalysisService from "@soos-io/api-client/dist/services/AnalysisService";
import AnalysisArgumentParser from "@soos-io/api-client/dist/services/AnalysisArgumentParser";
import StringUtilities from "@soos-io/api-client/dist/StringUtilities";
import { SOOS_SAST_CONSTANTS } from "./constants";

interface SOOSSASTAnalysisArgs {
  apiKey: string;
  apiURL: string;
  appVersion: string;
  branchName: string;
  branchUri: string;
  buildUri: string;
  buildVersion: string;
  clientId: string;
  commitHash: string;
  directoriesToExclude: Array<string>;
  filesToExclude: Array<string>;
  integrationName: IntegrationName;
  integrationType: IntegrationType;
  logLevel: LogLevel;
  operatingEnvironment: string;
  projectName: string;
  scriptVersion: string;
  sourceCodePath: string;
  verbose: boolean;
}

interface IAnalysisFile {
  name: string;
  path: string;
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
      help: "Listing of files or patterns patterns to exclude from the search for manifest files. eg: **/req**.txt/, **/requirements.txt",
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

    // TODO wrap this method in AnalysisArgumentParser
    soosLogger.info("Parsing arguments");
    return analysisArgumentParser.argumentParser.parse_args();
  }

  async runAnalysis(): Promise<void> {
    const scanType = ScanType.SAST;

    // TODO use hasMoreThanMaximumManifests
    const { files } = await this.findSASTFiles(this.args.sourceCodePath);
    if (files.length === 0) {
      throw new Error("No SAST files found.");
    }

    const soosAnalysisService = AnalysisService.create(this.args.apiKey, this.args.apiURL);

    let projectHash: string | undefined;
    let branchHash: string | undefined;
    let analysisId: string | undefined;

    try {
      soosLogger.info("Starting SOOS SAST Analysis");
      soosLogger.info(`Creating scan for project '${this.args.projectName}'...`);
      soosLogger.info(`Branch Name: ${this.args.branchName}`);

      const result = await soosAnalysisService.setupScan({
        clientId: this.args.clientId,
        projectName: this.args.projectName,
        commitHash: this.args.commitHash,
        branchName: this.args.branchName,
        buildVersion: this.args.buildVersion,
        buildUri: this.args.buildUri,
        branchUri: this.args.branchUri,
        integrationType: this.args.integrationType,
        operatingEnvironment: this.args.operatingEnvironment,
        integrationName: this.args.integrationName,
        appVersion: this.args.appVersion,
        scanType,
        scriptVersion: this.args.scriptVersion,
        contributingDeveloperAudit: [], // TODO audit
        toolName: undefined,
        toolVersion: undefined,
      });

      projectHash = result.projectHash;
      branchHash = result.branchHash;
      analysisId = result.analysisId;

      soosLogger.info(`Project Hash: ${projectHash}`);
      soosLogger.info(`Branch Hash: ${branchHash}`);
      soosLogger.info(`Scan Id: ${analysisId}`);
      soosLogger.info("Scan created successfully.");
      soosLogger.logLineSeparator();

      soosLogger.info("Uploading SAST Files");

      const formData = await this.getSastFilesAsFormData(files);

      await soosAnalysisService.analysisApiClient.uploadScanToolResult({
        clientId: this.args.clientId,
        projectHash,
        branchHash,
        scanType,
        scanId: analysisId,
        resultFile: formData,
        // TODO hasMoreThanMaximumManifests,
      });

      soosLogger.logLineSeparator();
      soosLogger.info(
        `Scan results uploaded successfully. To see the results visit: ${result.scanUrl}`,
      );
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
        });
      soosLogger.error(error);
      exit(1);
    }
  }

  // TODO move to api-client analysisService as a helper method
  async getSastFilesAsFormData(sastFiles: IAnalysisFile[]): Promise<FormData> {
    const formData = sastFiles.reduce((formDataAcc: FormData, sastFile, index) => {
      const workingDirectory = this.args.sourceCodePath;
      const fileParts = sastFile.path.replace(workingDirectory, "").split(Path.sep);
      const parentFolder =
        fileParts.length >= 2 ? fileParts.slice(0, fileParts.length - 1).join(Path.sep) : "";
      const suffix = index > 0 ? index : "";
      const fileReadStream = FileSystem.createReadStream(sastFile.path, {
        encoding: SOOS_CONSTANTS.FileUploads.Encoding,
      });
      formDataAcc.append(`file${suffix}`, fileReadStream);
      formDataAcc.append(`parentFolder${suffix}`, parentFolder);

      return formDataAcc;
    }, new FormData());

    return formData;
  }

  // TODO move to api-client analysisService as a helper method - generic file
  async findSASTFiles(
    path: string,
  ): Promise<{ files: Array<IAnalysisFile>; hasMoreThanMaximumManifests: boolean }> {
    // TODO use filesToExclude/directoriesToExclude
    soosLogger.info(`Searching for SAST files from ${path}...`);
    const pattern = `${path}/${SOOS_SAST_CONSTANTS.FilePattern}`;
    const files = Glob.sync(pattern, {
      nocase: true,
    });
    const matchingFiles = files
      .map((x) => Path.resolve(x))
      .map((f) => {
        return {
          name: Path.basename(f),
          path: f,
        };
      });

    soosLogger.info(`${matchingFiles.length} files found matching pattern '${pattern}'.`);

    const hasMoreThanMaximumManifests =
      matchingFiles.length > SOOS_CONSTANTS.FileUploads.MaxManifests;
    const filesToUpload = matchingFiles.slice(0, SOOS_CONSTANTS.FileUploads.MaxManifests);

    if (hasMoreThanMaximumManifests) {
      const filesToSkip = matchingFiles.slice(SOOS_CONSTANTS.FileUploads.MaxManifests);
      const filesDetectedString = StringUtilities.pluralizeTemplate(
        matchingFiles.length,
        "file was",
        "files were",
      );
      const filesSkippedString = StringUtilities.pluralizeTemplate(
        filesToSkip.length,
        "file",
        "files",
      );
      soosLogger.info(
        `The maximum number of SAST files per scan is ${SOOS_CONSTANTS.FileUploads.MaxManifests}. ${filesDetectedString} detected, and ${filesSkippedString} will be not be uploaded. \n`,
        `The following manifests will not be included in the scan: \n`,
        filesToSkip.map((file) => `  "${file.name}": "${file.path}"`).join("\n"),
      );
    }

    return { files: filesToUpload, hasMoreThanMaximumManifests };
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
      ensureValue(args.clientId, "clientId");
      ensureValue(args.apiKey, "apiKey");
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
