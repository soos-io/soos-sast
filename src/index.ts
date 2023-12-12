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
import { exit } from "process";
import { SOOS_SAST_CONSTANTS } from "./constants";
import { version } from "../package.json";
import AnalysisService from "@soos-io/api-client/dist/services/AnalysisService";
import AnalysisArgumentParser from "@soos-io/api-client/dist/services/AnalysisArgumentParser";

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

class SOOSSASTAnalysis {
  constructor(private args: SOOSSASTAnalysisArgs) {}

  static parseArgs(): SOOSSASTAnalysisArgs {
    const analysisArgumentParser = AnalysisArgumentParser.create(ScanType.SAST, version);

    // TODO fix integration name/type - pass them in here
    analysisArgumentParser.addBaseScanArguments();

    // TODO wrap this method in AnalysisArgumentParser
    soosLogger.info("Parsing arguments");
    return analysisArgumentParser.argumentParser.parse_args();
  }

  async runAnalysis(): Promise<void> {
    const scanType = ScanType.SAST;

    // TODO file all files matching *.sarif.json from the workingDirectory
    const filePath = await this.findSASTFilePath();
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
        scriptVersion: version,
        contributingDeveloperAudit: [],
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

      const formData = await this.getSastAsFormData(filePath);

      await soosAnalysisService.analysisApiClient.uploadScanToolResult({
        clientId: this.args.clientId,
        projectHash,
        branchHash,
        scanType,
        scanId: analysisId,
        resultFile: formData,
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

  async getSastAsFormData(filePath: string): Promise<FormData> {
    try {
      const fileReadStream = FileSystem.createReadStream(filePath, {
        encoding: SOOS_CONSTANTS.FileUploads.Encoding,
      });

      const formData = new FormData();
      formData.append("file", fileReadStream);
      return formData;
    } catch (error) {
      soosLogger.error(`Error on getSastAsFormData: ${error}`);
      throw error;
    }
  }

  async findSASTFilePath(): Promise<string> {
    const sastPathStat = await FileSystem.statSync(this.args.sourceCodePath);

    if (sastPathStat.isDirectory()) {
      const files = await FileSystem.promises.readdir(this.args.sourceCodePath);
      const sastFile = files.find((file) => SOOS_SAST_CONSTANTS.FilePatternRegex.test(file));

      if (!sastFile) {
        throw new Error("No SAST file found in the directory.");
      }

      return Path.join(this.args.sourceCodePath, sastFile);
    }

    if (!SOOS_SAST_CONSTANTS.FilePatternRegex.test(this.args.sourceCodePath)) {
      throw new Error("The file does not match the required SAST pattern.");
    }

    return this.args.sourceCodePath;
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
