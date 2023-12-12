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

interface ISastFile {
  name: string;
  path: string;
}

class SOOSSASTAnalysis {
  constructor(private args: SOOSSASTAnalysisArgs) {}

  static parseArgs(): SOOSSASTAnalysisArgs {
    const analysisArgumentParser = AnalysisArgumentParser.create(ScanType.SAST);

    analysisArgumentParser.addBaseScanArguments(IntegrationName.SoosSast, IntegrationType.Script, version);

    analysisArgumentParser.argumentParser.add_argument("--sourceCodePath", {
      help: "The path to start searching for SAST files.",
      required: false,
      default: process.cwd()
    });

    // TODO wrap this method in AnalysisArgumentParser
    soosLogger.info("Parsing arguments");
    return analysisArgumentParser.argumentParser.parse_args();
  }

  async runAnalysis(): Promise<void> {
    const scanType = ScanType.SAST;

    
    const sastFiles = await this.findSASTFiles();
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

      const formData = await this.getSastFilesAsFormData(sastFiles);

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

  async getSastFilesAsFormData(sastFiles: ISastFile[]): Promise<FormData> {
    const formData = sastFiles.reduce((formDataAcc: FormData, sastFile, index) => {
      const workingDirectory = this.args.sourceCodePath;
      const fileParts = sastFile.path.replace(workingDirectory, "").split(Path.sep);
      const parentFolder =
      fileParts.length >= 2
          ? fileParts.slice(0, fileParts.length - 1).join(Path.sep)
          : "";
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

  async findSASTFiles(): Promise<Array<ISastFile>> {
      soosLogger.info("Searching for SAST files");
      process.chdir(this.args.sourceCodePath);
      const pattern = SOOS_SAST_CONSTANTS.FilePattern;
      const files = Glob.sync(pattern, {
        nocase: true,
      });

      const absolutePathFiles = files.map((x) => Path.resolve(x));

      const matchingFilesMessage = `${absolutePathFiles.length} files found matching pattern '${pattern}'.`

      if (absolutePathFiles.length > 0) {
        soosLogger.info(matchingFilesMessage);
      }else{
        throw new Error("No SAST files found.");
      }
    

    return absolutePathFiles.map((f) => {
      return {
        name: Path.basename(f),
        path: f,
      };
    });
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
