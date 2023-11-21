#!/usr/bin/env node
import { LogLevel, SOOS_CONSTANTS, ScanStatus, ScanType, soosLogger } from "@soos-io/api-client";
import {
  getEnvVariable,
  obfuscateProperties,
  ensureEnumValue,
  ensureValue,
} from "@soos-io/api-client/dist/utilities";
import { ArgumentParser } from "argparse";
import * as FileSystem from "fs";
import * as Path from "path";
import FormData from "form-data";
import { CONSTANTS } from "./utils/constants";
import { exit } from "process";
import SOOSAnalysisApiClient from "@soos-io/api-client/dist/api/SOOSAnalysisApiClient";

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
  integrationName: string;
  integrationType: string;
  logLevel: LogLevel;
  operatingEnvironment: string;
  projectName: string;
  scriptVersion: string;
  sastPath: string;
  verbose: boolean;
}

class SOOSSASTAnalysis {
  constructor(private args: SOOSSASTAnalysisArgs) {}

  static parseArgs(): SOOSSASTAnalysisArgs {
    const parser = new ArgumentParser({ description: "SOOS SAST" });

    parser.add_argument("--apiKey", {
      help: "SOOS API Key - get yours from https://app.soos.io/integrate/sast",
      default: getEnvVariable(CONSTANTS.SOOS.API_KEY_ENV_VAR),
      required: false,
    });

    parser.add_argument("--apiURL", {
      help: "SOOS API URL - Intended for internal use only, do not modify.",
      default: "https://api.soos.io/api/",
      required: false,
    });

    parser.add_argument("--appVersion", {
      help: "App Version - Intended for internal use only.",
      required: false,
    });

    parser.add_argument("--branchName", {
      help: "The name of the branch from the SCM System.",
      default: null,
      required: false,
    });

    parser.add_argument("--branchURI", {
      help: "The URI to the branch from the SCM System.",
      default: null,
      required: false,
    });

    parser.add_argument("--buildURI", {
      help: "URI to CI build info.",
      default: null,
      required: false,
    });

    parser.add_argument("--buildVersion", {
      help: "Version of application build artifacts.",
      default: null,
      required: false,
    });

    parser.add_argument("--clientId", {
      help: "SOOS Client ID - get yours from https://app.soos.io/integrate/sast",
      default: getEnvVariable(CONSTANTS.SOOS.CLIENT_ID_ENV_VAR),
      required: false,
    });

    parser.add_argument("--commitHash", {
      help: "The commit hash value from the SCM System.",
      default: null,
      required: false,
    });

    parser.add_argument("--integrationName", {
      help: "Integration Name - Intended for internal use only.",
      required: false,
    });

    parser.add_argument("--integrationType", {
      help: "Integration Type - Intended for internal use only.",
      required: false,
      default: CONSTANTS.SOOS.DEFAULT_INTEGRATION_TYPE,
    });

    parser.add_argument("--logLevel", {
      help: "Minimum level to show logs: PASS, IGNORE, INFO, WARN or FAIL.",
      default: LogLevel.INFO,
      required: false,
      type: (value: string) => {
        return ensureEnumValue(LogLevel, value);
      },
    });

    parser.add_argument("--operatingEnvironment", {
      help: "Set Operating environment for information purposes only.",
      default: null,
      required: false,
    });

    parser.add_argument("--projectName", {
      help: "Project Name - this is what will be displayed in the SOOS app.",
      required: true,
    });

    parser.add_argument("--scriptVersion", {
      help: "Script Version - Intended for internal use only.",
      required: false,
    });

    parser.add_argument("--verbose", {
      help: "Enable verbose logging.",
      action: "store_true",
      default: false,
      required: false,
    });

    parser.add_argument("sastPath", {
      help: "The SAST File to scan (*.sarif.json), it could be the location of the file or the file itself. When location is specified only the first file found will be scanned.",
    });

    soosLogger.info("Parsing arguments");
    return parser.parse_args();
  }

  async runAnalysis(): Promise<void> {
    let projectHash: string | undefined;
    let branchHash: string | undefined;
    let analysisId: string | undefined;
    const filePath = await this.findSASTFilePath();
    const soosAnalysisApiClient = new SOOSAnalysisApiClient(this.args.apiKey, this.args.apiURL);
    try {
      soosLogger.info("Starting SOOS SAST Analysis");
      soosLogger.info(`Creating scan for project '${this.args.projectName}'...`);
      soosLogger.info(`Branch Name: ${this.args.branchName}`);

      const result = await soosAnalysisApiClient.createScan({
        clientId: this.args.clientId,
        projectName: this.args.projectName,
        commitHash: this.args.commitHash,
        branch: this.args.branchName,
        buildVersion: this.args.buildVersion,
        buildUri: this.args.buildUri,
        branchUri: this.args.branchUri,
        integrationType: this.args.integrationType,
        operatingEnvironment: this.args.operatingEnvironment,
        integrationName: this.args.integrationName,
        appVersion: this.args.appVersion,
        scriptVersion: null,
        contributingDeveloperAudit: undefined,
        scanType: ScanType.SAST,
        toolName: null,
        toolVersion: null,
      });

      projectHash = result.projectHash;
      branchHash = result.branchHash;
      analysisId = result.analysisId;

      soosLogger.info(`Project Hash: ${projectHash}`);
      soosLogger.info(`Branch Hash: ${branchHash}`);
      soosLogger.info(`Scan Id: ${analysisId}`);
      soosLogger.info("Scan created successfully.");
      soosLogger.logLineSeparator();

      soosLogger.info("Uploading SAST File");

      const formData = await this.getSastAsFormData(filePath);

      await soosAnalysisApiClient.uploadScanToolResult({
        clientId: this.args.clientId,
        projectHash,
        branchHash,
        scanType: ScanType.SAST,
        scanId: analysisId,
        resultFile: formData,
      });

      soosLogger.info(`Scan result uploaded successfully`);

      soosLogger.logLineSeparator();
      soosLogger.info(
        `Analysis scan started successfully, to see the results visit: ${result.scanUrl}`
      );
    } catch (error) {
      if (projectHash && branchHash && analysisId)
        await soosAnalysisApiClient.updateScanStatus({
          clientId: this.args.clientId,
          projectHash,
          branchHash,
          scanType: ScanType.SAST,
          scanId: analysisId,
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
    const sastPathStat = await FileSystem.statSync(this.args.sastPath);

    if (sastPathStat.isDirectory()) {
      const files = await FileSystem.promises.readdir(this.args.sastPath);
      const sastFile = files.find((file) => CONSTANTS.SAST.FILE_REGEX.test(file));

      if (!sastFile) {
        throw new Error("No SAST file found in the directory.");
      }

      return Path.join(this.args.sastPath, sastFile);
    }

    if (!CONSTANTS.SAST.FILE_REGEX.test(this.args.sastPath)) {
      throw new Error("The file does not match the required SAST pattern.");
    }

    return this.args.sastPath;
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
          2
        )
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
