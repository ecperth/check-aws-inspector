import * as core from "@actions/core";
import { scan } from "./ecr";
import { findingSeverities, ScanFindings } from "./scanner";

try {
  const repository = core.getInput("repository");
  const tag = core.getInput("tag");
  const delay = +core.getInput("delay");
  const max_retries = +core.getInput("max_retries");
  const failSeverity = core.getInput("failSeverity");

  if (findingSeverities[failSeverity] == undefined) {
    throw new Error(`Invalid severity: ${failSeverity}`);
  }
  scan(repository, tag, delay, max_retries, failSeverity).then(
    (scanFindings: ScanFindings) => {
      core.setOutput(
        "findingSeverityCounts",
        scanFindings.findingSeverityCounts,
      );
      if (scanFindings.errorMessage) {
        core.setFailed(scanFindings.errorMessage);
      }
    },
  );
} catch (error: any) {
  core.setFailed(error.message);
}
