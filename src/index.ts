import * as core from "@actions/core";
import { scan } from "./ecr";
import { findingSeverities, ScanFindings } from "./scanner";
import { setTimeout } from "timers/promises";

const repository = core.getInput("repository");
const tag = core.getInput("tag");
const initialDelay = +core.getInput("initial-delay");
const retryDelay = +core.getInput("retry-delay");
const maxRetries = +core.getInput("max-retries");
const failSeverity = core.getInput("fail-severity");

if (findingSeverities[failSeverity] == undefined) {
  throw new Error(`Invalid severity: ${failSeverity}`);
}

setTimeout(initialDelay).then(() => {
  scan(repository, tag, retryDelay, maxRetries, failSeverity)
    .then((scanFindings: ScanFindings) => {
      console.log(scanFindings)
      core.setOutput(
        "findingSeverityCounts",
        scanFindings.findingSeverityCounts,
      );
      if (scanFindings.errorMessage) {
        core.setFailed(scanFindings.errorMessage);
      }
    })
    .catch((err) => core.setFailed(err.message));
});
