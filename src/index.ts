import * as core from "@actions/core";
import { getImageScanFindings } from "./ecr";
import { findingSeverities, ScanFindings } from "./scanner";
import { setTimeout } from "timers/promises";

const repository = core.getInput("repository");
const tag = core.getInput("tag");
const failSeverity = core.getInput("fail-severity");
const initialDelay = +core.getInput("initial-delay");
const retryDelay = +core.getInput("retry-delay");
const maxRetries = +core.getInput("max-retries");
const validationDelay = +core.getInput("validation-delay");

if (findingSeverities[failSeverity] == undefined) {
  core.setFailed(`Invalid severity: ${failSeverity}`);
} else {
  setTimeout(initialDelay).then(() => {
    getImageScanFindings(repository, tag, failSeverity, retryDelay, maxRetries, validationDelay)
      .then((scanFindings: ScanFindings) => {
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
}
