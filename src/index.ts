import * as core from "@actions/core";
import { getImageScanFindings } from "./ecr";
import { findingSeverities, ScanFindings } from "./scanner";
import { setTimeout } from "timers/promises";

const repository = core.getInput("repository");
const tag = core.getInput("tag");
const failOn = core.getInput("fail-on");
const initialDelay = +core.getInput("initial-delay");
const retryDelay = +core.getInput("retry-delay");
const maxRetries = +core.getInput("max-retries");
const validationDelay = +core.getInput("validation-delay");

if (findingSeverities[failOn] == undefined) {
  core.setFailed(`Invalid severity: ${failOn}`);
} else {
  setTimeout(initialDelay).then(() => {
    getImageScanFindings(repository, tag, failOn, retryDelay, maxRetries, validationDelay)
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
