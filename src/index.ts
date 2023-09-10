import * as core from "@actions/core";
import { scan } from "./ecr";
import { findingSeverities } from "./scanner";

try {
  const repository = core.getInput("repository");
  const tag = core.getInput("tag");
  const delay = +core.getInput("delay");
  const timeout = +core.getInput("timeout");
  const failSeverity = core.getInput("failSeverity");

  if (!findingSeverities.includes(failSeverity)) {
    throw new Error(`Invalid severity: ${failSeverity}`);
  }

  core.setOutput("image", repository + ":" + tag);
  scan(repository, tag, delay, timeout, failSeverity);
} catch (error: any) {
  core.setFailed(error.message);
}
