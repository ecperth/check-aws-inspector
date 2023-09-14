import * as core from '@actions/core';
import { getImageScanFindings } from './ecr';
import { findingSeverities, ScanFindings } from './scanner';

const repository = core.getInput('repository', { required: true }).trim();
const tag = core.getInput('tag', { required: true }).trim();
const failOn = core.getInput('fail-on').trim().toUpperCase();
const ignore = core.getInput('ignore').trim();
const timeout = core.getInput('timeout', { required: true }).trim();
const consistencyDelay = core
  .getInput('consistency-delay', { required: true })
  .trim();

const ignoreList = '' ? [] : ignore.replace(/\n|\s/g, ',').split(',');

if (validateInput(failOn, timeout, consistencyDelay)) {
  getImageScanFindings(
    repository,
    tag,
    failOn,
    ignoreList,
    +timeout,
    +consistencyDelay,
  )
    .then((scanFindings: ScanFindings) => {
      core.setOutput(
        'findingSeverityCounts',
        scanFindings.findingSeverityCounts,
      );
      if (scanFindings.errorMessage) {
        core.setFailed(scanFindings.errorMessage);
      }
    })
    .catch((err) => core.setFailed(err.message));
}

function validateInput(
  failOn: string,
  timeout: string,
  consistencyDelay: string,
): boolean {
  if (findingSeverities[failOn] == undefined) {
    core.setFailed(`Invalid fail-on: ${failOn}`);
    return false;
  } else if (isNaN(+timeout) || !Number.isInteger(+timeout)) {
    core.setFailed(`Invalid timeout: ${timeout}. Must be an integer`);
    return false;
  } else if (isNaN(+consistencyDelay) || !Number.isInteger(+consistencyDelay)) {
    core.setFailed(
      `Invalid consistency-delay: ${consistencyDelay}. Must be an integer`,
    );
    return false;
  }
  return true;
}
