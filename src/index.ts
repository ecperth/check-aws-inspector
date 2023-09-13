import * as core from '@actions/core';
import { getImageScanFindings } from './ecr';
import { findingSeverities, ScanFindings } from './scanner';

const repository = core.getInput('repository', { required: true });
const tag = core.getInput('tag', { required: true });
const failOn = core.getInput('fail-on');
const ignore = core.getInput('ignore');
const maxRetries = core.getInput('max-retries', { required: true });
const delay = core.getInput('delay', { required: true });
const consistencyDelay = core.getInput('consistency-delay', { required: true });

const ignoreList = '' ? [] : ignore.trim().replace(/\n|\s/g, ',').split(',');

if (validateInput(failOn, maxRetries, delay, consistencyDelay)) {
  getImageScanFindings(
    repository,
    tag,
    failOn,
    ignoreList,
    +delay,
    +maxRetries,
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
  maxRetries: string,
  delay: string,
  consistencyDelay: string,
): boolean {
  if (findingSeverities[failOn] == undefined) {
    core.setFailed(`Invalid failOn: ${failOn}`);
    return false;
  } else if (isNaN(+maxRetries) || !Number.isInteger(+maxRetries)) {
    core.setFailed(`Invalid maxRetries: ${maxRetries}. Must be an integer`);
    return false;
  } else if (isNaN(+delay) || !Number.isInteger(+delay)) {
    core.setFailed(`Invalid delay: ${delay}. Must be an integer`);
    return false;
  } else if (isNaN(+consistencyDelay) || !Number.isInteger(+consistencyDelay)) {
    core.setFailed(
      `Invalid consistencyDelay: ${consistencyDelay}. Must be an integer`,
    );
    return false;
  }
  return true;
}
