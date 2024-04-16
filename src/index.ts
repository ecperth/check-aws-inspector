import * as core from '@actions/core';
import { getImageScanFindings } from './ecr';
import { ScanFindings, findingSeverities } from './scanner';
const POLL_RATE = 5;

run();
export async function run() {
  const repositoryInput = core.getInput('repository', { trimWhitespace: true });
  const registryIdInput = core.getInput('registry-id', {
    trimWhitespace: true,
  });
  const imageTag = core.getInput('tag', { trimWhitespace: true });
  const imageDigest = core.getInput('image-digest', { trimWhitespace: true });

  const failOnInput = core
    .getInput('fail-on', { trimWhitespace: true })
    .toUpperCase();
  const ignoreInput = core.getInput('ignore', { trimWhitespace: true });
  const timeoutInput = core.getInput('timeout', { trimWhitespace: true });
  const consistencyDelayInput = core.getInput('consistency-delay', {
    trimWhitespace: true,
  });

  const ignoreList = splitIgnoreList(ignoreInput);
  const failOn = failOnInput === '' ? undefined : failOnInput;
  const registryId = registryIdInput === '' ? undefined : registryIdInput;

  if (validateInput(registryId, failOn, timeoutInput, consistencyDelayInput)) {
    try {
      const scanFindings: ScanFindings = await getImageScanFindings(
        repositoryInput,
        registryId,
        { imageTag, imageDigest },
        ignoreList,
        +timeoutInput,
        POLL_RATE,
        +consistencyDelayInput,
        failOn,
      );
      core.setOutput(
        'findingSeverityCounts',
        scanFindings.findingSeverityCounts,
      );
      if (scanFindings.errorMessage) {
        core.setFailed(scanFindings.errorMessage);
      }
    } catch (err) {
      if (err instanceof Error) {
        core.setFailed(err.message);
      }
    }
  }
}

function validateInput(
  registryId: string | undefined,
  failOn: string | undefined,
  timeout: string,
  consistencyDelay: string,
): boolean {
  if (registryId != undefined && !/^\d{12}$/.test(registryId)) {
    core.setFailed(
      `Invalid registry-id: ${registryId}. Must be 12 digit number`,
    );
    return false;
  } else if (failOn != undefined && findingSeverities[failOn] == undefined) {
    core.setFailed(`Invalid fail-on: ${failOn}`);
    return false;
  } else if (!isStringPositiveInteger(timeout)) {
    core.setFailed(`Invalid timeout: ${timeout}. Must be a positive integer`);
    return false;
  } else if (!isStringPositiveInteger(consistencyDelay)) {
    core.setFailed(
      `Invalid consistency-delay: ${consistencyDelay}. Must be a positive integer`,
    );
    return false;
  }
  return true;
}

function isStringPositiveInteger(input: string) {
  return !isNaN(+input) && Number.isInteger(+input) && +input >= 0;
}

export function splitIgnoreList(ignore: string) {
  return ignore === ''
    ? []
    : ignore
        .trim()
        .replace(/\n+|\s+/g, ',')
        .replace(/,+/g, ',')
        .split(',')
        .map((cv) => cv.trim());
}
