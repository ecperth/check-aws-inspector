import * as core from '@actions/core';
import {
  ECRClient,
  DescribeImageScanFindingsCommand,
  FindingSeverity,
  ScanNotFoundException,
  ImageNotFoundException,
  ImageIdentifier,
} from '@aws-sdk/client-ecr';
import { findingSeverities, ScanFindings } from './scanner';
import { setTimeout } from 'timers/promises';

const client = new ECRClient();
/**
 * @param {string} repository - ECR repo name
 * @param {string | undefined} registryId - ECR registry ID
 * @param {ImageIdentifier} imageIdentifier - image identifier
 * @param {string[]} ignore - VulnerabilityIds to ignore
 * @param {number} timeout - Time in seconds for scan to complete before failure
 * @param {number} pollRate - Time in seconds between polls complete scan status
 * @param {number} consistencyDelay - Time in seconds between polls for consistency
 * @param {string} [failOn] - Severity to cause failure
 * @returns {Promise<ScanFindings>}
 */
export async function getImageScanFindings(
  repository: string,
  registryId: string | undefined,
  imageIdentifier: ImageIdentifier,
  ignore: string[],
  timeout: number,
  pollRate: number,
  consistencyDelay: number,
  failOn?: string,
): Promise<ScanFindings> {
  const command = new DescribeImageScanFindingsCommand({
    repositoryName: repository,
    registryId: registryId,
    imageId: imageIdentifier,
  });

  // Poll with delay untill we get 'COMPLETE' status.
  try {
    await pollForScanCompletion(command, pollRate * 1000, timeout);
  } catch (err) {
    if (err instanceof Error) {
      return { errorMessage: err.message };
    }
  }

  // Poll with consistencyDelay untill we get consistent data
  const findingSeverityCounts = await pollForConsistency(
    command,
    consistencyDelay * 1000,
  );
  // No findings
  if (Object.keys(findingSeverityCounts).length === 0) {
    return { findingSeverityCounts: {} };
  }
  // No vulnerability > failOn or failOn not provided
  if (
    !failOn ||
    !doesContainFailOnVulnerabilty(findingSeverityCounts, failOn)
  ) {
    return { findingSeverityCounts: findingSeverityCounts };
  }
  // Vulnerability > failOn found and no ignores provided
  if (ignore.length === 0) {
    return {
      findingSeverityCounts: findingSeverityCounts!,
      errorMessage: `Found vulnerabilty with severity of ${failOn} or greater.`,
    };
  }
  // Vulnerability > failOn found after excluded ignores
  if (
    await doesContainNotIgnoredFailOnVulnerabilty(
      command,
      { ...findingSeverityCounts },
      failOn,
      [...ignore],
    )
  ) {
    return {
      findingSeverityCounts: findingSeverityCounts,
      errorMessage: `Found vulnerabilty with severity of ${failOn} or greater.`,
    };
  }
  // Excluding ignores no Vulnerability failOn
  return {
    findingSeverityCounts: findingSeverityCounts,
  };
}

/**
 * Continues to send the provided command untill getting a 'COMPLETE' status
 * or timeout is reached.
 */
async function pollForScanCompletion(
  command: DescribeImageScanFindingsCommand,
  delay: number,
  timeout: number,
) {
  const timeoutMs = Date.now() + timeout * 1000;
  do {
    try {
      core.info(`Polling for complete scan...`);
      const resp = await client.send(command);
      if (resp.imageScanStatus?.status === 'COMPLETE') {
        core.info(`Scan complete!`);
        return;
      } else if (resp.imageScanStatus?.status === 'PENDING') {
        core.info(`Scan status is "Pending"`);
      } else if (resp.imageScanStatus?.status === 'IN_PROGRESS') {
        core.info(`Scan status is "In Progress"`);
      } else {
        throw new Error(`Unknown status: ${resp.imageScanStatus!.status}`);
      }
    } catch (err) {
      if (err instanceof ImageNotFoundException) {
        core.info(err.message);
      } else if (err instanceof ScanNotFoundException) {
        core.info(err.message);
      } else {
        throw err;
      }
    }
    await setTimeout(delay);
  } while (Date.now() < timeoutMs);
  throw new Error(`No complete scan after ${timeout} seconds`);
}

/**
 * Continues to call getAllSeverityCounts untill getting
 * the same result on subsequent calls. This is because after the aws ecr
 * api returns a status of COMPLETE, results continue to be be slowly updated
 * for a few seconds after
 */
async function pollForConsistency(
  command: DescribeImageScanFindingsCommand,
  delay: number,
): Promise<Record<string, number>> {
  if (delay === 0) {
    return getAllSeverityCounts(command);
  }

  let previousResult = undefined;
  while (true) {
    const currentResult = await getAllSeverityCounts(command);
    core.info(JSON.stringify(currentResult));
    if (previousResult && areFindingsEqual(currentResult, previousResult)) {
      core.info('Consistent Results!');
      return currentResult;
    }
    core.info('Polling for consitency...');
    previousResult = currentResult;
    await setTimeout(delay);
  }
}

/**
 * Continues to send the provided command with the previous nextToken
 * and aggregating findingSeverityCounts untill the nextToken in not returned.
 * Returns the aggregated findingSeverityCounts.
 *
 * TODO: This is due to the annoying behaviour of the ecr api. When returning the paginated
 * findings, the aggregated summary is only based on the current page. Meaning to get
 * the full aggregated vulnerability counts we need to check all the pages. Update here if
 * they change this.
 */
async function getAllSeverityCounts(
  command: DescribeImageScanFindingsCommand,
): Promise<Record<string, number>> {
  const result: Record<string, number> = {};
  let nextToken: string | undefined = undefined;
  do {
    const nextCommand: DescribeImageScanFindingsCommand =
      new DescribeImageScanFindingsCommand({ ...command.input, nextToken });
    const page = await client.send(nextCommand);
    if (!page.imageScanFindings?.findingSeverityCounts) {
      return result;
    }
    for (const key in page.imageScanFindings!.findingSeverityCounts) {
      const findingSeverity = key as FindingSeverity;
      if (result[key]) {
        result[key] +=
          page.imageScanFindings!.findingSeverityCounts![findingSeverity] || 0;
      } else {
        result[key] =
          page.imageScanFindings!.findingSeverityCounts![findingSeverity] || 0;
      }
    }
    nextToken = page.nextToken;
  } while (nextToken);
  return result;
}

/**
 * Checks if there are still vulnerabilities with severity > failOn
 * after removing vulnerabilites from ignore list and returns result.
 * Processes vulnerabilites in pages untill they are exhausted or all
 * items in the ignore list have been processed.
 */
async function doesContainNotIgnoredFailOnVulnerabilty(
  command: DescribeImageScanFindingsCommand,
  findingSeverityCounts: Record<string, number>,
  failOn: string,
  ignore: string[],
): Promise<boolean> {
  let nextToken: string | undefined = undefined;
  do {
    const nextCommand: DescribeImageScanFindingsCommand =
      new DescribeImageScanFindingsCommand({ ...command.input, nextToken });
    const page = await client.send(nextCommand);
    page.imageScanFindings?.enhancedFindings?.forEach((vulnerabilty) => {
      const ignoreIndex = ignore.indexOf(
        vulnerabilty.packageVulnerabilityDetails!.vulnerabilityId!,
      );
      if (ignoreIndex >= 0) {
        core.info(
          `Vulnerability ${vulnerabilty.packageVulnerabilityDetails!
            .vulnerabilityId!} is ignored with ${vulnerabilty.severity!} severity.`,
        );
        findingSeverityCounts[vulnerabilty.severity!] =
          findingSeverityCounts[vulnerabilty.severity!] - 1;
        ignore.splice(ignoreIndex, 1);
        if (!doesContainFailOnVulnerabilty(findingSeverityCounts, failOn)) {
          return false;
        }
      }
    });
    nextToken = page.nextToken;
  } while (nextToken && ignore.length > 0);
  return doesContainFailOnVulnerabilty(findingSeverityCounts, failOn);
}

function doesContainFailOnVulnerabilty(
  findingSeverityCounts: Record<string, number> | undefined,
  failOn: string,
): boolean {
  for (const severity in findingSeverityCounts) {
    if (
      findingSeverities[severity] <= findingSeverities[failOn] &&
      findingSeverityCounts[severity] > 0
    ) {
      return true;
    }
  }
  return false;
}

export function areFindingsEqual(
  f1: Record<string, number>,
  f2: Record<string, number>,
): boolean {
  const keys = Object.keys(f1);
  if (keys.length != Object.keys(f2).length) {
    return false;
  }

  for (let i = 0; i < keys.length; i++) {
    if (f1[keys[i]] != f2[keys[i]]) {
      return false;
    }
  }
  return true;
}
