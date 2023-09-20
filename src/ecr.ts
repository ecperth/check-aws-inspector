import {
  ECRClient,
  DescribeImageScanFindingsCommand,
  ScanNotFoundException,
} from '@aws-sdk/client-ecr';
import { findingSeverities, ScanFindings } from './scanner';
import { setTimeout } from 'timers/promises';

const client = new ECRClient();
const POLL_RATE = 5000;

/**
 * @param {string} repository - ECR repo name
 * @param {tag} tag - Image tag
 * @param {string} failOn - Severity to cause failure
 * @param {string[]} ignore - VulnerabilityIds to ignore
 * @param {string} timeout - Time in seconds for scan to complete before failure
 * @param {string} consistencyDelay - Time in seconds between polls for consistency
 * @returns {Promise<ScanFindings>}
 */
export async function getImageScanFindings(
  repository: string,
  tag: string,
  failOn: string,
  ignore: string[],
  timeout: number,
  consistencyDelay: number,
): Promise<ScanFindings> {
  const command = new DescribeImageScanFindingsCommand({
    repositoryName: repository,
    imageId: {
      imageTag: tag,
    },
  });

  // Poll with delay untill we get 'COMPLETE' status.
  try {
    await pollForScanCompletion(command, POLL_RATE, timeout);
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
  if (!findingSeverityCounts) {
    return {};
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
    console.log(`Polling for complete scan...`);
    try {
      const resp = await client.send(command);
      if (resp.imageScanStatus?.status === 'COMPLETE') {
        console.log(`Scan complete!`);
        return;
      } else if (resp.imageScanStatus?.status === 'PENDING') {
        console.log(`Scan status is "Pending"`);
      } else {
        throw new Error(`Unknown status: ${resp.imageScanStatus!.status}`);
      }
    } catch (err) {
      if (err instanceof ScanNotFoundException) {
        console.log(`ERROR: ${err.message}`);
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
  let previousResult = undefined;
  while (true) {
    const currentResult = await getAllSeverityCounts(command);
    console.log(currentResult);
    if (previousResult && areFindingsEqual(currentResult, previousResult)) {
      console.log('Consistent Results!');
      return currentResult;
    }
    console.log('Polling for consitency...');
    previousResult = currentResult;
    await setTimeout(delay);
  }
}

/**
 * Continues to send the provided command with the previous nextToken
 * and aggregating findingSeverityCounts untill the nextToken in not returned.
 * Returns the aggregated findingSeverityCounts.
 */
async function getAllSeverityCounts(
  command: DescribeImageScanFindingsCommand,
): Promise<Record<string, number>> {
  const result: Record<string, number> = {};
  do {
    const page = await client.send(command);
    if (!page.imageScanFindings?.findingSeverityCounts) {
      return result;
    }
    Object.keys(page.imageScanFindings!.findingSeverityCounts).forEach(
      (key) => {
        if (result[key]) {
          result[key] =
            result[key] + page.imageScanFindings!.findingSeverityCounts![key];
        } else {
          result[key] = page.imageScanFindings!.findingSeverityCounts![key];
        }
      },
    );
    command.input.nextToken = page.nextToken;
  } while (command.input.nextToken);
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
  do {
    const resp = await client.send(command);
    resp.imageScanFindings?.enhancedFindings?.forEach((vulnerabilty) => {
      const ignoreIndex = ignore.indexOf(
        vulnerabilty.packageVulnerabilityDetails!.vulnerabilityId!,
      );
      if (ignoreIndex >= 0) {
        console.log(
          `Vulnerability ${vulnerabilty.packageVulnerabilityDetails!
            .vulnerabilityId!} is ignored. Decrementing the ${vulnerabilty.severity!} severity count.`,
        );
        findingSeverityCounts[vulnerabilty.severity!] =
          findingSeverityCounts[vulnerabilty.severity!] - 1;
        ignore.splice(ignoreIndex, 1);
        if (!doesContainFailOnVulnerabilty(findingSeverityCounts, failOn)) {
          return false;
        }
      }
      command.input.nextToken = resp.nextToken;
    });
  } while (command.input.nextToken && ignore.length > 0);
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

function areFindingsEqual(
  f1: Record<string, number>,
  f2: Record<string, number>,
): boolean {
  const keys = Object.keys(f1);
  if (keys.length != Object.keys(f2).length) {
    return false;
  }
  keys.forEach((k) => {
    if (f1[k] != f2[k]) {
      return false;
    }
  });
  return true;
}
