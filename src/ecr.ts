import {
  ECRClient,
  DescribeImageScanFindingsCommand,
  ScanNotFoundException,
  ImageNotFoundException,
} from '@aws-sdk/client-ecr';
import { findingSeverities, ScanFindings } from './scanner';
import { setTimeout } from 'timers/promises';

const client = new ECRClient();
/**
 * @param {string} repository - ECR repo name
 * @param {tag} tag - Image tag
 * @param {string} failOn - Severity to cause failure
 * @param {string[]} ignore - VulnerabilityIds to ignore
 * @param {string} delay - Time in ms between polls for completion
 * @param {string} retries - Number of retries before failing
 * @param {string} consistencyDelay - Time in ms between polls for consistency
 * @returns {Promise<ScanFindings>}
 */
export async function getImageScanFindings(
  repository: string,
  tag: string,
  failOn: string,
  ignore: string[],
  delay: number,
  retries: number,
  consistencyDelay: number,
): Promise<ScanFindings> {
  const command = new DescribeImageScanFindingsCommand({
    repositoryName: repository,
    imageId: {
      imageTag: tag,
    },
  });

  // Poll with delay untill we get 'COMPLETE' status.
  const completedScan = await pollForScanCompletion(command, delay, retries);
  if (completedScan.errorMessage) {
    return completedScan;
  }

  // Poll with validationDelay untill we get consistent data
  await setTimeout(consistencyDelay);
  const findingSeverityCounts = await pollForConsistency(
    command,
    consistencyDelay,
    completedScan.findingSeverityCounts,
  );
  // No findings
  if (!findingSeverityCounts) {
    return {};
  }
  // No vulnerability > onFail or failOn not provided
  if (
    !failOn ||
    !doesContainOnFailVulnerabilty(findingSeverityCounts, failOn)
  ) {
    return { findingSeverityCounts: findingSeverityCounts };
  }
  // Vulnerability > onFail found and no ignores provided
  if (ignore.length === 0) {
    return {
      findingSeverityCounts: findingSeverityCounts!,
      errorMessage: `Found vulnerabilty with severity of ${failOn} or greater.`,
    };
  }
  // Vulnerability > onFail found after excluded ignores
  if (
    await doesContainNotIgnoredOnFailVulnerabilty(
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
  // Excluding ignores no Vulnerability onFail
  return {
    findingSeverityCounts: findingSeverityCounts,
  };
}

/**
 * Continues to send the provided command untill getting a 'COMPLETE' status
 * or retries are exhausted.
 */
async function pollForScanCompletion(
  command: DescribeImageScanFindingsCommand,
  delay: number,
  retries: number,
): Promise<ScanFindings> {
  return client
    .send(command)
    .then(async (resp) => {
      if (resp.imageScanStatus?.status === 'COMPLETE') {
        return {
          findingSeverityCounts: resp.imageScanFindings?.findingSeverityCounts,
        };
      } else if (resp.imageScanStatus?.status === 'PENDING') {
        if (retries === 0) {
          return { errorMessage: `No complete scan after maxRetries` };
        }
        retries--;
        console.log(
          `Scan status is "Pending". Retrying in ${delay}ms. ${retries} attempts remaining`,
        );
        await setTimeout(delay);
        return pollForScanCompletion(command, delay, retries);
      }
      return {
        errorMessage: `unknown status: ${resp.imageScanStatus!.status}`,
      };
    })
    .catch(async (err: Error) => {
      if (
        err instanceof ScanNotFoundException ||
        err instanceof ImageNotFoundException
      ) {
        if (retries === 0) {
          return { errorMessage: `No complete scan after maxRetries` };
        }
        retries--;
        console.log(`ERROR: ${err.message}`);
        console.log(`Retrying in ${delay}ms. ${retries} attempts remaining`);
        await setTimeout(delay);
        return pollForScanCompletion(command, delay, retries);
      }
      return { errorMessage: err.message };
    });
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
  previousResult: Record<string, number> | undefined,
): Promise<Record<string, number> | undefined> {
  console.log('Severity counts: ', previousResult);
  return getAllSeverityCounts(command).then(async (currentResult) => {
    if (currentResult === undefined) {
      await setTimeout(delay);
      return pollForConsistency(command, delay, currentResult);
    } else if (
      previousResult === undefined ||
      !areFindingsEqual(currentResult, previousResult)
    ) {
      await setTimeout(delay);
      return pollForConsistency(command, delay, currentResult);
    }
    return currentResult;
  });
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
async function doesContainNotIgnoredOnFailVulnerabilty(
  command: DescribeImageScanFindingsCommand,
  findingSeverityCounts: Record<string, number>,
  failOn: string,
  ignore: string[],
): Promise<boolean> {
  do {
    const resp = await client.send(command);
    resp.imageScanFindings?.enhancedFindings?.forEach((vulnerabilty) => {
      const i = ignore.indexOf(
        vulnerabilty.packageVulnerabilityDetails!.vulnerabilityId!,
      );
      if (i >= 0) {
        console.log(
          `Vulnerability ${vulnerabilty.packageVulnerabilityDetails!
            .vulnerabilityId!} is ignored. Decrementing the ${vulnerabilty.severity!} severity count.`,
        );
        findingSeverityCounts[vulnerabilty.severity!] =
          findingSeverityCounts[vulnerabilty.severity!] - 1;
        ignore.splice(i, 1);
        if (!doesContainOnFailVulnerabilty(findingSeverityCounts, failOn)) {
          return false;
        }
      }
      command.input.nextToken = resp.nextToken;
    });
  } while (command.input.nextToken && ignore.length > 0);
  return doesContainOnFailVulnerabilty(findingSeverityCounts, failOn);
}

function doesContainOnFailVulnerabilty(
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
