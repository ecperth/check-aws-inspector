import {
  ECRClient,
  DescribeImageScanFindingsCommand,
  DescribeImageScanFindingsCommandOutput,
  ScanNotFoundException,
  ImageNotFoundException,
} from "@aws-sdk/client-ecr";
import { findingSeverities, ScanFindings } from "./scanner";
import { setTimeout } from "timers/promises";

const client = new ECRClient({ region: "ap-southeast-2" });

export async function scan(
  repository: string,
  tag: string,
  failSeverity: string,
  delay: number,
  remainingRetries: number,
  validationDelay: number,
): Promise<ScanFindings> {
  const command = new DescribeImageScanFindingsCommand({
    repositoryName: repository,
    imageId: {
      imageTag: tag,
    },
  });

  const completedScan = await pollForScanCompletion(
    command,
    delay,
    remainingRetries,
  );
  if (completedScan.errorMessage) {
    return completedScan;
  }
  const verifiedScan = await verifyScanComplete(
    command,
    validationDelay,
    completedScan.findingSeverityCounts,
  );
  return processImageScanFindings(verifiedScan, failSeverity);
}

async function pollForScanCompletion(
  command: DescribeImageScanFindingsCommand,
  delay: number,
  remainingRetries: number,
): Promise<ScanFindings> {
  return client
    .send(command)
    .then(async (resp) => {
      if (resp.imageScanStatus?.status === "COMPLETE") {
        return {
          findingSeverityCounts: resp.imageScanFindings?.findingSeverityCounts,
        };
      } else if (resp.imageScanStatus?.status === "PENDING") {
        if (remainingRetries === 0) {
          return { errorMessage: `No complete scan after maxRetries` };
        }
        remainingRetries--;
        console.log(
          `Scan status is "Pending". Retrying in ${delay}ms. ${remainingRetries} attempts remaining`,
        );
        await setTimeout(delay);
        return pollForScanCompletion(command, delay, remainingRetries);
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
        if (remainingRetries === 0) {
          return { errorMessage: `No complete scan after maxRetries` };
        }

        console.log(`ERROR: ${err.message}`);
        remainingRetries--;
        console.log(
          `Retrying in ${delay}ms. ${remainingRetries} attempts remaining`,
        );
        await setTimeout(delay);
        return pollForScanCompletion(command, delay, remainingRetries);
      }
      return { errorMessage: err.message };
    });
}

async function verifyScanComplete(
  command: DescribeImageScanFindingsCommand,
  delay: number,
  lastSeverityCounts: Record<string, number> | undefined,
): Promise<DescribeImageScanFindingsCommandOutput> {
  return client.send(command).then(async (resp) => {
    const currentSeverityCounts = resp.imageScanFindings?.findingSeverityCounts;
    console.log("Current severity counts: ", currentSeverityCounts);

    if (currentSeverityCounts === undefined) {
      await setTimeout(delay);
      return verifyScanComplete(command, delay, currentSeverityCounts);
    } else if (
      lastSeverityCounts === undefined ||
      !areFindingsEqual(currentSeverityCounts, lastSeverityCounts)
    ) {
      await setTimeout(delay);
      return verifyScanComplete(command, delay, currentSeverityCounts);
    }
    return resp;
  });
}

function processImageScanFindings(
  imageScanFindings: DescribeImageScanFindingsCommandOutput,
  failSeverity: string,
): ScanFindings {
  const result: ScanFindings = {
    findingSeverityCounts:
      imageScanFindings.imageScanFindings!.findingSeverityCounts!,
  };

  for (const severity in result.findingSeverityCounts) {
    if (findingSeverities[severity] > findingSeverities[failSeverity]) {
      break;
    } else {
      result.errorMessage = `Found at least 1 vulnerabilty with severity ${failSeverity} or higher`;
    }
  }
  return result;
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
