import {
  ECRClient,
  DescribeImageScanFindingsCommand,
  DescribeImageScanFindingsCommandOutput,
  ScanNotFoundException,
} from "@aws-sdk/client-ecr";
import { findingSeverities, ScanFindings } from "./scanner";

const client = new ECRClient({ region: "ap-southeast-2" });

function wait(milliseconds: number) {
  return new Promise((resolve) => {
    setTimeout(resolve, milliseconds);
  });
}

export async function scan(
  repository: string,
  tag: string,
  delay: number,
  timeout: number,
  failSeverity: string,
): Promise<ScanFindings> {
  const command = new DescribeImageScanFindingsCommand({
    repositoryName: repository,
    imageId: {
      imageTag: tag,
    },
  });
  const startTime = Date.now();

  while (true) {
    try {
      return client
        .send(command)
        .then((resp) => processImageScanFindings(resp, failSeverity));
    } catch (err: unknown) {
      if (err instanceof ScanNotFoundException) {
        console.log(`Scan incomplete, retrying in ${delay}ms`);
        await wait(delay);
        continue;
      }
    }

    const runningTime = (Date.now() - startTime) / 1000;
    if (runningTime >= timeout) {
      return {
        errorMessage: `Scan findings timed out after ${runningTime} seconds`,
      };
    }
  }
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
