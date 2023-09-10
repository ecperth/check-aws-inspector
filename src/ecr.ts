import {
  ECRClient,
  DescribeImageScanFindingsCommand,
  DescribeImageScanFindingsCommandOutput,
  ScanNotFoundException,
} from "@aws-sdk/client-ecr";
import { findingSeverities } from "./scanner";

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
): Promise<DescribeImageScanFindingsCommandOutput> {
  const command = new DescribeImageScanFindingsCommand({
    repositoryName: repository,
    imageId: {
      imageTag: tag,
    },
  });
  const startTime = Date.now();

  do {
    try {
      client.send(command).then((resp) => {
        processImageScanFindings(resp, failSeverity);
      });
    } catch (err: unknown) {
      if (err instanceof ScanNotFoundException) {
        console.log(`Scan incomplete, retrying in ${delay}ms`);
        await wait(delay);
        continue;
      }
    }
  } while ((Date.now() - startTime) / 1000 < timeout);
  throw new Error("Scan findings timed out!");
}

function processImageScanFindings(
  imageScanFindings: DescribeImageScanFindingsCommandOutput,
  failSeverity: string,
) {
  console.log(imageScanFindings.imageScanFindings?.findingSeverityCounts);
}
