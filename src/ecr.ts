import {
  ECRClient,
  DescribeImageScanFindingsCommand,
  DescribeImageScanFindingsCommandOutput,
  ScanNotFoundException,
  ImageNotFoundException,
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
  max_retries: number,
  failSeverity: string,
): Promise<ScanFindings> {
  const command = new DescribeImageScanFindingsCommand({
    repositoryName: repository,
    imageId: {
      imageTag: tag,
    },
  });

  return client
    .send(command)
    .then((resp) => processImageScanFindings(resp, failSeverity))
    .catch((err) => {
      if (
        err instanceof ScanNotFoundException ||
        err instanceof ImageNotFoundException
      ) {
        if (max_retries === 0) {
          return {
            errorMessage: `Failed to retrieve scan findings after max_retries`,
          };
        }
        console.log(`ERROR: ${err.message}`);
        console.log(
          `Retrying in ${delay}ms. ${max_retries} attempts remaining`,
        );
      }
      return wait(delay).then(() =>
        scan(repository, tag, delay, max_retries - 1, failSeverity),
      );
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
