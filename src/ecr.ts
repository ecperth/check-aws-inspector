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
  maxRetries: number,
  validationDelay: number,
): Promise<ScanFindings> {
  const command = new DescribeImageScanFindingsCommand({
    repositoryName: repository,
    imageId: {
      imageTag: tag,
    },
  });

  return client
    .send(command)
    .then((resp) => {
      if (resp.imageScanStatus?.status === "PENDING") {
        if (maxRetries === 0) {
          return {
            errorMessage: `Failed to retrieve scan findings after max_retries`,
          };
        }
        console.log(
          `Scan status is "Pending". Retrying in ${delay}ms. ${
            maxRetries - 1
          } attempts remaining`,
        );
        return setTimeout(delay).then(() =>
          scan(
            repository,
            tag,
            failSeverity,
            delay,
            maxRetries - 1,
            validationDelay,
          ),
        );
      }
      return verifyScanComplete(
        command,
        failSeverity,
        validationDelay,
        resp.imageScanFindings?.findingSeverityCounts,
      );
    })
    .catch((err) => {
      if (
        err instanceof ScanNotFoundException ||
        err instanceof ImageNotFoundException
      ) {
        if (maxRetries === 0) {
          return {
            errorMessage: `Failed to retrieve scan findings after max_retries`,
          };
        }
        console.log(`ERROR: ${err.message}`);
        console.log(
          `Retrying in ${delay}ms. ${maxRetries - 1} attempts remaining`,
        );
      }
      return setTimeout(delay).then(() =>
        scan(
          repository,
          tag,
          failSeverity,
          delay,
          maxRetries - 1,
          validationDelay,
        ),
      );
    });
}

export async function verifyScanComplete(
  command: DescribeImageScanFindingsCommand,
  failSeverity: string,
  delay: number,
  lastSeverityCounts: Record<string, number> | undefined,
): Promise<ScanFindings> {
  return client.send(command).then((resp) => {
    console.log(resp.imageScanFindings?.findingSeverityCounts);
    if (
      resp.imageScanFindings?.findingSeverityCounts === undefined ||
      JSON.stringify(resp.imageScanFindings?.findingSeverityCounts) !=
        JSON.stringify(lastSeverityCounts)
    ) {
      console.log(
        `Last result: ${resp.imageScanFindings?.findingSeverityCounts}, "This result: ${lastSeverityCounts}`,
      );
      console.log(`Keep going...`);
      return setTimeout(delay).then(() =>
        verifyScanComplete(
          command,
          failSeverity,
          delay,
          resp.imageScanFindings?.findingSeverityCounts,
        ),
      );
    }
    return processImageScanFindings(resp, failSeverity);
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
