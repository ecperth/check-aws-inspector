import {
  ECRClient,
  DescribeImageScanFindingsCommand,
  ScanNotFoundException,
} from "@aws-sdk/client-ecr";

const client = new ECRClient({ region: "ap-southeast-2" });

function delay(milliseconds: number) {
  return new Promise((resolve) => {
    setTimeout(resolve, milliseconds);
  });
}

export async function scan(repository: string, tag: string) {
  const command = new DescribeImageScanFindingsCommand({
    repositoryName: repository,
    imageId: {
      imageTag: tag,
    },
  });

  while (true) {
    try {
      console.log(await client.send(command));
      break;
    } catch (err: unknown) {
      if (err instanceof ScanNotFoundException) {
        console.log("Scan Incomplete waiting 50ms");
        await delay(50);
        continue;
      } else {
        console.log("ERROR: ", err);
        break;
      }
    }
  }
}
