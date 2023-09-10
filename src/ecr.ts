import {
  ECRClient,
  DescribeImageScanFindingsCommand,
  ScanNotFoundException,
} from "@aws-sdk/client-ecr";

const client = new ECRClient({ region: "ap-southeast-2" });
const command = new DescribeImageScanFindingsCommand({
  repositoryName: "check-aws-inspector-test",
  imageId: {
    imageTag: "latest",
  },
});

function delay(milliseconds: number) {
  return new Promise((resolve) => {
    setTimeout(resolve, milliseconds);
  });
}

export async function scan() {
  while (true) {
    try {
      let x = await client.send(command);
      console.log(x);
      await delay(50);
      break;
    } catch (err: unknown) {
      if (err instanceof ScanNotFoundException) {
        console.log("Scan Incomplete waiting 50ms");
        continue;
      } else {
        console.log("ERROR: ", err);
        break;
      }
    }
  }
}
