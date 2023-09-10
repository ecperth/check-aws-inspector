import * as core from "@actions/core";
import { scan } from "./ecr";

try {
  const repository = core.getInput("repository");
  const tag = core.getInput("tag");
  //core.setOutput("image", repository + ":" + tag);
  scan(repository, tag);
} catch (error: any) {
  core.setFailed(error.message);
}
