import * as core from "@actions/core";

try {
  const repository = core.getInput("repository");
  const tag = core.getInput("tag");
  core.setOutput("image", repository + ":" + tag);
} catch (error: any) {
  core.setFailed(error.message);
}
