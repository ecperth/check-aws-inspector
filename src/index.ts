import * as core from "@actions/core";
import { main } from "./ecr";

try {
  //const repository = core.getInput("repository");
  //const tag = core.getInput("tag");
  //core.setOutput("image", repository + ":" + tag);
  main();
} catch (error: any) {
  core.setFailed(error.message);
}
