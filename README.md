
<p align="center">
  <img src="badges/coverage.svg">
</p>

# Check AWS Inspector Scan #

This action can be used to check the findings of an [amazon inspector](https://docs.aws.amazon.com/inspector/latest/user/what-is-inspector.html) scan. Currently the action also only supports checking the results of scans on images pushed to ecr.

### Usage ###
```yml
- uses: ecperth/check-aws-inspector@v3
    with:
      # ecr repository name
      repository:
      # ecr registry id (optional)
      # aws account id which containts the ecr registry. Only required if
      # different from primary aws account id of authed role
      registry-id:
      # image tag
      image-tag:
      # and/or image digest
      image-digest:
      # vulnerability severity to cause action to fail (optional)
      # if provided the action will fail if a vulnerability of that severity or higher is 
      # found. [ CRITICAL | HIGH | MEDIUM | LOW | INFORMATIONAL| UNDEFINED ]
      fail-on:
      # vulnerabilityIds to ignore (optional)
      # seperated by spaces, commas or newlines
      ignore:
      # time (seconds) to get complete status from ecr before action fails
      timeout:
      # time (seconds) between polls for consistency
      # i suggest reading the explanation below and experimenting for yourself
      # as aws inspector behaviour may change making this unnecessary
      consistency-delay:
```
### Output ###
There is just one output **findingSeverityCounts**. A json representation of the counts of detected vulnerabilities grouped by severity. IE: 

```{ "CRITICAL": 2, "HIGH": 5, "MEDIUM": 10, "LOW": 17 }```

### Example ###

Get access token from [GitHub OIDC](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services), build and push image, check results of scan.

```yml
jobs:
  test-check-aws-inspector-action:
    runs-on: ubuntu-latest
    name: Test check-aws-inspector
    permissions:
      id-token: write
      contents: read

  steps:
  - uses: actions/checkout@v4

  - name: Configure AWS Credentials
    uses: aws-actions/configure-aws-credentials@v3
    with:
      role-to-assume: {IAM_ROLE}
      aws-region: ap-southeast-2

  - name: Login to Amazon ECR
    id: login-ecr
    uses: aws-actions/amazon-ecr-login@v1

  - name: Build, tag, and push image to Amazon ECR
    env:
      ECR_REGISTRY: ${{steps.login-ecr.outputs.registry}}
      ECR_REPOSITORY: my-ecr-repo
      IMAGE_TAG: ${{github.event.inputs.tag}}
      run: |
        docker build -t $ECR_REGISTRY/$ECR_REPOSITORY:$IMAGE_TAG .
        docker push $ECR_REGISTRY/$ECR_REPOSITORY:$IMAGE_TAG

  - name: Check results of aws inspect on image
    id: check-aws-inspector
    uses: ecperth/check-aws-inspector@v2
    with:
      repository: my-ecr-repo
      image-tag: ${{github.event.inputs.tag}}
      fail-on: CRITICAL
      ignore: 	
        CVE-2023-40217
        CVE-2023-36054
      timeout: 60
      consistency-delay: 15

  - name: Print the findings regardless of fail
    if: always()
    run: echo "${{ steps.check-aws-inspector.outputs.findingSeverityCounts }}" 
```
---
### Permissions ###
Required permission to check scan findings of ecr image with amazon inspector:

```terraform
data "aws_iam_policy_document" "example" {
  statement {
    sid       = "AllowEcrRepoAccess"
    effect    = "Allow"
    actions   = ["ecr:DescribeImageScanFindings"]
    resources = [{repo-arn}]
  }
  statement {
    sid       = "AllowAwsInspectAccess"
    effect    = "Allow"
    actions   = ["inspector2:ListCoverage", "inspector2:ListFindings"]
    resources = ["*"]
  }
}
```
For more concrete example check out what i did [here](https://github.com/ecperth/check-aws-inspector-test/).

---
### consistency-delay ###
In my testing i noticed that after a COMPLETE scan status is returned from the ecr api, the findings will take a while to all roll in. I added code in my action to re-poll the ecr api for findings once the status is COMPLETE untill it gets the same result set twice. The consistency-delay input is the time between these re-polls. 15 seconds consistently produced a full set of results for me but i was testing on a image with a lot of vulnerabilities.

```
Polling for complete scan...
Scan status is "Pending"
Polling for complete scan...
scan complete!
{ HIGH: 1, MEDIUM: 1 }
Polling for consitency...
{ HIGH: 73, MEDIUM: 144, LOW: 19, CRITICAL: 14 }
Polling for consitency...
{ HIGH: 97, MEDIUM: 199, LOW: 28, CRITICAL: 16 }
Polling for consitency...
{ HIGH: 97, MEDIUM: 199, LOW: 28, CRITICAL: 16 }
Consistent Results!
```
---
### development ###
Basic setup
```
git clone https://github.com/ecperth/check-aws-inspector
cd check-aws-inspector
npm install
```

Unit tests
```
npm run test
```

Bundle
```
npm run bundle
```
---

Nothing more to it than that!
