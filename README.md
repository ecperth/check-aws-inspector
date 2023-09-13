## Usage ##
```
- name: Login to Amazon ECR
        id: login-ecr
        uses: aws-actions/amazon-ecr-login@v1

- name: Check results of aws inspect on image
        id: check-aws-inspector
        uses: ecperth/check-aws-inspector@v0.1
        with:
          repository: 
          tag:
          fail-on:
          ignore:
          max-retries:
          delay:
          consistency-delay:
```
