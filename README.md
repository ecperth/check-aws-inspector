
<p align="center">
  <img src="badges/coverage.svg">
</p>

## Usage ##
```
- name: Check results of aws inspect on image
        id: check-aws-inspector
        uses: ecperth/check-aws-inspector@v0.1
        with:
          repository: ecr repo name
          tag: image tag
          fail-on: vulnerability severity to cause action to fail (Optional)
          ignore: vulnerabilityIds to ignore (Optional)
          timeout: time (s) to get complete status from ecr before action fails
          consistency-delay: time (s) between polls for consistency 
```
## Output ##
There is just one output **findingSeverityCounts** which is json containting the severity counts as shown in log below.

#### consistency-delay ####
In my testing i noticed that after a COMPLETE scan status is returned from the ecr api, the findings will take a while to all roll in. I added code in my action to re-poll the ecr api for findings once the status is COMPLERE untill it gets the same result set twice. The consistency-delay input is the time between these re-polls. 15 seconds consistently produced a full set of results for me but i was testing on a image with a lot of vulnerabilities.

```
Polling for complete scan...
Scan status is "Pending"
Polling for complete scan...
scan complete!
{ HIGH: 1, MEDIUM: 1 }
Polling for consitency...
{ HIGH: 73, MEDIUM: 144, LOW: 19, UNTRIAGED: 1, CRITICAL: 14 }
Polling for consitency...
{ HIGH: 97, MEDIUM: 199, LOW: 28, UNTRIAGED: 2, CRITICAL: 16 }
Polling for consitency...
{ HIGH: 97, MEDIUM: 199, LOW: 28, UNTRIAGED: 2, CRITICAL: 16 }
Consistent Results!
```
