import {
  DescribeImageScanFindingsCommand,
  DescribeImageScanFindingsCommandInput,
  DescribeImageScanFindingsCommandOutput,
  ECRClient,
  ImageNotFoundException,
  ScanNotFoundException,
} from '@aws-sdk/client-ecr';
import { mockClient } from 'aws-sdk-client-mock';
import { areFindingsEqual, getImageScanFindings } from '../src/ecr';

const timeoutSeconds = 0.05;
const pollRateSeconds = 0.01;

it('error when timeout is exceeded', async () => {
  const ecrClientMock = mockClient(ECRClient);
  ecrClientMock.on(DescribeImageScanFindingsCommand).resolves({
    imageScanStatus: {
      status: 'PENDING',
    },
  });

  const result = await getImageScanFindings(
    'repository',
    undefined,
    { imageTag: 'tag' },
    [],
    timeoutSeconds,
    pollRateSeconds,
    0,
  );
  expect(result).toEqual({
    errorMessage: `No complete scan after ${timeoutSeconds} seconds`,
  });
});

it('error when unexpected status', async () => {
  const ecrClientMock = mockClient(ECRClient);
  ecrClientMock.on(DescribeImageScanFindingsCommand).resolves({
    imageScanStatus: {
      status: 'RANDOM_STATUS',
    },
  });

  const result = await getImageScanFindings(
    'repository',
    undefined,
    { imageTag: 'tag' },
    [],
    timeoutSeconds,
    pollRateSeconds,
    0,
  );
  expect(result).toEqual({
    errorMessage: `Unknown status: RANDOM_STATUS`,
  });
});

it('handle when ImageNotFoundException recieved when polling for completion and keep polling', async () => {
  const ecrClientMock = mockClient(ECRClient);
  ecrClientMock
    .on(DescribeImageScanFindingsCommand)
    .rejects(new ImageNotFoundException({ $metadata: {}, message: '' }));

  const result = await getImageScanFindings(
    'repository',
    undefined,
    { imageTag: 'tag' },
    [],
    timeoutSeconds,
    pollRateSeconds,
    0,
  );
  expect(result).toEqual({
    errorMessage: `No complete scan after ${timeoutSeconds} seconds`,
  });
});

it('handle when ScanNotFoundException recieved when polling for completion and keep polling', async () => {
  const ecrClientMock = mockClient(ECRClient);
  ecrClientMock
    .on(DescribeImageScanFindingsCommand)
    .rejects(new ScanNotFoundException({ $metadata: {}, message: '' }));

  const result = await getImageScanFindings(
    'repository',
    undefined,
    { imageTag: 'tag' },
    [],
    timeoutSeconds,
    pollRateSeconds,
    0,
  );
  expect(result).toEqual({
    errorMessage: `No complete scan after ${timeoutSeconds} seconds`,
  });
});

it('return error when Error recieved from ecr client during polling for completion', async () => {
  const ecrClientMock = mockClient(ECRClient);
  ecrClientMock
    .on(DescribeImageScanFindingsCommand)
    .rejects(new Error('Some random thing went wrong'));

  const result = await getImageScanFindings(
    'repository',
    undefined,
    { imageTag: 'tag' },
    [],
    timeoutSeconds,
    pollRateSeconds,
    0,
  );
  expect(result).toEqual({
    errorMessage: 'Some random thing went wrong',
  });
});

it('complete with no findings', async () => {
  const ecrClientMock = mockClient(ECRClient);
  ecrClientMock.on(DescribeImageScanFindingsCommand).resolves({
    imageScanStatus: {
      status: 'COMPLETE',
    },
  });

  const result = await getImageScanFindings(
    'repository',
    undefined,
    { imageTag: 'tag' },
    [],
    timeoutSeconds,
    pollRateSeconds,
    0,
  );
  expect(result).toEqual({ findingSeverityCounts: {} });
});

it('complete with findings. No failOn', async () => {
  const ecrClientMock = mockClient(ECRClient);
  ecrClientMock.on(DescribeImageScanFindingsCommand).resolves({
    imageScanStatus: {
      status: 'COMPLETE',
    },
    imageScanFindings: {
      findingSeverityCounts: { CRITICAL: 1 },
    },
  });

  const result = await getImageScanFindings(
    'repository',
    undefined,
    { imageTag: 'tag' },
    [],
    timeoutSeconds,
    pollRateSeconds,
    0,
  );
  expect(result).toEqual({ findingSeverityCounts: { CRITICAL: 1 } });
});

describe('set errorMessage on failOn condition', () => {
  beforeAll(() => {
    const ecrClientMock = mockClient(ECRClient);
    ecrClientMock.on(DescribeImageScanFindingsCommand).resolves({
      imageScanStatus: {
        status: 'COMPLETE',
      },
      imageScanFindings: {
        findingSeverityCounts: { CRITICAL: 1 },
      },
    });
  });

  it('error message when failOn severity found', async () => {
    const result = await getImageScanFindings(
      'repository',
      undefined,
      { imageTag: 'tag' },
      [],
      timeoutSeconds,
      pollRateSeconds,
      0,
      'CRITICAL',
    );
    expect(result).toEqual({
      findingSeverityCounts: { CRITICAL: 1 },
      errorMessage: 'Found vulnerabilty with severity of CRITICAL or greater.',
    });
  });

  it('error message when > failOn severity found', async () => {
    const result = await getImageScanFindings(
      'repository',
      undefined,
      { imageTag: 'tag' },
      [],
      timeoutSeconds,
      pollRateSeconds,
      0,
      'HIGH',
    );
    expect(result).toEqual({
      findingSeverityCounts: { CRITICAL: 1 },
      errorMessage: 'Found vulnerabilty with severity of HIGH or greater.',
    });
  });
});

describe('check ignored list', () => {
  beforeAll(() => {
    const ecrClientMock = mockClient(ECRClient);
    ecrClientMock.on(DescribeImageScanFindingsCommand).resolves({
      imageScanStatus: {
        status: 'COMPLETE',
      },
      imageScanFindings: {
        findingSeverityCounts: { CRITICAL: 1, HIGH: 1 },
        enhancedFindings: [
          {
            packageVulnerabilityDetails: { vulnerabilityId: 'CRIT1' },
            severity: 'CRITICAL',
          },
          {
            packageVulnerabilityDetails: { vulnerabilityId: 'CRIT2' },
            severity: 'HIGH',
          },
        ],
      },
    });
  });

  it("don't fail on ignored vulnerability", async () => {
    const result = await getImageScanFindings(
      'repository',
      undefined,
      { imageTag: 'tag' },
      ['CRIT1', 'CRIT2'],
      timeoutSeconds,
      pollRateSeconds,
      0,
      'CRITICAL',
    );
    expect(result).toEqual({
      findingSeverityCounts: { CRITICAL: 1, HIGH: 1 },
    });
  });

  it('fail on ignored vulnerability when remaining vulnerabilty with failOn severity', async () => {
    const result = await getImageScanFindings(
      'repository',
      undefined,
      { imageTag: 'tag' },
      ['CRIT1'],
      timeoutSeconds,
      pollRateSeconds,
      0,
      'HIGH',
    );
    expect(result).toEqual({
      findingSeverityCounts: { CRITICAL: 1, HIGH: 1 },
      errorMessage: 'Found vulnerabilty with severity of HIGH or greater.',
    });
  });
});

describe('mulitple pages of findingSeverityCounts', () => {
  const input1: DescribeImageScanFindingsCommandInput = {
    repositoryName: 'repository',
    imageId: {
      imageTag: 'tag',
    },
  };

  const input2: DescribeImageScanFindingsCommandInput = {
    repositoryName: 'repository',
    imageId: {
      imageTag: 'tag',
    },
    nextToken: 'NEXT_TOKEN1',
  };

  const input3: DescribeImageScanFindingsCommandInput = {
    repositoryName: 'repository',
    imageId: {
      imageTag: 'tag'
    },
    nextToken: 'NEXT_TOKEN2',
  };

  const page1: DescribeImageScanFindingsCommandOutput = {
    $metadata: {},
    imageScanStatus: {
      status: 'COMPLETE',
    },
    imageScanFindings: {
      findingSeverityCounts: { HIGH: 1, MEDIUM: 1 },
    },
    nextToken: 'NEXT_TOKEN1',
  };

  const page2: DescribeImageScanFindingsCommandOutput = {
    $metadata: {},
    imageScanStatus: {
      status: 'COMPLETE',
    },
    imageScanFindings: {
      findingSeverityCounts: { CRITICAL: 1, MEDIUM: 1, LOW: 1 },
      enhancedFindings: [
        {
          packageVulnerabilityDetails: { vulnerabilityId: 'CRIT1' },
          severity: 'CRITICAL',
        },
      ],
    },
    nextToken: 'NEXT_TOKEN2',
  };

  const page3: DescribeImageScanFindingsCommandOutput = {
    $metadata: {},
    imageScanStatus: {
      status: 'COMPLETE',
    },
    imageScanFindings: {
      findingSeverityCounts: { CRITICAL: 1 },
      enhancedFindings: [
        {
          packageVulnerabilityDetails: { vulnerabilityId: 'CRIT2' },
          severity: 'CRITICAL',
        },
      ],
    },
  };

  it('get all pages. Last ignored vulnerability is on last page', async () => {
    const ecrClientMock = mockClient(ECRClient);
    ecrClientMock.on(DescribeImageScanFindingsCommand, input1).resolves(page1);
    ecrClientMock.on(DescribeImageScanFindingsCommand, input2).resolves(page2);
    ecrClientMock.on(DescribeImageScanFindingsCommand, input3).resolves(page3);

    const result = await getImageScanFindings(
      'repository',
      undefined,
      { imageTag: 'tag' },
      ['CRIT1', 'CRIT2'],
      timeoutSeconds,
      pollRateSeconds,
      0.01,
      'CRITICAL',
    );
    expect(result).toEqual({
      findingSeverityCounts: { CRITICAL: 2, HIGH: 1, MEDIUM: 2, LOW: 1 },
    });
    /*
		Check that the last page of results was requested 3 times. Twice while polling
		for consistent findingSeverityCounts and a third time while checking against the
		ignore list
		*/
    expect(
      ecrClientMock
        .commandCalls(DescribeImageScanFindingsCommand)
        .filter((x) => {
          return x.args[0].input.nextToken === 'NEXT_TOKEN2';
        }).length,
    ).toEqual(3);
  });

  it('Dont get last page as all ignores are accounted for', async () => {
    const ecrClientMock = mockClient(ECRClient);
    ecrClientMock.on(DescribeImageScanFindingsCommand, input1).resolves(page1);
    ecrClientMock.on(DescribeImageScanFindingsCommand, input2).resolves(page2);
    ecrClientMock.on(DescribeImageScanFindingsCommand, input3).resolves(page3);

    const result = await getImageScanFindings(
      'repository',
      undefined,
      { imageTag: 'tag' },
      ['CRIT1'],
      timeoutSeconds,
      pollRateSeconds,
      0.01,
      'CRITICAL',
    );
    expect(result).toEqual({
      errorMessage: 'Found vulnerabilty with severity of CRITICAL or greater.',
      findingSeverityCounts: { CRITICAL: 2, HIGH: 1, MEDIUM: 2, LOW: 1 },
    });
    /*
		Check that the last page of results was requested 2 times. Twice while polling
		for consistent findingSeverityCounts. Third page should not be reached while
		checking against ignore list as the only ignore vulnerability is on the second page.
		*/
    expect(
      ecrClientMock
        .commandCalls(DescribeImageScanFindingsCommand)
        .filter((x) => {
          return x.args[0].input.nextToken === 'NEXT_TOKEN2';
        }).length,
    ).toEqual(2);
  });
});

describe('areFindingsEqual', () => {
  it('different length', () => {
    const result = areFindingsEqual({ CRITICAL: 1 }, { CRITICAL: 1, HIGH: 1 });
    expect(result).toBeFalsy();
  });

  it('different keys', () => {
    const result = areFindingsEqual({ CRITICAL: 1 }, { HIGH: 1 });
    expect(result).toBeFalsy();
  });

  it('different values', () => {
    const result = areFindingsEqual({ CRITICAL: 1 }, { CRITICAL: 2 });
    expect(result).toBeFalsy();
  });

  it('same', () => {
    const result = areFindingsEqual({ CRITICAL: 1 }, { CRITICAL: 1 });
    expect(result).toBeTruthy();
  });
});
