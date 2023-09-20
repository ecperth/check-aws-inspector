import * as core from '@actions/core';
import * as ecr from '../src/ecr';
import { run, splitIgnoreList } from '../src/index';
import { ScanFindings } from '../src/scanner';

const getInputMock = jest.spyOn(core, 'getInput');
const setOutputMock = jest.spyOn(core, 'setOutput');
const setFailedMock = jest.spyOn(core, 'setFailed');
const getImageScanFindingsMock = jest.spyOn(ecr, 'getImageScanFindings');

describe('validation', () => {
  it('fail early on invalid fail-on severity', async () => {
    getInputMock.mockImplementation((name: string): string => {
      switch (name) {
        case 'fail-on':
          return 'banana';
        default:
          return '0';
      }
    });
    await run();

    expect(setOutputMock).toBeCalledTimes(0);
    expect(setFailedMock).toHaveBeenCalledWith(`Invalid fail-on: BANANA`);
    expect(getImageScanFindingsMock).toBeCalledTimes(0);
  });

  it('fail early on invalid timeout', async () => {
    getInputMock.mockImplementation((name: string): string => {
      switch (name) {
        case 'fail-on':
          return 'critical';
        case 'timeout':
          return '-1';
        default:
          return '0';
      }
    });
    await run();

    expect(setOutputMock).toBeCalledTimes(0);
    expect(setFailedMock).toHaveBeenCalledWith(
      `Invalid timeout: -1. Must be a positive integer`,
    );
    expect(getImageScanFindingsMock).toBeCalledTimes(0);
  });

  it('fail early on invalid consistency-delay', async () => {
    getInputMock.mockImplementation((name: string): string => {
      switch (name) {
        case 'fail-on':
          return 'critical';
        case 'timeout':
          return '60';
        case 'consistency-delay':
          return '-1';
        default:
          return '0';
      }
    });
    await run();

    expect(setOutputMock).toBeCalledTimes(0);
    expect(setFailedMock).toHaveBeenCalledWith(
      `Invalid consistency-delay: -1. Must be a positive integer`,
    );
    expect(getImageScanFindingsMock).toBeCalledTimes(0);
  });
});

describe('execution handling', () => {
  beforeAll(() => {
    getInputMock.mockImplementation((name: string): string => {
      switch (name) {
        case 'fail-on':
          return 'critical';
        case 'timeout':
          return '60';
        case 'consistency-delay':
          return '15';
        default:
          return '0';
      }
    });
  });

  it('SetFailed when unexpected error during execution', async () => {
    getImageScanFindingsMock.mockImplementation(
      (
        repository: string,
        tag: string,
        ignore: string[],
        timeout: number,
        pollRate: number,
        consistencyDelay: number,
        failOn?: string,
      ): Promise<ScanFindings> => {
        throw new Error('Something went wrong');
      },
    );
    await run();

    expect(getImageScanFindingsMock).toBeCalledTimes(1);
    expect(setOutputMock).toBeCalledTimes(0);
    expect(setFailedMock).toHaveBeenCalledWith(`Something went wrong`);
  });

  it('SetFailed when ScanFindings returned with error message', async () => {
    getImageScanFindingsMock.mockImplementation(
      (
        repository: string,
        tag: string,
        ignore: string[],
        timeout: number,
        pollRate: number,
        consistencyDelay: number,
        failOn?: string,
      ): Promise<ScanFindings> => {
        return new Promise((resolve, _) =>
          resolve({
            findingSeverityCounts: { CRITICAL: 1 },
            errorMessage:
              'Found vulnerabilty with severity of CRITICAL or greater.',
          }),
        );
      },
    );
    await run();

    expect(getImageScanFindingsMock).toBeCalledTimes(1);
    expect(setOutputMock).toHaveBeenCalledWith('findingSeverityCounts', {
      CRITICAL: 1,
    });
    expect(setFailedMock).toHaveBeenCalledWith(
      `Found vulnerabilty with severity of CRITICAL or greater.`,
    );
  });
});

describe('splitIgnoreList', () => {
  it('Spaces', () => {
    const ignoreList = splitIgnoreList(`CRIT1 CRIT2`);
    expect(ignoreList).toEqual(['CRIT1', 'CRIT2']);
  });

  it('Commas', () => {
    const ignoreList = splitIgnoreList(`CRIT1, CRIT2`);
    expect(ignoreList).toEqual(['CRIT1', 'CRIT2']);
  });

  it('New Lines and Spaces', () => {
    const ignoreList = splitIgnoreList(`
			CRIT1, 
			CRIT2`);
    expect(ignoreList).toEqual(['CRIT1', 'CRIT2']);
  });
});
